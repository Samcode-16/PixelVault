#!/bin/bash
# PixelVault v4 upgrade: metadata moves from SQLite to DynamoDB; optional CloudFront delivery.
# Prerequisites: infra/SETUP.md Phase 2 steps 1-2 (table created, IAM policy attached).
# Usage:  bash upgrade.sh                      (DynamoDB only)
#         CDN_DOMAIN=dxxx.cloudfront.net CDN_KEY_PAIR_ID=KXXX bash upgrade.sh   (also switch the CDN on)
set -euo pipefail
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-south-2}"
TABLE="${DDB_TABLE:-PixelVault}"
[ -x /opt/gallery/venv/bin/flask ] || { echo "Expected the v3 install in /opt/gallery."; exit 1; }
echo "Checking DynamoDB table $TABLE ..."
aws dynamodb describe-table --table-name "$TABLE" --query Table.TableStatus --output text \
  || { echo "Cannot read table $TABLE. Create it (SETUP.md Phase 2 step 1) and attach the IAM policy (step 2), then re-run."; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
sudo cp /opt/gallery/app.py "/opt/gallery/app.py.v3.$STAMP.bak" 2>/dev/null || true
[ -f /var/lib/gallery/gallery.db ] && cp /var/lib/gallery/gallery.db "/var/lib/gallery/gallery.db.$STAMP.bak"
sudo mkdir -p /opt/gallery/templates /opt/gallery/static
sudo chown -R ec2-user:ec2-user /opt/gallery

cat > /opt/gallery/app.py <<'GALLERY_EOF'
"""
PixelVault v4 - private photo library (Flask + DynamoDB + S3 + CloudFront)
-------------------------------------------------------------------------
* Users register and sign in with their own account; passwords are stored only as salted hashes.
* Every image lives under  images/<user-id>/  in the private bucket, and every request is checked
  against the signed-in user's own rows, so one user can never list, share or delete another's images.
* AWS credentials still come from the EC2 instance role (no access keys anywhere).
"""
import hashlib
import hmac
import io
import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import boto3
import click
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from flask import (Flask, Response, g, jsonify, redirect, render_template,
                   request, session, url_for)
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import cdn
import store

# ---------------------------------------------------------------- config ----
BUCKET = os.environ["S3_BUCKET"]
REGION = os.environ.get("AWS_REGION", "ap-south-2")
PREFIX = "images/"                       # keeps the existing GalleryEC2S3Access policy valid
DDB_TABLE = os.environ.get("DDB_TABLE", "PixelVault")
SQLITE_PATH = os.environ.get("DB_PATH", "/var/lib/gallery/gallery.db")   # only used by `migrate-sqlite`
CDN_DOMAIN = os.environ.get("CDN_DOMAIN", "").strip()                 # e.g. d1234abcd.cloudfront.net
CDN_KEY_PAIR_ID = os.environ.get("CDN_KEY_PAIR_ID", "").strip()       # CloudFront public key ID (K...)
CDN_KEY_PARAM = os.environ.get("CDN_KEY_PARAM", "/pixelvault/cloudfront-private-key")   # SSM SecureString holding the PEM
CDN_KEY_FILE = os.environ.get("CDN_KEY_FILE", "")                      # alternative: a local PEM file
VIEW_URL_TTL = int(os.environ.get("VIEW_URL_TTL", 900))
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 5))
MAX_IMAGES = int(os.environ.get("MAX_IMAGES_PER_USER", 50))
MAX_STORAGE_MB = int(os.environ.get("MAX_STORAGE_MB_PER_USER", 100))
REGISTRATION_OPEN = os.environ.get("REGISTRATION_OPEN", "true").lower() == "true"
INVITE_CODE = os.environ.get("INVITE_CODE", "")
ADMIN_USER = os.environ.get("APP_USERNAME", "admin")
ADMIN_PASS = os.environ.get("APP_PASSWORD", "")          # optional: seeds the first account
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
TRASH_DAYS = int(os.environ.get("TRASH_DAYS", 30))
THUMB_PX = 480
MAX_SHARE_MIN = 7 * 24 * 60
MAX_FAILS, LOCKOUT_SECONDS = 5, 300
Image.MAX_IMAGE_PIXELS = 50_000_000      # refuse decompression bombs

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
FORMAT_MIME = {"PNG": "image/png", "JPEG": "image/jpeg", "GIF": "image/gif", "WEBP": "image/webp"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    MAX_CONTENT_LENGTH=(MAX_UPLOAD_MB + 1) * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gallery")

# Regional endpoint: pre-signed URLs must be signed for, and sent to, ap-south-2.
s3 = boto3.client(
    "s3",
    region_name=REGION,
    endpoint_url=f"https://s3.{REGION}.amazonaws.com",
    config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"},
                  retries={"max_attempts": 3, "mode": "standard"}),
)


store.init(DDB_TABLE, REGION)


def _load_pem():
    if CDN_KEY_FILE:
        return open(CDN_KEY_FILE, "rb").read()
    ssm = boto3.client("ssm", region_name=REGION)
    return ssm.get_parameter(Name=CDN_KEY_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()


signer = cdn.Signer(CDN_DOMAIN, CDN_KEY_PAIR_ID, _load_pem) if CDN_DOMAIN and CDN_KEY_PAIR_ID else None
log.info("Database: DynamoDB table %s | CDN: %s", DDB_TABLE, CDN_DOMAIN or "off (S3 pre-signed URLs)")


def ensure_admin():
    if ADMIN_PASS and store.get_user_by_name(ADMIN_USER) is None:
        store.create_user(uuid.uuid4().hex, ADMIN_USER, generate_password_hash(ADMIN_PASS))


try:
    ensure_admin()
except Exception:                                                     # noqa: BLE001 - table may not exist yet
    log.exception("Could not reach DynamoDB table %s at start-up", DDB_TABLE)

# -------------------------------------------------------------- security ----
CDN_ORIGIN = f"https://{CDN_DOMAIN}" if CDN_DOMAIN else ""


def _eq(a, b):
    return hmac.compare_digest(a.encode(), b.encode())


DUMMY_HASH = generate_password_hash(secrets.token_hex(16))   # equalises timing for unknown usernames


def require_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = store.get_user(session.get("uid"))
        if user is None:
            session.pop("uid", None)
            if request.method == "POST" or request.path.startswith("/api/"):
                return jsonify(ok=False, error="Session expired. Please sign in again."), 401
            return redirect(url_for("login"))
        g.user = user
        return view(*args, **kwargs)
    return wrapper


@app.before_request
def csrf_protect():
    if request.endpoint == "static":
        return None
    session.setdefault("csrf", secrets.token_hex(16))
    if request.method == "POST":
        sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token", "")
        if not _eq(sent, session["csrf"]):
            return jsonify(ok=False, error="Invalid or missing CSRF token."), 400
    return None


@app.context_processor
def inject_globals():
    return {"csrf_token": session.get("csrf", "")}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob: https://*.amazonaws.com " + CDN_ORIGIN + "; "
        "style-src 'self'; script-src 'self'; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------- helpers ----
def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def presign(key, ttl, **extra):
    return s3.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": key, **extra}, ExpiresIn=ttl)


def parse_exif(exif):
    """Return (taken_at epoch or None, camera label or None) from an EXIF block."""
    raw = None
    try:
        raw = exif.get_ifd(0x8769).get(36867)          # DateTimeOriginal lives in the Exif sub-IFD
    except Exception:                                  # noqa: BLE001 - malformed EXIF must never break uploads
        pass
    raw = raw or exif.get(306)                         # DateTime fallback
    taken = None
    if isinstance(raw, str):
        try:
            ts = int(datetime.strptime(raw.strip("\x00 ")[:19], "%Y:%m:%d %H:%M:%S")
                     .replace(tzinfo=timezone.utc).timestamp())
            if 631152000 < ts < time.time() + 86400:   # ignore dates before 1990 or in the future
                taken = ts
        except ValueError:
            pass
    make, model = str(exif.get(271) or "").strip("\x00 "), str(exif.get(272) or "").strip("\x00 ")
    camera = (model if model.startswith(make) else f"{make} {model}").strip()[:60] or None
    return taken, camera


def analyse(raw):
    """Validate an image and derive everything the library needs. Returns None if it is not a real image."""
    try:
        with Image.open(io.BytesIO(raw)) as probe:
            probe.verify()                              # structural integrity check
        with Image.open(io.BytesIO(raw)) as img:
            fmt = img.format
            if fmt not in FORMAT_MIME:
                return None
            taken, camera = parse_exif(img.getexif())
            upright = ImageOps.exif_transpose(img)      # honour the camera's rotation flag
            width, height = upright.size
            upright = upright.convert("RGBA")
            upright.thumbnail((THUMB_PX, THUMB_PX))
            flat = Image.new("RGB", upright.size, (255, 255, 255))
            flat.paste(upright, mask=upright.split()[3])
            buf = io.BytesIO()
            flat.save(buf, "JPEG", quality=80, optimize=True)
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError, Image.DecompressionBombError):
        return None
    return {"fmt": fmt, "width": width, "height": height, "taken": taken, "camera": camera, "thumb": buf.getvalue()}


def put_s3(key, body, content_type):
    s3.put_object(Bucket=BUCKET, Key=key, Body=body, ContentType=content_type, ServerSideEncryption="AES256",
                  CacheControl="max-age=31536000, immutable")   # keys are unique per upload, so edges/browsers may cache for a year


def start_session(user_id):
    session.clear()                                    # new session on every login/registration
    session["csrf"] = secrets.token_hex(16)
    session["uid"] = user_id
    session.permanent = True


def ok(**kw):
    return jsonify(ok=True, **kw)


def fail(msg, code=400):
    return jsonify(ok=False, error=msg), code


# ---------------------------------------------------------- CloudFront / URLs ----
_warned = set()


def view_url(key, ttl, exact=False):
    """URL for showing an object: a signed CloudFront link when the CDN is configured, otherwise straight S3."""
    if signer:
        try:
            return signer.url(key, ttl, exact=exact)
        except Exception:                                  # noqa: BLE001 - never let a CDN problem take the gallery down
            if "cdn" not in _warned:
                _warned.add("cdn")
                log.exception("CloudFront signing failed - falling back to S3 pre-signed URLs")
    return presign(key, ttl)


def imgs():
    """The signed-in user's images (cached per request). A user owns at most MAX_IMAGES, so one Query returns them all."""
    if "imgs" not in g:
        g.imgs = store.list_images(g.user["id"])
    return g.imgs


def owned(ids, trashed=None):
    """Images among IDS that belong to the signed-in user (never trusts the client for ownership)."""
    if not isinstance(ids, list) or not ids or len(ids) > 200 or not all(isinstance(i, str) for i in ids):
        return []
    wanted = set(ids)
    return [r for r in imgs() if r["id"] in wanted and (trashed is None or bool(r.get("deleted_at")) == trashed)]


def own_album(album_id):
    return store.get_album(g.user["id"], album_id)


def purge_rows(rows):
    """Permanently remove images: S3 originals + thumbnails first, then the metadata."""
    keys = []
    for r in rows:
        keys.append({"Key": r["s3_key"]})
        if r.get("thumb_key"):
            keys.append({"Key": r["thumb_key"]})
    for i in range(0, len(keys), 500):
        s3.delete_objects(Bucket=BUCKET, Delete={"Objects": keys[i:i + 500], "Quiet": True})
    ids = [r["id"] for r in rows]
    store.delete_images(g.user["id"], ids)
    store.strip_from_albums(g.user["id"], ids)
    g.pop("imgs", None)


def purge_expired_trash():
    cutoff = int(time.time()) - TRASH_DAYS * 86400
    rows = [r for r in imgs() if r.get("deleted_at") and r["deleted_at"] < cutoff]
    if rows:
        try:
            purge_rows(rows)
            log.info("Auto-purged %d expired trash item(s)", len(rows))
        except (ClientError, BotoCoreError):
            log.exception("Auto-purge failed")


def taken(r):
    return r.get("taken_at") or r["created_at"]


def serialize(r):
    return {
        "id": r["id"], "name": r["name"], "size": r["size"], "size_label": human_size(r["size"]),
        "created": r["created_at"], "taken": taken(r), "has_exif_date": bool(r.get("taken_at")),
        "width": r.get("width"), "height": r.get("height"), "camera": r.get("camera"),
        "favorite": bool(r.get("favorite")), "deleted_at": r.get("deleted_at"),
        "thumb": view_url(r.get("thumb_key") or r["s3_key"], VIEW_URL_TTL), "url": view_url(r["s3_key"], VIEW_URL_TTL),
    }


@app.errorhandler(ClientError)
@app.errorhandler(BotoCoreError)
def aws_error(exc):
    log.exception("AWS call failed")
    return jsonify(ok=False, error="A cloud service error occurred. Please try again."), 502


# ----------------------------------------------------------- auth routes ----
@app.route("/health")
def health():
    return jsonify(status="ok", database="dynamodb", cdn=bool(signer), time=datetime.now(timezone.utc).isoformat())


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("uid"):
        return redirect(url_for("index"))
    if not REGISTRATION_OPEN:
        return render_template("register.html", closed=True, error=None, username="", needs_invite=False), 403
    error, username = None, ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pwd, confirm = request.form.get("password", ""), request.form.get("confirm", "")
        if INVITE_CODE and not _eq(request.form.get("invite", "").strip(), INVITE_CODE):
            error = "That invite code is not valid."
        elif not USERNAME_RE.match(username):
            error = "Username must be 3 to 30 characters: letters, numbers or underscore."
        elif not 10 <= len(pwd) <= 128:
            error = "Password must be between 10 and 128 characters."
        elif pwd.lower() == username.lower() or pwd.isdigit():
            error = "Choose a stronger password (not your username, not only digits)."
        elif pwd != confirm:
            error = "The two passwords do not match."
        else:
            uid = uuid.uuid4().hex
            if store.create_user(uid, username, generate_password_hash(pwd)):
                log.info("Registered user %s", username)
                start_session(uid)
                return redirect(url_for("index"))
            error = "That username is already taken."
    return render_template("register.html", closed=False, error=error, username=username,
                           needs_invite=bool(INVITE_CODE)), (400 if error else 200)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("uid"):
        return redirect(url_for("index"))
    error, status = None, 200
    if request.method == "POST":
        username, pwd = request.form.get("username", "").strip(), request.form.get("password", "")
        user = store.get_user_by_name(username) if USERNAME_RE.match(username) else None
        now = int(time.time())
        if user and user["locked_until"] > now:
            error, status = f"Too many failed attempts. Try again in {user['locked_until'] - now} seconds.", 429
        else:
            good = check_password_hash(user["pw_hash"] if user else DUMMY_HASH, pwd) and user is not None
            if good:
                store.set_login_state(user["id"], 0, 0)
                log.info("Login success for %s", username)
                start_session(user["id"])
                return redirect(url_for("index"))
            if user:
                fails = user["failed_count"] + 1
                locked = now + LOCKOUT_SECONDS if fails >= MAX_FAILS else 0
                store.set_login_state(user["id"], 0 if locked else fails, locked)
            log.warning("Failed login for %s", username)
            error, status = "Incorrect username or password.", 401
    return render_template("login.html", error=error), status


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@require_auth
def index():
    return render_template("index.html", user=g.user["username"], bucket=BUCKET, region=REGION,
                           max_mb=MAX_UPLOAD_MB, trash_days=TRASH_DAYS)


# ------------------------------------------------------------------- API ----
@app.get("/api/summary")
@require_auth
def api_summary():
    rows = imgs()
    live = [r for r in rows if not r.get("deleted_at")]
    live_ids = {r["id"] for r in live}
    albums = sorted(store.list_albums(g.user["id"]), key=lambda a: a["name"].lower())
    used = sum(r["size"] for r in rows)
    return ok(photos=len(live), favorites=sum(1 for r in live if r.get("favorite")), trash=len(rows) - len(live),
              used_bytes=used, used_label=human_size(used), total=len(rows), max_images=MAX_IMAGES,
              quota_mb=MAX_STORAGE_MB, trash_days=TRASH_DAYS,
              albums=[dict(id=a["id"], name=a["name"], count=len(live_ids & set(a.get("image_ids", [])))) for a in albums])


@app.get("/api/photos")
@require_auth
def api_photos():
    purge_expired_trash()
    view = request.args.get("view", "photos")
    rows = imgs()
    if view == "trash":
        rows = [r for r in rows if r.get("deleted_at")]
    else:
        rows = [r for r in rows if not r.get("deleted_at")]
        if view == "favorites":
            rows = [r for r in rows if r.get("favorite")]
        elif view == "album":
            album = own_album(request.args.get("album"))
            if album is None:
                return fail("Album not found.", 404)
            members = set(album.get("image_ids", []))
            rows = [r for r in rows if r["id"] in members]
    rows = sorted(rows, key=lambda r: (taken(r), r["created_at"]), reverse=True)
    return ok(items=[serialize(r) for r in rows])


@app.route("/upload", methods=["POST"])
@require_auth
def upload():
    f = request.files.get("image")
    if not f or not f.filename:
        return fail("No file received.")
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    raw = f.stream.read(MAX_UPLOAD_MB * 1024 * 1024 + 1)
    if ext not in ALLOWED_EXT or len(raw) > MAX_UPLOAD_MB * 1024 * 1024:
        return fail("Not a valid PNG, JPG, GIF or WEBP image under the size limit.")
    info = analyse(raw)
    if not info:
        return fail("Not a valid PNG, JPG, GIF or WEBP image.")

    uid, size = g.user["id"], len(raw)
    digest = hashlib.sha256(raw).hexdigest()
    dup = next((r for r in imgs() if r.get("sha256") == digest), None)
    if dup:
        return fail("Already in your Trash - restore it from there." if dup.get("deleted_at")
                    else "Already in your library (duplicate).", 409)
    if len(imgs()) >= MAX_IMAGES:
        return fail(f"Image limit reached ({MAX_IMAGES}). Delete some images first.", 403)
    if sum(r["size"] for r in imgs()) + size > MAX_STORAGE_MB * 1024 * 1024:
        return fail(f"Storage limit reached ({MAX_STORAGE_MB} MB).", 403)

    name = secure_filename(f.filename)
    if not name.lower().endswith("." + ext):
        name = f"image.{ext}"
    image_id = uuid.uuid4().hex
    key = f"{PREFIX}{uid}/{image_id}-{name}"             # the user id comes from the session, never the client
    thumb_key = f"{PREFIX}{uid}/thumbs/{image_id}.jpg"
    try:
        put_s3(key, raw, FORMAT_MIME[info["fmt"]])
        put_s3(thumb_key, info["thumb"], "image/jpeg")
    except (ClientError, BotoCoreError):
        log.exception("Upload failed for %s", key)
        return fail("Storage error. Please try again.", 502)
    try:
        store.put_image(uid, dict(id=image_id, name=name, size=size, created_at=int(time.time()), taken_at=info["taken"],
                                  width=info["width"], height=info["height"], camera=info["camera"], sha256=digest,
                                  s3_key=key, thumb_key=thumb_key, favorite=False))
    except (ClientError, BotoCoreError):
        log.exception("Metadata write failed; removing %s", key)
        try:
            s3.delete_objects(Bucket=BUCKET, Delete={"Objects": [{"Key": key}, {"Key": thumb_key}], "Quiet": True})
        except (ClientError, BotoCoreError):
            pass
        return fail("Could not save the image record.", 500)
    log.info("Uploaded %s", key)
    return ok(name=name, id=image_id)


@app.post("/api/favorite")
@require_auth
def api_favorite():
    data = request.get_json(silent=True) or {}
    rows = owned(data.get("ids"), trashed=False)
    for r in rows:
        store.update_image(g.user["id"], r["id"], {"favorite": bool(data.get("value"))})
    return ok(changed=len(rows))


@app.post("/api/trash")
@require_auth
def api_trash():
    rows = owned((request.get_json(silent=True) or {}).get("ids"), trashed=False)
    now = int(time.time())
    for r in rows:
        store.update_image(g.user["id"], r["id"], {"deleted_at": now})
        store.revoke_image_shares(g.user["id"], r["id"])         # links die with the photo
    return ok(changed=len(rows))


@app.post("/api/restore")
@require_auth
def api_restore():
    rows = owned((request.get_json(silent=True) or {}).get("ids"), trashed=True)
    for r in rows:
        store.update_image(g.user["id"], r["id"], remove=["deleted_at"])
    return ok(changed=len(rows))


@app.post("/api/purge")
@require_auth
def api_purge():
    data = request.get_json(silent=True) or {}
    rows = [r for r in imgs() if r.get("deleted_at")] if data.get("all") else owned(data.get("ids"), trashed=True)
    if rows:
        try:
            purge_rows(rows)
        except (ClientError, BotoCoreError):
            log.exception("Purge failed")
            return fail("Could not delete from storage. Nothing was removed.", 502)
    return ok(changed=len(rows))


@app.post("/api/albums/create")
@require_auth
def album_create():
    name = str((request.get_json(silent=True) or {}).get("name", "")).strip()[:60]
    if not name:
        return fail("Give the album a name.")
    if len(store.list_albums(g.user["id"])) >= 50:
        return fail("Album limit reached (50).", 403)
    aid = uuid.uuid4().hex
    store.create_album(g.user["id"], aid, name)
    return ok(id=aid, name=name)


@app.post("/api/albums/rename")
@require_auth
def album_rename():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()[:60]
    if own_album(data.get("id")) is None or not name:
        return fail("Album not found.", 404)
    store.rename_album(g.user["id"], data["id"], name)
    return ok()


@app.post("/api/albums/delete")
@require_auth
def album_delete():
    data = request.get_json(silent=True) or {}
    if own_album(data.get("id")) is None:
        return fail("Album not found.", 404)
    store.delete_album(g.user["id"], data["id"])                  # photos themselves are untouched
    return ok()


@app.post("/api/albums/add")
@require_auth
def album_add():
    data = request.get_json(silent=True) or {}
    if own_album(data.get("id")) is None:
        return fail("Album not found.", 404)
    rows = owned(data.get("ids"), trashed=False)
    store.album_add(g.user["id"], data["id"], [r["id"] for r in rows])
    return ok(changed=len(rows))


@app.post("/api/albums/remove")
@require_auth
def album_remove():
    data = request.get_json(silent=True) or {}
    if own_album(data.get("id")) is None:
        return fail("Album not found.", 404)
    rows = owned(data.get("ids"))
    store.album_remove(g.user["id"], data["id"], [r["id"] for r in rows])
    return ok(changed=len(rows))


# -------------------------------------------------------- sharing / download ----
@app.post("/api/share/create")
@require_auth
def share_create():
    data = request.get_json(silent=True) or {}
    rows = owned([data.get("id")], trashed=False)
    if not rows:
        return fail("Image not found.", 404)
    try:
        minutes = max(1, min(int(data.get("minutes", 60)), MAX_SHARE_MIN))
    except (TypeError, ValueError):
        minutes = 60
    token, expires = secrets.token_urlsafe(16), int(time.time()) + minutes * 60
    store.create_share(token, g.user["id"], rows[0]["id"], expires)
    return ok(token=token, url=url_for("shared", token=token, _external=True), expires_at=expires)


@app.get("/api/shares")
@require_auth
def share_list():
    rows = owned([request.args.get("id")])
    if not rows:
        return fail("Image not found.", 404)
    now = time.time()
    links = [s for s in store.list_shares(g.user["id"], rows[0]["id"]) if not s["revoked"] and s["expires_at"] > now]
    links.sort(key=lambda s: s["created_at"], reverse=True)
    return ok(links=[dict(token=s["token"], url=url_for("shared", token=s["token"], _external=True),
                          expires_at=s["expires_at"], views=s["views"]) for s in links])


@app.post("/api/share/revoke")
@require_auth
def share_revoke():
    token = (request.get_json(silent=True) or {}).get("token")
    return ok() if isinstance(token, str) and store.revoke_share(g.user["id"], token) else fail("Link not found.", 404)


@app.route("/s/<token>")
def shared(token):
    """Public, revocable link. Checked against the database on every hit, then redirected to a 60-second signed URL."""
    gone = Response("This link has expired or was revoked.", status=404, mimetype="text/plain")
    share = store.get_share(token)
    if share is None or share["revoked"] or share["expires_at"] < time.time():
        return gone
    image = store.get_image(share["user_id"], share["image_id"])
    if image is None or image.get("deleted_at"):
        return gone
    store.bump_views(share)
    return redirect(view_url(image["s3_key"], 60, exact=True), 302)


@app.route("/download/<image_id>")
@require_auth
def download(image_id):
    rows = owned([image_id])
    if not rows:
        return fail("Image not found.", 404)
    disp = f'attachment; filename="{rows[0]["name"]}"'
    return redirect(presign(rows[0]["s3_key"], 60, ResponseContentDisposition=disp), 302)    # downloads go straight to S3


@app.errorhandler(413)
def too_large(_):
    return jsonify(ok=False, error=f"File too large (max {MAX_UPLOAD_MB} MB)."), 413


# --------------------------------------------------------------- CLI tools ----
@app.cli.command("adopt-legacy")
@click.argument("username")
def adopt_legacy(username):
    """Move images uploaded by the old single-user version (images/<name>) into USERNAME's folder."""
    user = store.get_user_by_name(username)
    if user is None:
        raise click.ClickException(f"No such user: {username}")
    moved = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix=PREFIX):
        for obj in page.get("Contents", []):
            rest = obj["Key"][len(PREFIX):]
            if not rest or "/" in rest or rest.rsplit(".", 1)[-1].lower() not in ALLOWED_EXT:
                continue
            new_key = f"{PREFIX}{user['id']}/{rest}"
            s3.copy_object(Bucket=BUCKET, Key=new_key, CopySource={"Bucket": BUCKET, "Key": obj["Key"]}, ServerSideEncryption="AES256")
            s3.delete_object(Bucket=BUCKET, Key=obj["Key"])
            store.put_image(user["id"], dict(id=uuid.uuid4().hex, name=rest.split("-", 1)[-1], size=obj["Size"],
                                             created_at=int(obj["LastModified"].timestamp()), s3_key=new_key, favorite=False))
            moved += 1
    click.echo(f"Moved {moved} image(s) to {username}.")


@app.cli.command("backfill")
def backfill():
    """Give photos that lack a thumbnail, EXIF data or content hash (all users) what they need."""
    rows = [r for r in store.scan_images() if not r.get("thumb_key") or not r.get("sha256")]
    done = 0
    for r in rows:
        try:
            raw = s3.get_object(Bucket=BUCKET, Key=r["s3_key"])["Body"].read()
        except (ClientError, BotoCoreError):
            click.echo(f"skip (unreadable): {r['s3_key']}")
            continue
        info = analyse(raw)
        if not info:
            click.echo(f"skip (not an image): {r['s3_key']}")
            continue
        thumb_key = f"{r['s3_key'].rsplit('/', 1)[0]}/thumbs/{r['id']}.jpg"
        put_s3(thumb_key, info["thumb"], "image/jpeg")
        fields = dict(thumb_key=thumb_key, sha256=hashlib.sha256(raw).hexdigest(), width=info["width"], height=info["height"])
        for k, v in (("taken_at", info["taken"]), ("camera", info["camera"])):
            if v is not None:
                fields[k] = v
        store.update_image(r["user_id"], r["id"], fields)
        done += 1
    click.echo(f"Backfilled {done} of {len(rows)} image(s).")


@app.cli.command("migrate-sqlite")
@click.option("--sqlite", "path", default=SQLITE_PATH, show_default=True, help="Old SQLite database file")
def migrate_sqlite(path):
    """One-time copy of users, photos, albums and live share links from the old SQLite file into DynamoDB. Safe to re-run."""
    import sqlite3
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    cols = lambda t: {c["name"] for c in con.execute(f"PRAGMA table_info({t})")}
    n = dict(users=0, images=0, albums=0, links=0)
    for u in con.execute("SELECT * FROM users"):
        if store.get_user(u["id"]) is None:
            n["users"] += store.create_user(u["id"], u["username"], u["pw_hash"], u["created_at"])
    for r in con.execute("SELECT * FROM images"):
        d = dict(r)
        item = {k: d[k] for k in ("id", "name", "size", "created_at", "taken_at", "width", "height", "camera", "sha256", "s3_key", "thumb_key")
                if k in d and d[k] is not None}
        item["favorite"] = bool(d.get("favorite"))
        if d.get("deleted_at"):
            item["deleted_at"] = d["deleted_at"]
        store.put_image(d["user_id"], item)
        n["images"] += 1
    if "albums" in {t[0] for t in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}:
        for a in con.execute("SELECT * FROM albums"):
            store.create_album(a["user_id"], a["id"], a["name"], a["created_at"])
            members = [m["image_id"] for m in con.execute("SELECT image_id FROM album_images WHERE album_id = ?", (a["id"],))]
            store.album_add(a["user_id"], a["id"], members)
            n["albums"] += 1
        for s in con.execute("SELECT * FROM shares WHERE revoked = 0 AND expires_at > ?", (int(time.time()),)):
            store.create_share(s["token"], s["user_id"], s["image_id"], s["expires_at"], s["created_at"], s["views"])
            n["links"] += 1
    click.echo(f"Migrated: {n['users']} user(s), {n['images']} image(s), {n['albums']} album(s), {n['links']} live share link(s).")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
GALLERY_EOF

cat > /opt/gallery/store.py <<'GALLERY_EOF'
"""DynamoDB data layer for PixelVault (single-table design).

One table, keys PK + SK. Everything a user owns shares the partition  USER#<id>:
  USER#<id>  | PROFILE                 account (username, password hash, lockout state)
  USER#<id>  | IMG#<image-id>           one photo's metadata
  USER#<id>  | ALB#<album-id>           an album; its photos are a string-set attribute `image_ids`
  USER#<id>  | SHR#<image-id>#<token>   a share link (views, expiry, revoked)
Lookup items:
  USERNAME#<lowercase name> | CLAIM     guarantees unique usernames (conditional write)
  SHARE#<token>             | POINTER   token -> (user, image) so /s/<token> needs no login
Share items carry a `ttl` attribute so DynamoDB deletes them itself after they expire.
"""
import time
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

_table = None


def init(table_name, region):
    global _table
    _table = boto3.resource("dynamodb", region_name=region).Table(table_name)


def _py(v):
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    if isinstance(v, dict):
        return {k: _py(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_py(x) for x in v]
    if isinstance(v, set):
        return sorted(_py(x) for x in v)
    return v


def _query(pk, prefix):
    kw = {"KeyConditionExpression": Key("PK").eq(pk) & Key("SK").begins_with(prefix)}
    out = []
    while True:
        r = _table.query(**kw)
        out += r["Items"]
        if "LastEvaluatedKey" not in r:
            return [_py(i) for i in out]
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def _failed_condition(err):
    return err.response["Error"]["Code"] == "ConditionalCheckFailedException"


def _update(key, set_=None, remove=(), add=None, delete=None, must_exist=True):
    names, values, sets, rem = {}, {}, [], []
    for n, (k, v) in enumerate((set_ or {}).items()):
        names[f"#s{n}"], values[f":s{n}"] = k, v
        sets.append(f"#s{n} = :s{n}")
    for n, k in enumerate(remove):
        names[f"#r{n}"] = k
        rem.append(f"#r{n}")
    parts = []
    if sets: parts.append("SET " + ", ".join(sets))
    if rem: parts.append("REMOVE " + ", ".join(rem))
    for word, spec in (("ADD", add), ("DELETE", delete)):
        if spec:
            (k, v), = spec.items()
            names["#a"], values[":a"] = k, v
            parts.append(f"{word} #a :a")
    kw = {"Key": key, "UpdateExpression": " ".join(parts), "ExpressionAttributeNames": names}
    if values: kw["ExpressionAttributeValues"] = values
    if must_exist: kw["ConditionExpression"] = "attribute_exists(PK)"
    try:
        _table.update_item(**kw)
        return True
    except ClientError as e:
        if _failed_condition(e):
            return False
        raise


# ------------------------------------------------------------------ users ----
def create_user(uid, username, pw_hash, created_at=None):
    """Returns False if the username is taken (conditional write = atomic uniqueness check)."""
    try:
        _table.put_item(Item={"PK": f"USERNAME#{username.lower()}", "SK": "CLAIM", "user_id": uid},
                        ConditionExpression="attribute_not_exists(PK)")
    except ClientError as e:
        if _failed_condition(e):
            return False
        raise
    _table.put_item(Item={"PK": f"USER#{uid}", "SK": "PROFILE", "id": uid, "username": username, "pw_hash": pw_hash,
                          "created_at": created_at or int(time.time()), "failed_count": 0, "locked_until": 0})
    return True


def get_user(uid):
    if not isinstance(uid, str):
        return None
    item = _table.get_item(Key={"PK": f"USER#{uid}", "SK": "PROFILE"}).get("Item")
    return _py(item) if item else None


def get_user_by_name(username):
    claim = _table.get_item(Key={"PK": f"USERNAME#{username.lower()}", "SK": "CLAIM"}).get("Item")
    return get_user(claim["user_id"]) if claim else None


def set_login_state(uid, failed, locked_until):
    _update({"PK": f"USER#{uid}", "SK": "PROFILE"}, {"failed_count": failed, "locked_until": locked_until})


# ----------------------------------------------------------------- images ----
def list_images(uid):
    return _query(f"USER#{uid}", "IMG#")


def get_image(uid, image_id):
    item = _table.get_item(Key={"PK": f"USER#{uid}", "SK": f"IMG#{image_id}"}).get("Item")
    return _py(item) if item else None


def put_image(uid, img):
    item = {k: v for k, v in img.items() if v is not None}
    item.update(PK=f"USER#{uid}", SK=f"IMG#{img['id']}", user_id=uid)
    _table.put_item(Item=item)


def update_image(uid, image_id, set_=None, remove=()):
    return _update({"PK": f"USER#{uid}", "SK": f"IMG#{image_id}"}, set_, remove)


def delete_images(uid, ids):
    with _table.batch_writer() as batch:
        for i in ids:
            batch.delete_item(Key={"PK": f"USER#{uid}", "SK": f"IMG#{i}"})


def scan_images():
    """Every image of every user (admin CLI only)."""
    kw, out = {"FilterExpression": Attr("SK").begins_with("IMG#")}, []
    while True:
        r = _table.scan(**kw)
        out += r["Items"]
        if "LastEvaluatedKey" not in r:
            return [_py(i) for i in out]
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


# ----------------------------------------------------------------- albums ----
def list_albums(uid):
    return _query(f"USER#{uid}", "ALB#")


def get_album(uid, album_id):
    if not isinstance(album_id, str):
        return None
    item = _table.get_item(Key={"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"}).get("Item")
    return _py(item) if item else None


def create_album(uid, album_id, name, created_at=None):
    _table.put_item(Item={"PK": f"USER#{uid}", "SK": f"ALB#{album_id}", "id": album_id, "name": name,
                          "created_at": created_at or int(time.time())})


def rename_album(uid, album_id, name):
    return _update({"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"}, {"name": name})


def delete_album(uid, album_id):
    _table.delete_item(Key={"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"})


def album_add(uid, album_id, ids):
    if ids:
        _update({"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"}, add={"image_ids": set(ids)})


def album_remove(uid, album_id, ids):
    if ids:                                       # DynamoDB drops the attribute itself when the set becomes empty
        _update({"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"}, delete={"image_ids": set(ids)})


def strip_from_albums(uid, ids):
    gone = set(ids)
    for a in list_albums(uid):
        hit = gone & set(a.get("image_ids", []))
        if hit:
            album_remove(uid, a["id"], hit)


# ----------------------------------------------------------------- shares ----
def create_share(token, uid, image_id, expires_at, created_at=None, views=0):
    ttl = expires_at + 86400
    _table.put_item(Item={"PK": f"USER#{uid}", "SK": f"SHR#{image_id}#{token}", "token": token, "image_id": image_id,
                          "user_id": uid, "created_at": created_at or int(time.time()), "expires_at": expires_at,
                          "revoked": False, "views": views, "ttl": ttl})
    _table.put_item(Item={"PK": f"SHARE#{token}", "SK": "POINTER", "user_id": uid, "image_id": image_id, "ttl": ttl})


def get_share(token):
    p = _table.get_item(Key={"PK": f"SHARE#{token}", "SK": "POINTER"}).get("Item")
    if not p:
        return None
    s = _table.get_item(Key={"PK": f"USER#{p['user_id']}", "SK": f"SHR#{p['image_id']}#{token}"}).get("Item")
    return _py(s) if s else None


def bump_views(share):
    _update({"PK": f"USER#{share['user_id']}", "SK": f"SHR#{share['image_id']}#{share['token']}"}, add={"views": 1})


def list_shares(uid, image_id):
    return _query(f"USER#{uid}", f"SHR#{image_id}#")


def revoke_share(uid, token):
    p = _table.get_item(Key={"PK": f"SHARE#{token}", "SK": "POINTER"}).get("Item")
    if not p or p["user_id"] != uid:
        return False
    return _update({"PK": f"USER#{uid}", "SK": f"SHR#{p['image_id']}#{token}"}, {"revoked": True})


def revoke_image_shares(uid, image_id):
    for s in list_shares(uid, image_id):
        if not s["revoked"]:
            _update({"PK": f"USER#{uid}", "SK": f"SHR#{image_id}#{s['token']}"}, {"revoked": True})
GALLERY_EOF

cat > /opt/gallery/cdn.py <<'GALLERY_EOF'
"""CloudFront signed URLs (canned policy). The bucket stays private; only a valid, unexpired signature gets an image."""
import base64
import json
import threading
import time
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

WINDOW = 900                                       # URLs are stable for 15 minutes so browsers/edges can reuse them


def _b64(raw):                                     # CloudFront's URL-safe base64 variant
    return base64.b64encode(raw).decode().replace("+", "-").replace("=", "_").replace("/", "~")


class Signer:
    def __init__(self, domain, key_pair_id, load_pem):
        self.domain, self.kid, self._load, self._key, self._lock = domain, key_pair_id, load_pem, None, threading.Lock()

    def _private_key(self):
        with self._lock:
            if self._key is None:
                self._key = serialization.load_pem_private_key(self._load(), password=None)
            return self._key

    def url(self, key, ttl, exact=False):
        now = int(time.time())
        expires = now + ttl if exact else (now + ttl) // WINDOW * WINDOW + WINDOW
        resource = f"https://{self.domain}/{quote(key)}"
        policy = json.dumps({"Statement": [{"Resource": resource, "Condition": {"DateLessThan": {"AWS:EpochTime": expires}}}]},
                            separators=(",", ":"))
        sig = self._private_key().sign(policy.encode(), padding.PKCS1v15(), hashes.SHA1())   # CloudFront requires RSA-SHA1
        return f"{resource}?Expires={expires}&Signature={_b64(sig)}&Key-Pair-Id={self.kid}"
GALLERY_EOF

cat > /opt/gallery/requirements.txt <<'GALLERY_EOF'
Flask==3.0.3
boto3==1.34.162
gunicorn==22.0.0
Pillow==10.4.0
cryptography>=42,<45
GALLERY_EOF

cat > /opt/gallery/templates/login.html <<'GALLERY_EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · PixelVault</title>
  <link rel="icon" type="image/svg+xml" href="{{ url_for('static', filename='logo.svg') }}">
  <script src="{{ url_for('static', filename='theme.js') }}"></script>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
{% include "_icons.html" %}
<main class="auth">
  <aside class="auth-aside">
    <div class="brand light">
      <span class="brand-mark"><img src="{{ url_for('static', filename='logo.svg') }}" alt="" width="36" height="36"></span>
      <span>PixelVault</span>
    </div>
    <div class="aside-copy">
      <h1>Your photos,<br>privately yours.</h1>
      <p>A secure gallery built on Amazon S3 with role-based access and time-limited sharing links.</p>
      <ul class="feature-list">
        <li><svg class="icon"><use href="#i-lock"/></svg><span><b>Private by default</b> &mdash; the bucket blocks all public access.</span></li>
        <li><svg class="icon"><use href="#i-shield"/></svg><span><b>Least-privilege IAM</b> &mdash; the server uses a scoped EC2 role, no stored keys.</span></li>
        <li><svg class="icon"><use href="#i-clock"/></svg><span><b>Expiring links</b> &mdash; share an image for minutes, not forever.</span></li>
      </ul>
    </div>
    <div class="aside-foot">Amazon S3 &middot; IAM &middot; EC2</div>
  </aside>

  <section class="auth-main">
    <form class="auth-card" method="post" action="{{ url_for('login') }}">
      <input type="hidden" name="csrf" value="{{ csrf_token }}">
      <h2>Welcome back</h2>
      <p class="muted">Sign in to manage your image library.</p>

      {% if error %}
      <div class="alert error" role="alert"><svg class="icon"><use href="#i-alert"/></svg><span>{{ error }}</span></div>
      {% endif %}

      <div class="field">
        <label for="username">Username</label>
        <div class="input-wrap">
          <svg class="icon lead"><use href="#i-user"/></svg>
          <input id="username" name="username" type="text" autocomplete="username" required autofocus>
        </div>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <div class="input-wrap">
          <svg class="icon lead"><use href="#i-lock"/></svg>
          <input id="password" name="password" type="password" autocomplete="current-password" required>
          <button class="reveal" type="button" id="reveal" aria-label="Show password">
            <svg class="icon eye"><use href="#i-eye"/></svg>
          </button>
        </div>
      </div>
      <button class="btn btn-primary btn-block" type="submit" id="loginBtn">Sign in</button>
      <p class="auth-switch">New to PixelVault? <a href="{{ url_for('register') }}">Create an account</a></p>
      <p class="auth-note"><svg class="icon"><use href="#i-shield"/></svg>Session expires automatically after 2 hours.</p>
    </form>
  </section>
</main>
<script src="{{ url_for('static', filename='login.js') }}"></script>
</body>
</html>
GALLERY_EOF

cat > /opt/gallery/templates/register.html <<'GALLERY_EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Create account · PixelVault</title>
  <link rel="icon" type="image/svg+xml" href="{{ url_for('static', filename='logo.svg') }}">
  <script src="{{ url_for('static', filename='theme.js') }}"></script>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
{% include "_icons.html" %}
<main class="auth">
  <aside class="auth-aside">
    <div class="brand light">
      <span class="brand-mark"><img src="{{ url_for('static', filename='logo.svg') }}" alt="" width="36" height="36"></span>
      <span>PixelVault</span>
    </div>
    <div class="aside-copy">
      <h1>Your photos,<br>privately yours.</h1>
      <p>A secure gallery built on Amazon S3 with role-based access and time-limited sharing links.</p>
      <ul class="feature-list">
        <li><svg class="icon"><use href="#i-lock"/></svg><span><b>Your own private space</b> &mdash; every account sees only its own images.</span></li>
        <li><svg class="icon"><use href="#i-shield"/></svg><span><b>Least-privilege IAM</b> &mdash; the server uses a scoped EC2 role, no stored keys.</span></li>
        <li><svg class="icon"><use href="#i-clock"/></svg><span><b>Expiring links</b> &mdash; share an image for minutes, not forever.</span></li>
      </ul>
    </div>
    <div class="aside-foot">Amazon S3 &middot; IAM &middot; EC2</div>
  </aside>

  <section class="auth-main">
    <form class="auth-card" method="post" action="{{ url_for('register') }}">
      <input type="hidden" name="csrf" value="{{ csrf_token }}">
      <h2>Create your account</h2>
      <p class="muted">Your images are private to you. No one else can see or manage them.</p>

      {% if closed %}
      <div class="alert error" role="alert"><svg class="icon"><use href="#i-alert"/></svg><span>Registration is currently closed.</span></div>
      <p class="auth-switch"><a href="{{ url_for('login') }}">Back to sign in</a></p>
      {% else %}
      {% if error %}
      <div class="alert error" role="alert"><svg class="icon"><use href="#i-alert"/></svg><span>{{ error }}</span></div>
      {% endif %}

      <div class="field">
        <label for="username">Username</label>
        <div class="input-wrap">
          <svg class="icon lead"><use href="#i-user"/></svg>
          <input id="username" name="username" type="text" value="{{ username }}" autocomplete="username"
                 pattern="[A-Za-z0-9_]{3,30}" required autofocus>
        </div>
        <p class="hint-text">3 to 30 letters, numbers or underscores.</p>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <div class="input-wrap">
          <svg class="icon lead"><use href="#i-lock"/></svg>
          <input id="password" name="password" type="password" autocomplete="new-password" minlength="10" required>
          <button class="reveal" type="button" id="reveal" aria-label="Show password">
            <svg class="icon eye"><use href="#i-eye"/></svg>
          </button>
        </div>
        <p class="hint-text">At least 10 characters. Do not reuse a password from another site.</p>
      </div>
      <div class="field">
        <label for="confirm">Confirm password</label>
        <div class="input-wrap">
          <svg class="icon lead"><use href="#i-lock"/></svg>
          <input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="10" required>
        </div>
      </div>
      {% if needs_invite %}
      <div class="field">
        <label for="invite">Invite code</label>
        <div class="input-wrap">
          <svg class="icon lead"><use href="#i-shield"/></svg>
          <input id="invite" name="invite" type="text" autocomplete="off" required>
        </div>
      </div>
      {% endif %}
      <button class="btn btn-primary btn-block" type="submit" id="loginBtn">Create account</button>
      <p class="auth-switch">Already registered? <a href="{{ url_for('login') }}">Sign in</a></p>
      {% endif %}
    </form>
  </section>
</main>
<script src="{{ url_for('static', filename='login.js') }}"></script>
</body>
</html>
GALLERY_EOF

cat > /opt/gallery/templates/index.html <<'GALLERY_EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf" content="{{ csrf_token }}">
  <meta name="max-mb" content="{{ max_mb }}">
  <meta name="trash-days" content="{{ trash_days }}">
  <title>PixelVault · Photos</title>
  <link rel="icon" type="image/svg+xml" href="{{ url_for('static', filename='logo.svg') }}">
  <script src="{{ url_for('static', filename='theme.js') }}"></script>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
  <link rel="stylesheet" href="{{ url_for('static', filename='v3.css') }}">
</head>
<body>
{% include "_icons.html" %}

<header class="topbar"><div class="topbar-in wide">
  <button class="btn-icon menu-btn" id="menuBtn" type="button" aria-label="Menu"><svg class="icon"><use href="#i-menu"/></svg></button>
  <a class="brand" href="#photos"><span class="brand-mark"><img src="{{ url_for('static', filename='logo.svg') }}" alt="" width="36" height="36"></span><span>PixelVault</span></a>
  <div class="search grow"><svg class="icon"><use href="#i-search"/></svg>
    <input id="search" type="search" placeholder="Search by name or camera…" aria-label="Search photos" autocomplete="off"></div>
  <button class="btn btn-primary" id="openUpload" type="button"><svg class="icon"><use href="#i-upload"/></svg><span class="hide-sm">Upload</span></button>
  <button class="btn-icon" id="themeToggle" type="button" aria-label="Toggle dark mode"><svg class="icon i-sun"><use href="#i-sun"/></svg><svg class="icon i-moon"><use href="#i-moon"/></svg></button>
  <span class="user-chip"><span class="avatar">{{ user[:1]|upper }}</span><span class="user-name">{{ user }}</span></span>
  <form method="post" action="{{ url_for('logout') }}" id="logoutForm"><input type="hidden" name="csrf" value="{{ csrf_token }}">
    <button class="btn btn-ghost logout-btn" id="logoutBtn" type="button" title="Log out"><svg class="icon"><use href="#i-logout"/></svg><span>Logout</span></button></form>
</div></header>

<div class="shell">
  <aside class="side" id="side" aria-label="Library">
    <nav class="nav">
      <a href="#photos" data-nav="photos"><svg class="icon"><use href="#i-photos"/></svg><span>Photos</span><b id="cPhotos">0</b></a>
      <a href="#favorites" data-nav="favorites"><svg class="icon"><use href="#i-star"/></svg><span>Favorites</span><b id="cFavs">0</b></a>
      <a href="#trash" data-nav="trash"><svg class="icon"><use href="#i-trash"/></svg><span>Trash</span><b id="cTrash">0</b></a>
    </nav>
    <div class="side-sec"><span>Albums</span><button class="btn-icon sm" id="newAlbum" type="button" aria-label="New album" title="New album"><svg class="icon"><use href="#i-plus"/></svg></button></div>
    <nav class="nav" id="albumList"></nav>
    <p class="side-empty muted small" id="noAlbums" hidden>No albums yet. Select photos and choose “Add to album”.</p>
    <div class="usage">
      <div class="usage-row"><span>Storage</span><b id="usedText">0 MB</b></div>
      <div class="meter"><i id="usedBar"></i></div>
      <div class="usage-row small muted"><span id="countText">0 photos</span><span title="{{ bucket }}">{{ region }}</span></div>
    </div>
  </aside>

  <main class="content">
    <div class="alert error" id="loadError" role="alert" hidden><svg class="icon"><use href="#i-alert"/></svg><span></span></div>

    <div class="view-head">
      <div><h1 id="viewTitle">Photos</h1><p class="muted small" id="viewSub"></p></div>
      <div class="spacer"></div>
      <button class="btn btn-ghost" id="renameAlbum" type="button" hidden><svg class="icon"><use href="#i-edit"/></svg><span>Rename</span></button>
      <button class="btn btn-ghost" id="deleteAlbum" type="button" hidden><svg class="icon"><use href="#i-trash"/></svg><span>Delete album</span></button>
      <button class="btn btn-ghost" id="emptyTrash" type="button" hidden><svg class="icon"><use href="#i-trash"/></svg><span>Empty trash</span></button>
      <label class="select"><span class="sr-only">Sort</span>
        <select id="sort"><option value="desc">Newest first</option><option value="asc">Oldest first</option><option value="name">Name A–Z</option><option value="size">Largest first</option></select></label>
    </div>

    <div class="selbar" id="selbar" hidden>
      <button class="btn-icon sm" data-act="clear" type="button" aria-label="Clear selection"><svg class="icon"><use href="#i-x"/></svg></button>
      <b id="selCount">0 selected</b><div class="spacer"></div>
      <button class="btn btn-ghost n-only" data-act="fav" type="button"><svg class="icon"><use href="#i-star"/></svg><span>Favorite</span></button>
      <button class="btn btn-ghost n-only" data-act="album" type="button"><svg class="icon"><use href="#i-folder"/></svg><span>Add to album</span></button>
      <button class="btn btn-ghost n-only a-only" data-act="unalbum" type="button"><svg class="icon"><use href="#i-x"/></svg><span>Remove from album</span></button>
      <button class="btn btn-ghost n-only" data-act="trash" type="button"><svg class="icon"><use href="#i-trash"/></svg><span>Trash</span></button>
      <button class="btn btn-ghost t-only" data-act="restore" type="button"><svg class="icon"><use href="#i-undo"/></svg><span>Restore</span></button>
      <button class="btn btn-danger t-only" data-act="purge" type="button"><svg class="icon"><use href="#i-trash"/></svg><span>Delete forever</span></button>
    </div>

    <div id="timeline" aria-live="polite"></div>
    <div class="empty" id="empty" hidden>
      <div class="empty-art"><svg class="icon" id="emptyIcon"><use href="#i-image"/></svg></div>
      <h3 id="emptyTitle">No photos yet</h3><p class="muted" id="emptyText"></p>
      <button class="btn btn-primary" id="emptyUpload" type="button"><svg class="icon"><use href="#i-upload"/></svg><span>Upload photos</span></button>
    </div>
    <footer class="foot"><span>Private S3 bucket</span><span class="dot"></span><span>Encrypted &amp; versioned</span><span class="dot"></span><span>Trash keeps items {{ trash_days }} days</span></footer>
  </main>
</div>

<div class="drop-overlay" id="dropOverlay" hidden><div><svg class="icon"><use href="#i-upload"/></svg>Drop photos to upload</div></div>

<!-- Lightbox -->
<div class="lightbox" id="lightbox" hidden role="dialog" aria-modal="true" aria-label="Photo viewer">
  <div class="lb-top">
    <div class="lb-title"><span id="lbName"></span><small id="lbMeta"></small></div>
    <div class="lb-tools">
      <button class="lb-btn n-only" id="lbFav" type="button" aria-label="Favorite" title="Favorite"><svg class="icon"><use href="#i-star"/></svg></button>
      <button class="lb-btn n-only" id="lbAlbum" type="button" aria-label="Add to album" title="Add to album"><svg class="icon"><use href="#i-folder"/></svg></button>
      <button class="lb-btn n-only" id="lbShare" type="button" aria-label="Share" title="Share link"><svg class="icon"><use href="#i-link"/></svg></button>
      <button class="lb-btn n-only" id="lbDownload" type="button" aria-label="Download" title="Download"><svg class="icon"><use href="#i-download"/></svg></button>
      <button class="lb-btn n-only" id="lbTrash" type="button" aria-label="Move to trash" title="Move to trash"><svg class="icon"><use href="#i-trash"/></svg></button>
      <button class="lb-btn t-only" id="lbRestore" type="button" aria-label="Restore" title="Restore"><svg class="icon"><use href="#i-undo"/></svg></button>
      <button class="lb-btn t-only" id="lbPurge" type="button" aria-label="Delete forever" title="Delete forever"><svg class="icon"><use href="#i-trash"/></svg></button>
      <button class="lb-btn" id="lbClose" type="button" aria-label="Close"><svg class="icon"><use href="#i-x"/></svg></button>
    </div>
  </div>
  <button class="lb-nav prev" id="lbPrev" type="button" aria-label="Previous"><svg class="icon"><use href="#i-left"/></svg></button>
  <figure class="lb-stage"><img id="lbImg" alt=""></figure>
  <button class="lb-nav next" id="lbNext" type="button" aria-label="Next"><svg class="icon"><use href="#i-right"/></svg></button>
  <div class="lb-count" id="lbCount"></div>
</div>

<!-- Upload -->
<dialog class="modal wide" id="uploadDialog" aria-labelledby="upTitle"><div class="modal-inner">
  <header class="modal-head"><h3 id="upTitle">Upload photos</h3><button class="btn-icon sm" type="button" data-close aria-label="Close"><svg class="icon"><use href="#i-x"/></svg></button></header>
  <label class="dropzone" id="dropzone" for="fileInput"><span class="dz-ico"><svg class="icon"><use href="#i-upload"/></svg></span>
    <span class="dz-title">Drag &amp; drop, or <u>browse</u></span><span class="dz-sub">PNG, JPG, GIF or WEBP · up to {{ max_mb }} MB each · duplicates are skipped</span>
    <input class="sr-only" id="fileInput" type="file" multiple accept="image/png,image/jpeg,image/gif,image/webp"></label>
  <ul class="queue" id="queue"></ul>
  <div class="queue-actions" id="queueActions" hidden><span class="muted" id="uploadStatus"></span><div class="spacer"></div>
    <button class="btn btn-ghost" id="clearBtn" type="button">Clear</button>
    <button class="btn btn-primary" id="uploadBtn" type="button"><svg class="icon"><use href="#i-upload"/></svg><span>Upload</span></button></div>
</div></dialog>

<!-- Share -->
<dialog class="modal" id="shareDialog" aria-labelledby="shareTitle"><div class="modal-inner">
  <header class="modal-head"><h3 id="shareTitle">Share photo</h3><button class="btn-icon sm" type="button" data-close aria-label="Close"><svg class="icon"><use href="#i-x"/></svg></button></header>
  <p class="muted modal-sub" id="shareName"></p>
  <fieldset class="segmented"><legend>New link expires after</legend>
    <label><input type="radio" name="minutes" value="60" checked><span>1 hour</span></label>
    <label><input type="radio" name="minutes" value="1440"><span>1 day</span></label>
    <label><input type="radio" name="minutes" value="10080"><span>7 days</span></label></fieldset>
  <div class="copy-field"><input id="shareUrl" type="text" readonly placeholder="Create a link to copy it" aria-label="Share URL">
    <button class="btn btn-primary" id="createLink" type="button"><svg class="icon"><use href="#i-link"/></svg><span>Create link</span></button></div>
  <h4 class="subhead">Active links</h4>
  <ul class="links" id="shareList"></ul>
  <div class="notice"><svg class="icon"><use href="#i-shield"/></svg><span>Anyone with a link can view the photo until it expires or you revoke it. Revoking works instantly.</span></div>
</div></dialog>

<!-- Album picker -->
<dialog class="modal" id="albumDialog" aria-labelledby="albTitle"><div class="modal-inner">
  <header class="modal-head"><h3 id="albTitle">Add to album</h3><button class="btn-icon sm" type="button" data-close aria-label="Close"><svg class="icon"><use href="#i-x"/></svg></button></header>
  <ul class="pick-list" id="pickList"></ul>
  <div class="copy-field"><input id="pickNew" class="text-input" type="text" maxlength="60" placeholder="New album name" aria-label="New album name">
    <button class="btn btn-primary" id="pickCreate" type="button"><svg class="icon"><use href="#i-plus"/></svg><span>Create</span></button></div>
</div></dialog>

<!-- Name prompt -->
<dialog class="modal" id="nameDialog" aria-labelledby="nameTitle"><form method="dialog" class="modal-inner">
  <h3 id="nameTitle">Album name</h3>
  <input class="text-input" id="nameInput" type="text" maxlength="60" required aria-label="Name">
  <div class="modal-actions"><button class="btn btn-ghost" type="button" data-close>Cancel</button><button class="btn btn-primary" value="ok" id="nameOk">Save</button></div>
</form></dialog>

<!-- Confirm -->
<dialog class="modal" id="confirmDialog" aria-labelledby="confTitle"><form method="dialog" class="modal-inner">
  <div class="del-ico"><svg class="icon"><use href="#i-trash"/></svg></div>
  <h3 id="confTitle">Are you sure?</h3><p class="muted" id="confText"></p>
  <div class="modal-actions"><button class="btn btn-ghost" type="button" data-close>Cancel</button><button class="btn btn-danger" value="ok" id="confOk">Confirm</button></div>
</form></dialog>

<!-- Logout confirm -->
<dialog class="modal" id="logoutDialog" aria-labelledby="logoutTitle"><form method="dialog" class="modal-inner">
  <div class="del-ico logout-ico"><svg class="icon"><use href="#i-logout"/></svg></div>
  <h3 id="logoutTitle">Log out of PixelVault?</h3><p class="muted">You will need to sign in again to see your photos.</p>
  <div class="modal-actions"><button class="btn btn-ghost" type="button" data-close>Stay signed in</button><button class="btn btn-primary" value="ok">Log out</button></div>
</form></dialog>

<div class="toasts" id="toasts" aria-live="polite"></div>
<script src="{{ url_for('static', filename='app.js') }}"></script>
</body>
</html>
GALLERY_EOF

cat > /opt/gallery/templates/_icons.html <<'GALLERY_EOF'
<svg class="sprite" aria-hidden="true" focusable="false">
  <symbol id="i-layers" viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></symbol>
  <symbol id="i-upload" viewBox="0 0 24 24"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></symbol>
  <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></symbol>
  <symbol id="i-grid" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></symbol>
  <symbol id="i-list" viewBox="0 0 24 24"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></symbol>
  <symbol id="i-link" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></symbol>
  <symbol id="i-trash" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></symbol>
  <symbol id="i-x" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></symbol>
  <symbol id="i-left" viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"/></symbol>
  <symbol id="i-right" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></symbol>
  <symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></symbol>
  <symbol id="i-check" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></symbol>
  <symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></symbol>
  <symbol id="i-moon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></symbol>
  <symbol id="i-logout" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></symbol>
  <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></symbol>
  <symbol id="i-image" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></symbol>
  <symbol id="i-lock" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></symbol>
  <symbol id="i-user" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></symbol>
  <symbol id="i-eye" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></symbol>
  <symbol id="i-eye-off" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></symbol>
  <symbol id="i-database" viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></symbol>
  <symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></symbol>
  <symbol id="i-alert" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></symbol>
  <symbol id="i-star" viewBox="0 0 24 24"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></symbol>
  <symbol id="i-folder" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></symbol>
  <symbol id="i-undo" viewBox="0 0 24 24"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></symbol>
  <symbol id="i-download" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></symbol>
  <symbol id="i-plus" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></symbol>
  <symbol id="i-photos" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></symbol>
  <symbol id="i-menu" viewBox="0 0 24 24"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></symbol>
  <symbol id="i-edit" viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></symbol>
</svg>
GALLERY_EOF

cat > /opt/gallery/static/app.js <<'GALLERY_EOF'
/* PixelVault v3 front-end: timeline, selection, albums, trash, sharing, uploads. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const meta = n => $(`meta[name="${n}"]`).content;
  const CSRF = meta("csrf"), MAX_MB = Number(meta("max-mb")), MAX_BYTES = MAX_MB * 1048576, TRASH_DAYS = Number(meta("trash-days"));
  const TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp"], MAX_QUEUE = 20, NS = "http://www.w3.org/2000/svg";

  /* ---------- helpers ---------- */
  const fmtBytes = b => { if (b < 1024) return `${b} B`; const u = ["KB", "MB", "GB"]; let i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < 2); return `${b.toFixed(1)} ${u[i]}`; };
  const svg = name => { const s = document.createElementNS(NS, "svg"); s.setAttribute("class", "icon");
    const u = document.createElementNS(NS, "use"); u.setAttribute("href", "#i-" + name); s.appendChild(u); return s; };
  function h(tag, attrs = {}, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) { if (v === false || v == null) continue; el.setAttribute(k, v === true ? "" : v); }
    el.append(...kids.filter(k => k != null)); return el;
  }
  function toast(message, type = "info", ms = 4200, action) {
    const el = h("div", { class: `toast ${type}`, role: type === "error" ? "alert" : "status" });
    const x = h("button", { type: "button", class: "toast-x", "aria-label": "Dismiss" }, svg("x"));
    el.append(svg({ success: "check", error: "alert" }[type] || "shield"), h("span", {}, message));
    const close = () => { el.classList.add("out"); setTimeout(() => el.remove(), 200); };
    if (action) { const a = h("button", { type: "button", class: "toast-act" }, action.label);
      a.addEventListener("click", () => { close(); action.fn(); }); el.append(a); }
    x.addEventListener("click", close); el.append(x); $("#toasts").appendChild(el); setTimeout(close, ms);
  }
  async function api(url, body) {
    const opts = body === undefined ? { credentials: "same-origin" } : { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF }, body: JSON.stringify(body) };
    const res = await fetch(url, opts);
    if (res.status === 401) { location.href = "/login"; throw new Error("Session expired"); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) throw new Error(data.error || "Request failed");
    return data;
  }
  const startOfDay = d => new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const dayKey = ts => { const d = new Date(ts * 1000); return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`; };
  function dayLabel(ts) {
    const d = new Date(ts * 1000), n = new Date(), diff = Math.round((startOfDay(n) - startOfDay(d)) / 864e5);
    if (diff === 0) return "Today"; if (diff === 1) return "Yesterday";
    return d.toLocaleDateString(undefined, { weekday: diff < 7 ? "long" : "short", day: "numeric", month: "short", year: d.getFullYear() === n.getFullYear() ? undefined : "numeric" });
  }

  /* ---------- theme / mobile menu ---------- */
  $("#themeToggle").addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("theme", next); } catch (e) { /* ignore */ }
  });
  $("#menuBtn").addEventListener("click", () => $("#side").classList.toggle("open"));

  /* ---------- dialogs ---------- */
  $$("dialog").forEach(d => {
    d.addEventListener("click", e => { if (e.target === d) d.close(); });
    $$("[data-close]", d).forEach(b => b.addEventListener("click", () => d.close()));
  });
  function ask(dlg, setup) {                       // promise wrapper around <form method=dialog>
    return new Promise(res => { dlg.returnValue = ""; setup();
      dlg.addEventListener("close", () => res(dlg.returnValue === "ok"), { once: true }); dlg.showModal(); });
  }
  const confirmDlg = (title, text, button) => ask($("#confirmDialog"), () => {
    $("#confTitle").textContent = title; $("#confText").textContent = text; $("#confOk").textContent = button; });
  async function askName(title, value) {
    const ok = await ask($("#nameDialog"), () => { $("#nameTitle").textContent = title; $("#nameInput").value = value || ""; });
    return ok ? $("#nameInput").value.trim() : null;
  }

  /* ---------- state ---------- */
  const S = { view: "photos", album: null, items: [], sum: null, sel: new Set(), q: "", sort: "desc", loadedAt: 0, lb: -1 };
  const byId = id => S.items.find(i => i.id === id);
  const inTrash = () => S.view === "trash";

  function shown() {
    const q = S.q.toLowerCase();
    const list = S.items.filter(i => !q || i.name.toLowerCase().includes(q) || (i.camera || "").toLowerCase().includes(q));
    const cmp = { desc: (a, b) => b.taken - a.taken, asc: (a, b) => a.taken - b.taken,
      name: (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" }), size: (a, b) => b.size - a.size }[S.sort];
    return list.sort(cmp);
  }

  async function loadAll() {
    const qs = new URLSearchParams({ view: S.view }); if (S.album) qs.set("album", S.album);
    try {
      const [p, s] = await Promise.all([api(`/api/photos?${qs}`), api("/api/summary")]);
      S.items = p.items; S.sum = s; S.loadedAt = Date.now(); $("#loadError").hidden = true;
    } catch (e) {
      if (S.view === "album") { location.hash = "#photos"; return; }
      $("#loadError span").textContent = e.message; $("#loadError").hidden = false;
    }
    S.sel = new Set([...S.sel].filter(id => byId(id)));
    render();
  }
  function route() {
    const hash = location.hash.slice(1) || "photos";
    if (hash.startsWith("album/")) { S.view = "album"; S.album = hash.slice(6); }
    else { S.view = ["photos", "favorites", "trash"].includes(hash) ? hash : "photos"; S.album = null; }
    S.sel.clear(); closeLb(); $("#side").classList.remove("open"); loadAll();
  }

  /* ---------- rendering ---------- */
  function render() { renderSide(); renderHead(); renderTimeline(); renderSelbar(); }

  function renderSide() {
    const s = S.sum; if (!s) return;
    $("#cPhotos").textContent = s.photos; $("#cFavs").textContent = s.favorites; $("#cTrash").textContent = s.trash;
    const list = $("#albumList"); list.replaceChildren(...s.albums.map(a =>
      h("a", { href: `#album/${a.id}`, "data-nav": `album/${a.id}` }, svg("folder"), h("span", {}, a.name), h("b", {}, String(a.count)))));
    $("#noAlbums").hidden = s.albums.length > 0;
    const key = S.view === "album" ? `album/${S.album}` : S.view;
    $$("[data-nav]").forEach(a => a.classList.toggle("active", a.dataset.nav === key));
    const pct = Math.min(100, Math.max(s.used_bytes / (s.quota_mb * 1048576), s.total / s.max_images) * 100);
    $("#usedBar").style.width = pct + "%"; $("#usedBar").parentElement.classList.toggle("warn", pct > 85);
    $("#usedText").textContent = `${s.used_label} of ${s.quota_mb} MB`; $("#countText").textContent = `${s.total} of ${s.max_images} photos`;
  }

  function renderHead() {
    const alb = S.view === "album" ? (S.sum?.albums.find(a => a.id === S.album)) : null;
    $("#viewTitle").textContent = { photos: "Photos", favorites: "Favorites", trash: "Trash" }[S.view] || alb?.name || "Album";
    $("#viewSub").textContent = inTrash() ? `Items are permanently deleted after ${TRASH_DAYS} days.` : `${S.items.length} item${S.items.length === 1 ? "" : "s"}`;
    $("#renameAlbum").hidden = $("#deleteAlbum").hidden = S.view !== "album";
    $("#emptyTrash").hidden = !(inTrash() && S.items.length);
    document.title = `${$("#viewTitle").textContent} · PixelVault`;
  }

  function renderTimeline() {
    const list = shown(), root = $("#timeline"), groups = [];
    for (const it of list) {
      const k = S.sort === "asc" || S.sort === "desc" ? dayKey(it.taken) : "all";
      let g = groups[groups.length - 1];
      if (!g || g.key !== k) { g = { key: k, label: k === "all" ? "" : dayLabel(it.taken), items: [] }; groups.push(g); }
      g.items.push(it);
    }
    root.replaceChildren(...groups.map(g => {
      const all = g.items.every(i => S.sel.has(i.id));
      const head = g.label ? h("div", { class: "group-head" },
        h("button", { class: "group-check" + (all ? " on" : ""), type: "button", "data-group": g.items.map(i => i.id).join(","), "aria-label": `Select ${g.label}` }, svg("check")),
        h("span", {}, g.label), h("small", { class: "muted" }, `${g.items.length}`)) : null;
      return h("section", { class: "group" }, head, h("div", { class: "grid" }, ...g.items.map(tile)));
    }));
    const empty = list.length === 0;
    $("#empty").hidden = !empty;
    if (empty) {
      const q = S.q, t = { photos: ["No photos yet", "Upload your first photo — it's stored privately in S3.", "photos"],
        favorites: ["No favorites", "Tap the star on a photo to find it here.", "star"], trash: ["Trash is empty", "Deleted photos wait here before they're gone for good.", "trash"],
        album: ["This album is empty", "Select photos in your library and choose “Add to album”.", "folder"] }[S.view];
      $("#emptyTitle").textContent = q ? "No matches" : t[0]; $("#emptyText").textContent = q ? "Try a different search." : t[1];
      $("#emptyIcon").replaceWith(Object.assign(svg(q ? "search" : t[2]), { id: "emptyIcon" }));
      $("#emptyUpload").hidden = !!q || S.view !== "photos";
    }
  }

  function tile(it) {
    const img = h("img", { src: it.thumb, alt: it.name, loading: "lazy", decoding: "async" });
    const el = h("div", { class: "tile" + (S.sel.has(it.id) ? " sel" : ""), "data-id": it.id },
      h("button", { class: "tile-open", type: "button", "aria-label": `Open ${it.name}` }, h("span", { class: "skeleton" }), img),
      h("button", { class: "tile-check", type: "button", "aria-label": `Select ${it.name}` }, svg("check")),
      it.favorite ? h("span", { class: "tile-fav", title: "Favorite" }, svg("star")) : null);
    img.addEventListener("load", () => el.classList.add("loaded"), { once: true });
    img.addEventListener("error", () => el.classList.add("loaded", "broken"), { once: true });
    return el;
  }

  function renderSelbar() {
    const n = S.sel.size;
    $("#selbar").hidden = n === 0; document.body.classList.toggle("selecting", n > 0);
    $("#selCount").textContent = `${n} selected`;
    $$("#selbar .n-only").forEach(b => b.hidden = inTrash());
    $$("#selbar .t-only").forEach(b => b.hidden = !inTrash());
    $$("#selbar .a-only").forEach(b => b.hidden = S.view !== "album");
    const ids = [...S.sel].map(byId).filter(Boolean);
    $("#selbar [data-act=fav] span").textContent = ids.length && ids.every(i => i.favorite) ? "Unfavorite" : "Favorite";
  }

  /* ---------- selection ---------- */
  function toggleSel(id) {
    S.sel.has(id) ? S.sel.delete(id) : S.sel.add(id);
    const t = $(`.tile[data-id="${id}"]`); if (t) t.classList.toggle("sel", S.sel.has(id));
    renderSelbar();
  }
  $("#timeline").addEventListener("click", e => {
    const grp = e.target.closest(".group-check");
    if (grp) { const ids = grp.dataset.group.split(","), all = ids.every(i => S.sel.has(i));
      ids.forEach(i => all ? S.sel.delete(i) : S.sel.add(i)); renderTimeline(); renderSelbar(); return; }
    const t = e.target.closest(".tile"); if (!t) return;
    if (e.target.closest(".tile-check") || S.sel.size || e.shiftKey || e.ctrlKey || e.metaKey) toggleSel(t.dataset.id);
    else openLb(t.dataset.id);
  });

  /* ---------- actions ---------- */
  async function run(name, ids, opts = {}) {
    const n = ids.length, s = n === 1 ? "" : "s";
    try {
      if (name === "fav") { const v = !ids.every(i => byId(i)?.favorite); await api("/api/favorite", { ids, value: v }); toast(v ? `Added ${n} to favorites` : "Removed from favorites", "success", 2200); }
      else if (name === "trash") await api("/api/trash", { ids }), toast(`${n} photo${s} moved to trash`, "success", 6000, { label: "Undo", fn: () => run("restore", ids, { silent: true }) });
      else if (name === "restore") { await api("/api/restore", { ids }); if (!opts.silent) toast(`Restored ${n} photo${s}`, "success"); else toast("Restored", "success", 2000); }
      else if (name === "purge") {
        if (!await confirmDlg(`Delete ${n} photo${s} forever?`, "This removes the files from S3. It can't be undone from the app.", "Delete forever")) return;
        await api("/api/purge", { ids }); toast(`Deleted ${n} photo${s} permanently`, "success");
      } else if (name === "unalbum") { await api("/api/albums/remove", { id: S.album, ids }); toast("Removed from album", "success", 2200); }
      else if (name === "album") { if (!await pickAlbum(ids)) return; }
    } catch (e) { toast(e.message, "error"); return; }
    S.sel.clear(); await loadAll();
  }
  $("#selbar").addEventListener("click", e => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    if (b.dataset.act === "clear") { S.sel.clear(); render(); } else run(b.dataset.act, [...S.sel]);
  });
  document.addEventListener("keydown", e => {
    if (e.target.matches("input,textarea,select") || $("dialog[open]")) return;
    if (!$("#lightbox").hidden) return;
    if (e.key === "Escape" && S.sel.size) { S.sel.clear(); render(); }
    else if ((e.key === "Delete" || e.key === "Backspace") && S.sel.size && !inTrash()) run("trash", [...S.sel]);
    else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "a") { e.preventDefault(); shown().forEach(i => S.sel.add(i.id)); renderTimeline(); renderSelbar(); }
  });

  /* albums */
  function pickAlbum(ids) {
    return new Promise(resolve => {
      const dlg = $("#albumDialog"); let done = false;
      const finish = async (albumId, label) => {
        try { await api("/api/albums/add", { id: albumId, ids }); toast(`Added ${ids.length} to “${label}”`, "success"); done = true; dlg.close(); }
        catch (e) { toast(e.message, "error"); }
      };
      $("#pickList").replaceChildren(...(S.sum.albums.length ? S.sum.albums.map(a =>
        h("li", {}, (() => { const b = h("button", { type: "button", class: "pick" }, svg("folder"), h("span", {}, a.name), h("small", { class: "muted" }, String(a.count)));
          b.addEventListener("click", () => finish(a.id, a.name)); return b; })())) : [h("li", { class: "muted small pad" }, "No albums yet — create one below.")]));
      $("#pickNew").value = "";
      $("#pickCreate").onclick = async () => { const name = $("#pickNew").value.trim(); if (!name) return;
        try { const r = await api("/api/albums/create", { name }); await finish(r.id, r.name); } catch (e) { toast(e.message, "error"); } };
      dlg.addEventListener("close", () => resolve(done), { once: true }); dlg.showModal();
    });
  }
  $("#newAlbum").addEventListener("click", async () => {
    const name = await askName("New album", ""); if (!name) return;
    try { const r = await api("/api/albums/create", { name }); location.hash = `#album/${r.id}`; } catch (e) { toast(e.message, "error"); }
  });
  $("#renameAlbum").addEventListener("click", async () => {
    const cur = S.sum.albums.find(a => a.id === S.album), name = await askName("Rename album", cur?.name); if (!name) return;
    try { await api("/api/albums/rename", { id: S.album, name }); await loadAll(); } catch (e) { toast(e.message, "error"); }
  });
  $("#deleteAlbum").addEventListener("click", async () => {
    if (!await confirmDlg("Delete this album?", "The photos stay in your library — only the album is removed.", "Delete album")) return;
    try { await api("/api/albums/delete", { id: S.album }); location.hash = "#photos"; } catch (e) { toast(e.message, "error"); }
  });
  $("#emptyTrash").addEventListener("click", async () => {
    if (!await confirmDlg("Empty trash?", `${S.items.length} photo(s) will be permanently deleted from S3.`, "Empty trash")) return;
    try { await api("/api/purge", { all: true }); toast("Trash emptied", "success"); await loadAll(); } catch (e) { toast(e.message, "error"); }
  });

  /* ---------- share ---------- */
  const shareDlg = $("#shareDialog"); let shareId = null;
  const when = ts => new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) { const t = $("#shareUrl"); const old = t.value; t.value = text; t.select(); document.execCommand("copy"); t.value = old; }   // plain-HTTP fallback
    toast("Link copied", "success", 1800);
  }
  async function loadLinks() {
    try {
      const d = await api(`/api/shares?id=${shareId}`);
      $("#shareList").replaceChildren(...(d.links.length ? d.links.map(l => {
        const copy = h("button", { type: "button", class: "btn btn-ghost sm" }, "Copy"), rev = h("button", { type: "button", class: "btn btn-ghost sm danger-text" }, "Revoke");
        copy.addEventListener("click", () => copyText(l.url));
        rev.addEventListener("click", async () => { try { await api("/api/share/revoke", { token: l.token }); toast("Link revoked", "success", 2000); loadLinks(); } catch (e) { toast(e.message, "error"); } });
        return h("li", {}, h("div", {}, h("div", {}, `Expires ${when(l.expires_at)}`), h("small", { class: "muted" }, `${l.views} view${l.views === 1 ? "" : "s"}`)), h("div", { class: "row" }, copy, rev));
      }) : [h("li", { class: "muted small" }, "No active links.")]));
    } catch (e) { toast(e.message, "error"); }
  }
  function openShare(id) {
    shareId = id; $("#shareName").textContent = byId(id).name; $("#shareUrl").value = ""; shareDlg.showModal(); loadLinks();
  }
  $("#createLink").addEventListener("click", async () => {
    const btn = $("#createLink"); btn.disabled = true;
    try { const d = await api("/api/share/create", { id: shareId, minutes: Number($('input[name="minutes"]:checked').value) });
      $("#shareUrl").value = d.url; await copyText(d.url); loadLinks(); }
    catch (e) { toast(e.message, "error"); } finally { btn.disabled = false; }
  });

  /* ---------- lightbox ---------- */
  const lb = $("#lightbox"); let lbList = [], lbIndex = 0;
  const cur = () => lbList[lbIndex];
  function showLb() {
    const c = cur(); if (!c) return closeLb();
    $("#lbImg").src = c.url; $("#lbImg").alt = c.name; $("#lbName").textContent = c.name;
    const parts = [fmtBytes(c.size), new Date(c.taken * 1000).toLocaleString(), c.width ? `${c.width}×${c.height}` : null, c.camera].filter(Boolean);
    $("#lbMeta").textContent = parts.join(" · ");
    $("#lbCount").textContent = `${lbIndex + 1} / ${lbList.length}`;
    $("#lbPrev").hidden = $("#lbNext").hidden = lbList.length < 2;
    $("#lbFav").classList.toggle("on", c.favorite);
    $$(".lb-tools .n-only", lb).forEach(b => b.hidden = inTrash()); $$(".lb-tools .t-only", lb).forEach(b => b.hidden = !inTrash());
  }
  function openLb(id) {
    lbList = shown(); lbIndex = Math.max(0, lbList.findIndex(i => i.id === id));
    showLb(); lb.hidden = false; document.body.classList.add("noscroll"); $("#lbClose").focus();
  }
  function closeLb() { lb.hidden = true; $("#lbImg").removeAttribute("src"); document.body.classList.remove("noscroll"); }
  const stepLb = d => { if (!lbList.length) return; lbIndex = (lbIndex + d + lbList.length) % lbList.length; showLb(); };
  async function lbAct(name) {                     // run an action on the open photo, then keep the viewer on the next one
    const id = cur().id, keep = lbIndex;
    await run(name, [id]);
    lbList = shown(); lbIndex = Math.min(keep, lbList.length - 1);
    if (!lbList.length) closeLb(); else if (!lb.hidden) showLb();
  }
  $("#lbClose").addEventListener("click", closeLb);
  $("#lbPrev").addEventListener("click", () => stepLb(-1)); $("#lbNext").addEventListener("click", () => stepLb(1));
  $("#lbFav").addEventListener("click", async () => { const id = cur().id; await run("fav", [id]); lbList = shown(); lbIndex = Math.max(0, lbList.findIndex(i => i.id === id)); showLb(); });
  $("#lbTrash").addEventListener("click", () => lbAct("trash"));
  $("#lbRestore").addEventListener("click", () => lbAct("restore"));
  $("#lbPurge").addEventListener("click", () => lbAct("purge"));
  $("#lbAlbum").addEventListener("click", () => run("album", [cur().id]));
  $("#lbShare").addEventListener("click", () => openShare(cur().id));
  $("#lbDownload").addEventListener("click", () => { location.href = `/download/${cur().id}`; });
  lb.addEventListener("click", e => { if (e.target === lb || e.target.classList.contains("lb-stage")) closeLb(); });
  document.addEventListener("keydown", e => {
    if (lb.hidden || $("dialog[open]")) return;
    if (e.key === "Escape") closeLb(); else if (e.key === "ArrowLeft") stepLb(-1); else if (e.key === "ArrowRight") stepLb(1);
  });

  /* ---------- toolbar bits ---------- */
  $("#search").addEventListener("input", e => { S.q = e.target.value.trim(); renderTimeline(); });
  $("#sort").addEventListener("change", e => { S.sort = e.target.value; renderTimeline(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && Date.now() - S.loadedAt > 600000) loadAll(); });  // pre-signed links expire after 15 min

  /* ---------- upload ---------- */
  const upDlg = $("#uploadDialog"), input = $("#fileInput"), queueEl = $("#queue"), upBtn = $("#uploadBtn"), clearBtn = $("#clearBtn"), upStatus = $("#uploadStatus"), dz = $("#dropzone");
  let queue = [], busy = false;
  const openUpload = () => { if (!upDlg.open) upDlg.showModal(); };
  $("#openUpload").addEventListener("click", openUpload); $("#emptyUpload").addEventListener("click", openUpload);
  function makeItem(item) {
    const li = h("li", { class: "q-item", "data-state": "ready" });
    const name = h("div", { class: "q-name" }, item.file.name), metaEl = h("div", { class: "q-meta" }, fmtBytes(item.file.size));
    const fill = h("i"), bar = h("div", { class: "bar" }, fill);
    const rm = h("button", { type: "button", class: "btn-icon sm", "aria-label": `Remove ${item.file.name}` }, svg("x"));
    rm.addEventListener("click", () => { if (busy) return; URL.revokeObjectURL(item.url); queue = queue.filter(q => q !== item); renderQueue(); });
    li.append(h("img", { src: item.url, alt: "" }), h("div", { class: "q-body" }, name, metaEl, bar), rm);
    Object.assign(item, { li, metaEl, fill }); return li;
  }
  function renderQueue() {
    queueEl.replaceChildren(...queue.map(makeItem)); $("#queueActions").hidden = queue.length === 0;
    upBtn.querySelector("span").textContent = `Upload ${queue.length} photo${queue.length === 1 ? "" : "s"}`; upStatus.textContent = "";
  }
  function addFiles(files) {
    for (const f of files) {
      if (!TYPES.includes(f.type)) { toast(`${f.name}: unsupported file type`, "error"); continue; }
      if (f.size > MAX_BYTES) { toast(`${f.name}: larger than ${MAX_MB} MB`, "error"); continue; }
      if (queue.some(q => q.file.name === f.name && q.file.size === f.size && q.file.lastModified === f.lastModified)) continue;
      if (queue.length >= MAX_QUEUE) { toast(`Up to ${MAX_QUEUE} photos at a time`, "info"); break; }
      queue.push({ file: f, url: URL.createObjectURL(f) });
    }
    renderQueue(); openUpload();
  }
  const mark = (item, state, text) => { item.li.dataset.state = state; item.metaEl.textContent = text; if (state === "done") item.fill.style.width = "100%"; };
  function sendOne(item) {
    return new Promise(resolve => {
      const xhr = new XMLHttpRequest(); xhr.open("POST", "/upload"); xhr.setRequestHeader("X-CSRF-Token", CSRF); xhr.responseType = "json";
      xhr.upload.onprogress = e => { if (e.lengthComputable) { const p = Math.round(e.loaded / e.total * 100); item.fill.style.width = p + "%"; item.metaEl.textContent = `Uploading… ${p}%`; } };
      xhr.onload = () => { if (xhr.status === 401) { location.href = "/login"; return resolve(false); }
        const d = xhr.response || {}; if (xhr.status < 300 && d.ok) { mark(item, "done", "Uploaded"); resolve(true); }
        else { mark(item, xhr.status === 409 ? "dup" : "error", d.error || "Upload failed"); resolve(xhr.status === 409 ? "dup" : false); } };
      xhr.onerror = () => { mark(item, "error", "Network error"); resolve(false); };
      const fd = new FormData(); fd.append("image", item.file); xhr.send(fd);
    });
  }
  upBtn.addEventListener("click", async () => {
    if (busy || !queue.length) return; busy = true; upBtn.disabled = clearBtn.disabled = true;
    const todo = queue.filter(q => !["done", "dup"].includes(q.li.dataset.state)); let okN = 0, dupN = 0, failN = 0;
    for (let i = 0; i < todo.length; i++) { upStatus.textContent = `Uploading ${i + 1} of ${todo.length}…`;
      const r = await sendOne(todo[i]); r === true ? okN++ : r === "dup" ? dupN++ : failN++; }
    if (okN) toast(`${okN} photo${okN === 1 ? "" : "s"} uploaded`, "success");
    if (dupN) toast(`${dupN} duplicate${dupN === 1 ? "" : "s"} skipped`, "info");
    if (failN) toast(`${failN} upload${failN === 1 ? "" : "s"} failed`, "error");
    busy = false; upBtn.disabled = clearBtn.disabled = false;
    if (okN) { if (location.hash !== "#photos" && S.view !== "photos") location.hash = "#photos"; await loadAll(); }
    if (!failN) setTimeout(() => { if (upDlg.open) upDlg.close(); queue.forEach(q => URL.revokeObjectURL(q.url)); queue = []; renderQueue(); }, 900);
    else upStatus.textContent = "Some files failed. Remove them or retry.";
  });
  clearBtn.addEventListener("click", () => { queue.forEach(q => URL.revokeObjectURL(q.url)); queue = []; renderQueue(); });
  input.addEventListener("change", () => { if (!busy) addFiles(input.files); input.value = ""; });
  [["dragenter", "dragover"], ["dragleave", "drop"]].forEach(([a, b], i) => [a, b].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.toggle("drag", i === 0 || t === "dragover"); if (i === 1) dz.classList.remove("drag"); })));
  let dragDepth = 0; const ov = $("#dropOverlay");               // drop anywhere on the page
  window.addEventListener("dragenter", e => { if (e.dataTransfer?.types?.includes("Files")) { dragDepth++; ov.hidden = false; } });
  window.addEventListener("dragleave", () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) ov.hidden = true; });
  window.addEventListener("dragover", e => e.preventDefault());
  window.addEventListener("drop", e => { e.preventDefault(); dragDepth = 0; ov.hidden = true; if (!busy && e.dataTransfer?.files?.length) addFiles(e.dataTransfer.files); });

  /* ---------- logout confirmation ---------- */
  $("#logoutBtn").addEventListener("click", async () => {
    if (await ask($("#logoutDialog"), () => {})) $("#logoutForm").submit();
  });

  window.addEventListener("hashchange", route); route();
})();
GALLERY_EOF

cat > /opt/gallery/static/style.css <<'GALLERY_EOF'
/* ===================== Design tokens ===================== */
:root{
  --bg:#f5f6fb; --surface:#fff; --surface-2:#f0f2f9; --border:#e2e5f0;
  --text:#0f172a; --muted:#64748b;
  --brand:#4f46e5; --brand-hover:#4338ca; --brand-soft:#eceeff; --on-brand:#fff;
  --danger:#dc2626; --danger-hover:#b91c1c; --danger-soft:#fee2e2;
  --success:#15803d; --success-soft:#dcfce7;
  --radius:14px; --radius-sm:10px;
  --shadow-sm:0 1px 2px rgba(15,23,42,.06),0 1px 3px rgba(15,23,42,.05);
  --shadow:0 18px 40px -14px rgba(15,23,42,.28);
  --font:"Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  color-scheme:light;
}
[data-theme="dark"]{
  --bg:#0a0f1f; --surface:#121932; --surface-2:#19224280; --border:#242f56;
  --text:#e8ebf7; --muted:#93a0c4;
  --brand:#818cf8; --brand-hover:#9aa4fb; --brand-soft:#1d2551; --on-brand:#0a0f1f;
  --danger:#f87171; --danger-hover:#fca5a5; --danger-soft:#3b1620;
  --success:#4ade80; --success-soft:#11301f;
  --shadow-sm:0 1px 2px rgba(0,0,0,.4);
  --shadow:0 18px 40px -14px rgba(0,0,0,.7);
  color-scheme:dark;
}

/* ===================== Base ===================== */
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;font-family:var(--font);font-size:15px;line-height:1.5;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}
[hidden]{display:none!important}
h1,h2,h3,p{margin:0}
img{max-width:100%;display:block}
button,input,select{font:inherit;color:inherit}
button{cursor:pointer}
u{text-decoration-color:var(--brand);text-underline-offset:3px;color:var(--brand)}
:focus-visible{outline:2px solid var(--brand);outline-offset:2px}
.sr-only{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.sprite{position:absolute;width:0;height:0;overflow:hidden}
.icon{width:18px;height:18px;flex:none;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.muted{color:var(--muted)} .small{font-size:13px} .spacer{flex:1}
.noscroll{overflow:hidden}
.dot{width:3px;height:3px;border-radius:50%;background:currentColor;opacity:.45;display:inline-block}
:root:not([data-theme="dark"]) .i-moon,[data-theme="dark"] .i-sun{display:none}

/* ===================== Buttons ===================== */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:40px;padding:0 16px;border-radius:var(--radius-sm);border:1px solid transparent;font-weight:600;font-size:14px;transition:background .15s,transform .05s,box-shadow .15s}
.btn:active{transform:translateY(1px)}
.btn:disabled{opacity:.55;cursor:not-allowed}
.btn-primary{background:var(--brand);color:var(--on-brand);box-shadow:0 6px 16px -8px var(--brand)}
.btn-primary:hover:not(:disabled){background:var(--brand-hover)}
.btn-ghost{background:transparent;border-color:var(--border);color:var(--text)}
.btn-ghost:hover{background:var(--surface-2)}
.btn-danger{background:var(--danger);color:#fff}
.btn-danger:hover:not(:disabled){background:var(--danger-hover)}
.btn-block{width:100%;height:44px}
.btn-icon{width:38px;height:38px;display:inline-grid;place-items:center;border-radius:var(--radius-sm);border:1px solid transparent;background:transparent;color:var(--muted);transition:background .15s,color .15s}
.btn-icon:hover{background:var(--surface-2);color:var(--text)}
.btn-icon.sm{width:32px;height:32px}
.btn-icon.danger:hover{background:var(--danger-soft);color:var(--danger)}

/* ===================== Top bar ===================== */
.topbar{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--surface) 88%,transparent);backdrop-filter:saturate(1.4) blur(12px);border-bottom:1px solid var(--border)}
.topbar-in{max-width:1200px;margin:0 auto;padding:12px 24px;display:flex;align-items:center;gap:12px}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:17px;letter-spacing:-.01em;line-height:1.2}
.brand small{display:block;font-weight:500;font-size:11.5px;color:var(--muted);letter-spacing:0}
.brand-mark{width:36px;height:36px;border-radius:11px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,#6366f1,#8b5cf6);box-shadow:0 8px 18px -8px rgba(99,102,241,.8)}
.chip{display:inline-flex;align-items:center;gap:6px;height:30px;padding:0 12px;border-radius:999px;font-size:12.5px;font-weight:600}
.chip .icon{width:14px;height:14px}
.chip-ok{background:var(--success-soft);color:var(--success)}
.user-chip{display:flex;align-items:center;gap:8px;padding:3px 12px 3px 3px;border:1px solid var(--border);border-radius:999px;font-weight:600;font-size:13px}
.avatar{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;background:var(--brand-soft);color:var(--brand);font-weight:700}

/* ===================== Layout ===================== */
.container{max-width:1200px;margin:0 auto;padding:28px 24px 56px}
.page-head{margin-bottom:20px}
.page-head h1{font-size:26px;letter-spacing:-.02em}
.page-head p{margin-top:2px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow-sm);margin-bottom:28px}

/* ===================== Stats ===================== */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.stat{display:flex;gap:14px;align-items:center;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow-sm);min-width:0}
.stat>div{min-width:0}
.stat-ico{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;background:var(--brand-soft);color:var(--brand);flex:none}
.stat-ico.ok{background:var(--success-soft);color:var(--success)}
.stat-label{font-size:12.5px;color:var(--muted);font-weight:500}
.stat-value{font-size:22px;font-weight:700;letter-spacing:-.02em;line-height:1.25}
.stat-value.sm{font-size:15px;padding:3px 0}
.stat-sub{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ===================== Dropzone / queue ===================== */
.dropzone{display:flex;flex-direction:column;align-items:center;gap:6px;padding:34px 16px;text-align:center;border:2px dashed var(--border);border-radius:var(--radius);background:var(--surface-2);cursor:pointer;transition:border-color .15s,background .15s}
.dropzone:hover,.dropzone.drag,.dropzone:focus-within{border-color:var(--brand);background:var(--brand-soft)}
.dz-ico{width:52px;height:52px;border-radius:50%;display:grid;place-items:center;background:var(--surface);color:var(--brand);box-shadow:var(--shadow-sm);margin-bottom:6px}
.dz-ico .icon{width:24px;height:24px}
.dropzone.drag .dz-ico{transform:scale(1.1);transition:transform .15s}
.dz-title{font-weight:600}
.dz-sub{font-size:13px;color:var(--muted)}
.queue{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.queue:not(:empty){margin-top:16px}
.q-item{display:flex;align-items:center;gap:12px;padding:10px;border:1px solid var(--border);border-radius:12px;background:var(--surface)}
.q-item img{width:46px;height:46px;border-radius:8px;object-fit:cover;flex:none}
.q-body{flex:1;min-width:0}
.q-name{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.q-meta{font-size:12.5px;color:var(--muted)}
.q-item[data-state="done"] .q-meta{color:var(--success)}
.q-item[data-state="error"] .q-meta{color:var(--danger)}
.bar{height:4px;border-radius:4px;background:var(--surface-2);margin-top:6px;overflow:hidden}
.bar>i{display:block;height:100%;width:0;background:var(--brand);transition:width .2s}
.q-item[data-state="done"] .bar>i{background:var(--success)}
.q-item[data-state="error"] .bar>i{background:var(--danger);width:100%}
.queue-actions{display:flex;align-items:center;gap:10px;margin-top:14px}

/* ===================== Toolbar ===================== */
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-bottom:16px}
.section-title{font-size:18px;font-weight:700;letter-spacing:-.01em;display:flex;align-items:center;gap:8px}
.badge{font-size:12px;font-weight:700;padding:2px 9px;border-radius:999px;background:var(--brand-soft);color:var(--brand)}
.search{position:relative}
.search .icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--muted);width:16px;height:16px}
.search input,.select select{height:40px;border:1px solid var(--border);background:var(--surface);border-radius:var(--radius-sm);padding:0 12px;outline:none}
.search input{padding-left:36px;width:240px}
.select select{padding-right:8px}
.search input:focus,.select select:focus{border-color:var(--brand);box-shadow:0 0 0 3px color-mix(in srgb,var(--brand) 25%,transparent)}
.segmented.compact{display:inline-flex;padding:3px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface)}
.segmented.compact button{width:34px;height:32px;display:grid;place-items:center;border:0;border-radius:8px;background:transparent;color:var(--muted)}
.segmented.compact button[aria-pressed="true"]{background:var(--brand-soft);color:var(--brand)}

/* ===================== Gallery ===================== */
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
.photo{position:relative;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow-sm);transition:transform .18s,box-shadow .18s}
.photo:hover{transform:translateY(-3px);box-shadow:var(--shadow)}
.photo.removing{opacity:0;transform:scale(.94);transition:all .25s}
.photo-media{position:relative;display:block;width:100%;aspect-ratio:4/3;padding:0;border:0;background:var(--surface-2);overflow:hidden}
.photo-media img{width:100%;height:100%;object-fit:cover;opacity:0;transition:opacity .35s,transform .35s}
.photo.loaded .photo-media img{opacity:1}
.photo:hover .photo-media img{transform:scale(1.04)}
.skeleton{position:absolute;inset:0;background:linear-gradient(90deg,var(--surface-2),var(--border),var(--surface-2));background-size:200% 100%;animation:shimmer 1.3s infinite linear}
.photo.loaded .skeleton{display:none}
.broken-msg{display:none;position:absolute;inset:0;place-items:center;padding:12px;text-align:center;font-size:13px;color:var(--muted)}
.photo.broken .broken-msg{display:grid}
.photo.broken .photo-media img{display:none}
.photo-info{padding:12px 14px 14px}
.photo-name{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.photo-meta{display:flex;align-items:center;gap:7px;font-size:12.5px;color:var(--muted);margin-top:2px}
.photo-actions{position:absolute;top:10px;right:10px;display:flex;gap:6px;opacity:0;transform:translateY(-4px);transition:opacity .15s,transform .15s}
.photo:hover .photo-actions,.photo:focus-within .photo-actions{opacity:1;transform:none}
.photo-actions .btn-icon{background:color-mix(in srgb,var(--surface) 92%,transparent);backdrop-filter:blur(6px);box-shadow:var(--shadow-sm);color:var(--text)}
@media (hover:none){.photo-actions{opacity:1;transform:none}}
/* list layout */
.gallery.view-list{grid-template-columns:1fr;gap:10px}
.view-list .photo{display:grid;grid-template-columns:110px 1fr auto;align-items:center;gap:6px}
.view-list .photo:hover{transform:none}
.view-list .photo-media{aspect-ratio:auto;height:76px}
.view-list .photo-info{padding:8px 12px}
.view-list .photo-actions{position:static;opacity:1;transform:none;padding-right:12px}
.view-list .photo-actions .btn-icon{background:transparent;box-shadow:none;backdrop-filter:none}

.empty{text-align:center;padding:56px 16px;background:var(--surface);border:1px dashed var(--border);border-radius:var(--radius)}
.empty-art{width:64px;height:64px;margin:0 auto 14px;border-radius:20px;display:grid;place-items:center;background:var(--brand-soft);color:var(--brand)}
.empty-art .icon{width:30px;height:30px}
.empty h3{font-size:17px;margin-bottom:4px}
.foot{display:flex;flex-wrap:wrap;gap:10px;justify-content:center;align-items:center;margin-top:40px;font-size:12.5px;color:var(--muted)}

/* ===================== Lightbox ===================== */
.lightbox{position:fixed;inset:0;z-index:50;background:rgba(6,9,20,.94);display:grid;grid-template-rows:auto 1fr;animation:fade .15s}
.lb-top{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 18px;color:#fff;z-index:2}
.lb-title{display:flex;flex-direction:column;min-width:0}
.lb-title span{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lb-title small{color:#aab3d1;font-size:12.5px}
.lb-tools{display:flex;gap:8px}
.lb-btn,.lb-nav{width:42px;height:42px;display:grid;place-items:center;border-radius:50%;border:0;background:rgba(255,255,255,.12);color:#fff;transition:background .15s}
.lb-btn:hover,.lb-nav:hover{background:rgba(255,255,255,.24)}
.lb-stage{margin:0;display:grid;place-items:center;padding:0 72px 56px;min-height:0}
.lb-stage img{max-width:100%;max-height:calc(100vh - 150px);object-fit:contain;border-radius:8px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.lb-nav{position:absolute;top:50%;transform:translateY(-50%)}
.lb-nav.prev{left:16px}.lb-nav.next{right:16px}
.lb-count{position:absolute;bottom:18px;left:50%;transform:translateX(-50%);color:#c3cae6;font-size:13px;background:rgba(255,255,255,.1);padding:4px 12px;border-radius:999px}

/* ===================== Dialogs ===================== */
dialog.modal{border:0;padding:0;border-radius:18px;background:var(--surface);color:var(--text);width:min(480px,calc(100vw - 32px));box-shadow:var(--shadow)}
dialog.modal::backdrop{background:rgba(8,12,28,.55);backdrop-filter:blur(3px)}
dialog.modal[open]{animation:pop .18s ease-out}
.modal-inner{padding:22px}
.modal-head{display:flex;justify-content:space-between;align-items:center}
.modal-head h3,.modal-inner>h3{font-size:18px}
.modal-sub{margin:2px 0 16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
fieldset.segmented{border:0;margin:0 0 14px;padding:0;display:flex;gap:8px;flex-wrap:wrap}
fieldset.segmented legend{font-size:13px;font-weight:600;margin-bottom:8px;padding:0}
fieldset.segmented label{flex:1;min-width:90px;position:relative}
fieldset.segmented input{position:absolute;opacity:0}
fieldset.segmented span{display:block;text-align:center;padding:9px 10px;border:1px solid var(--border);border-radius:var(--radius-sm);font-size:13.5px;font-weight:600;color:var(--muted);cursor:pointer}
fieldset.segmented input:checked+span{background:var(--brand-soft);border-color:var(--brand);color:var(--brand)}
fieldset.segmented input:focus-visible+span{outline:2px solid var(--brand);outline-offset:2px}
.copy-field{display:flex;gap:8px}
.copy-field input{flex:1;min-width:0;height:40px;border:1px solid var(--border);background:var(--surface-2);border-radius:var(--radius-sm);padding:0 12px;font-size:13px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;text-overflow:ellipsis}
.hint{font-size:12.5px;color:var(--muted);margin:8px 0 14px;min-height:18px}
.notice{display:flex;gap:10px;align-items:flex-start;padding:12px;border-radius:var(--radius-sm);background:var(--brand-soft);color:var(--text);font-size:13px}
.notice .icon{color:var(--brand);margin-top:1px}
.del-ico{width:48px;height:48px;border-radius:50%;display:grid;place-items:center;background:var(--danger-soft);color:var(--danger);margin-bottom:12px}
#delName{font-weight:600;color:var(--text);margin:4px 0 8px;overflow-wrap:anywhere}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}

/* ===================== Toasts & alerts ===================== */
.toasts{position:fixed;right:20px;bottom:20px;z-index:100;display:grid;gap:10px;width:min(360px,calc(100vw - 40px))}
.toast{display:flex;align-items:flex-start;gap:10px;padding:12px 12px 12px 14px;background:var(--surface);border:1px solid var(--border);border-left-width:4px;border-radius:12px;box-shadow:var(--shadow);font-size:14px;animation:slide .22s ease-out}
.toast.out{opacity:0;transform:translateX(20px);transition:all .2s}
.toast>span{flex:1}
.toast.success{border-left-color:var(--success)}.toast.success>.icon{color:var(--success)}
.toast.error{border-left-color:var(--danger)}.toast.error>.icon{color:var(--danger)}
.toast.info{border-left-color:var(--brand)}.toast.info>.icon{color:var(--brand)}
.toast-x{border:0;background:none;color:var(--muted);padding:0;display:grid}
.alert{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:var(--radius-sm);font-size:14px;margin-bottom:16px}
.alert.error{background:var(--danger-soft);color:var(--danger)}

/* ===================== Login ===================== */
.auth{min-height:100vh;display:grid;grid-template-columns:1.05fr 1fr}
.auth-aside{position:relative;overflow:hidden;color:#fff;padding:48px 56px;display:flex;flex-direction:column;justify-content:space-between;background:linear-gradient(150deg,#312e81 0%,#4f46e5 55%,#7c3aed 100%)}
.auth-aside::before,.auth-aside::after{content:"";position:absolute;border-radius:50%;background:rgba(255,255,255,.08)}
.auth-aside::before{width:420px;height:420px;right:-140px;top:-120px}
.auth-aside::after{width:320px;height:320px;left:-100px;bottom:-110px}
.auth-aside>*{position:relative;z-index:1}
.brand.light .brand-mark{background:rgba(255,255,255,.18);box-shadow:none}
.aside-copy h1{font-size:40px;line-height:1.12;letter-spacing:-.03em;margin-bottom:14px}
.aside-copy>p{color:#dcdcff;max-width:430px;font-size:16px}
.feature-list{list-style:none;padding:0;margin:30px 0 0;display:grid;gap:16px;max-width:440px}
.feature-list li{display:flex;gap:12px;align-items:flex-start;color:#e8e8ff;font-size:14.5px}
.feature-list .icon{width:36px;height:36px;padding:8px;border-radius:10px;background:rgba(255,255,255,.16)}
.feature-list b{color:#fff}
.aside-foot{font-size:13px;color:#c9c9f5}
.auth-main{display:grid;place-items:center;padding:32px}
.auth-card{width:min(400px,100%)}
.auth-card h2{font-size:28px;letter-spacing:-.02em}
.auth-card>.muted{margin:4px 0 24px}
.field{margin-bottom:16px}
.field label{display:block;font-weight:600;font-size:13.5px;margin-bottom:6px}
.input-wrap{position:relative}
.input-wrap input{width:100%;height:46px;padding:0 44px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);outline:none;transition:border-color .15s,box-shadow .15s}
.input-wrap input:focus{border-color:var(--brand);box-shadow:0 0 0 3px color-mix(in srgb,var(--brand) 25%,transparent)}
.input-wrap .lead{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--muted);width:17px;height:17px}
.reveal{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:34px;height:34px;display:grid;place-items:center;border:0;background:none;border-radius:8px;color:var(--muted)}
.reveal:hover{color:var(--text);background:var(--surface-2)}
.auth-note{display:flex;gap:8px;align-items:center;justify-content:center;margin-top:18px;font-size:12.5px;color:var(--muted)}
.auth-note .icon{width:14px;height:14px}

/* ===================== Animation & responsive ===================== */
@keyframes shimmer{to{background-position:-200% 0}}
@keyframes fade{from{opacity:0}}
@keyframes pop{from{opacity:0;transform:translateY(8px) scale(.98)}}
@keyframes slide{from{opacity:0;transform:translateX(24px)}}
@media (max-width:980px){.stats{grid-template-columns:repeat(2,1fr)}}
@media (max-width:900px){.auth{grid-template-columns:1fr}.auth-aside{display:none}}
@media (max-width:640px){
  .container{padding:20px 16px 40px}.topbar-in{padding:10px 16px}
  .user-name,.chip,.brand small{display:none}
  .stats{gap:10px}.stat{padding:12px;gap:10px}.stat-ico{width:36px;height:36px}.stat-value{font-size:18px}
  .toolbar .search,.search input{width:100%}.toolbar .search{flex:1 1 100%;order:3}
  .gallery{grid-template-columns:repeat(2,1fr);gap:10px}
  .lb-stage{padding:0 12px 56px}.lb-nav{display:none}
  .view-list .photo{grid-template-columns:84px 1fr auto}
  .toasts{right:50%;transform:translateX(50%)}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}

/* ===================== Account pages ===================== */
.auth-switch{margin-top:18px;text-align:center;font-size:14px;color:var(--muted)}
.auth-switch a{color:var(--brand);font-weight:600;text-decoration:none}
.auth-switch a:hover{text-decoration:underline}
.hint-text{margin:6px 0 0;font-size:12.5px;color:var(--muted)}
GALLERY_EOF

cat > /opt/gallery/static/v3.css <<'GALLERY_EOF'
/* PixelVault v3 layout: sidebar, timeline, selection, albums, trash, dialogs. Loaded after style.css. */
.brand-mark{background:none;box-shadow:none;width:36px;height:36px}.brand-mark img{width:36px;height:36px;border-radius:10px;display:block}
.brand{color:inherit;text-decoration:none}
.topbar-in.wide{max-width:none;padding:10px 20px}
.search.grow{flex:1;max-width:560px;margin:0 auto 0 12px}
.menu-btn{display:none}
.shell{display:grid;grid-template-columns:250px 1fr;min-height:calc(100vh - 62px)}
.side{position:sticky;top:62px;align-self:start;height:calc(100vh - 62px);overflow:auto;padding:18px 12px;border-right:1px solid var(--border);display:flex;flex-direction:column;gap:6px;background:var(--surface)}
.nav{display:flex;flex-direction:column;gap:2px}
.nav a{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:999px;color:var(--text);text-decoration:none;font-weight:500}
.nav a span{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nav a b{font-weight:500;font-size:12.5px;color:var(--muted)}
.nav a:hover{background:var(--surface-2)}
.nav a.active{background:var(--brand-soft);color:var(--brand);font-weight:600}.nav a.active b{color:var(--brand)}
.side-sec{display:flex;align-items:center;justify-content:space-between;margin-top:14px;padding:0 6px 0 12px;font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.side-empty{padding:4px 12px}
.usage{margin-top:auto;padding:14px 12px 4px;border-top:1px solid var(--border);display:grid;gap:8px}
.usage-row{display:flex;justify-content:space-between;gap:8px;font-size:13.5px}
.meter{height:6px;border-radius:99px;background:var(--surface-2);overflow:hidden}.meter i{display:block;height:100%;width:0;background:linear-gradient(90deg,#6366f1,#8b5cf6);border-radius:99px;transition:width .4s}
.meter.warn i{background:var(--danger)}
.content{padding:22px 28px 56px;min-width:0}
.view-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.view-head h1{font-size:24px;letter-spacing:-.02em}
.selbar{position:sticky;top:70px;z-index:15;display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:8px 12px;margin-bottom:14px;border-radius:14px;background:var(--brand-soft);border:1px solid var(--border);box-shadow:var(--shadow-sm)}
.group{margin-bottom:22px}
.group-head{display:flex;align-items:center;gap:10px;margin:0 0 8px;font-weight:600;font-size:14.5px}
.group-check,.tile-check{width:24px;height:24px;border-radius:50%;display:grid;place-items:center;padding:0;border:2px solid #fff;background:rgba(15,23,42,.35);color:#fff;opacity:0;transition:opacity .12s,background .12s}
.group-check{border-color:var(--muted);background:transparent;color:transparent}
.group-check .icon,.tile-check .icon{width:14px;height:14px;stroke-width:3}
.group-head:hover .group-check,.selecting .group-check{opacity:1}
.group-check.on{background:var(--brand);border-color:var(--brand);color:#fff;opacity:1}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:6px}
.tile{position:relative;aspect-ratio:1;border-radius:10px;overflow:hidden;background:var(--surface-2)}
.tile-open{position:absolute;inset:0;width:100%;height:100%;padding:0;border:0;background:none;overflow:hidden;transition:transform .15s}
.tile-open img{width:100%;height:100%;object-fit:cover;opacity:0;transition:opacity .3s}
.tile.loaded img{opacity:1}.tile.loaded .skeleton{display:none}.tile.broken img{display:none}
.tile:hover .tile-open img{transform:scale(1.03)}
.tile-check{position:absolute;top:8px;left:8px}
.tile:hover .tile-check,.selecting .tile-check,.tile.sel .tile-check{opacity:1}
.tile.sel .tile-check{background:var(--brand);border-color:#fff}
.tile.sel .tile-open{transform:scale(.86);border-radius:10px}.tile.sel{background:var(--brand-soft)}
.tile-fav{position:absolute;bottom:8px;left:8px;color:#fbbf24;filter:drop-shadow(0 1px 2px rgba(0,0,0,.6))}.tile-fav .icon{fill:currentColor;width:16px;height:16px}
@media (hover:none){.tile-check{opacity:1}}
.lb-btn.on{color:#fbbf24}.lb-btn.on .icon{fill:currentColor}
.lb-btn[hidden],.lb-nav[hidden]{display:none}
.toast-act{border:0;background:none;color:var(--brand);font-weight:700;padding:0 6px}
.drop-overlay{position:fixed;inset:0;z-index:60;display:grid;place-items:center;background:color-mix(in srgb,var(--brand) 22%,transparent);backdrop-filter:blur(3px);pointer-events:none}
.drop-overlay div{display:flex;gap:12px;align-items:center;padding:22px 34px;border-radius:18px;background:var(--surface);box-shadow:var(--shadow);font-weight:700;font-size:18px;color:var(--brand)}
dialog.modal{max-height:calc(100vh - 48px);overflow-x:hidden;overflow-y:auto}
dialog.modal.wide{width:min(680px,calc(100vw - 32px))}
.modal.wide .modal-inner{min-width:0}
.modal.wide .dropzone{padding:52px 24px}
.modal.wide .queue{max-height:300px;overflow-y:auto}
.logout-ico{background:var(--brand-soft);color:var(--brand)}
.logout-btn{gap:8px}
.text-input{flex:1;min-width:0;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:var(--surface);width:100%}
.subhead{margin:14px 0 6px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.links,.pick-list{list-style:none;margin:0;padding:0;display:grid;gap:6px;max-height:220px;overflow:auto}
.links li{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:8px 10px;border:1px solid var(--border);border-radius:10px;font-size:13.5px}
.row{display:flex;gap:6px}.btn.sm{padding:5px 10px;font-size:13px}.danger-text{color:var(--danger)}
.pick{display:flex;align-items:center;gap:10px;width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:var(--surface);text-align:left}
.pick span{flex:1}.pick:hover{border-color:var(--brand);background:var(--brand-soft)}.pad{padding:8px}
.q-item[data-state="dup"] .q-meta{color:var(--muted)}.q-item[data-state="dup"] .bar>i{background:var(--muted);width:100%}
.modal-inner .copy-field{margin-top:12px}
@media (max-width:860px){
  .shell{grid-template-columns:1fr}.menu-btn{display:grid}
  .side{position:fixed;z-index:40;top:62px;left:0;bottom:0;width:260px;height:auto;transform:translateX(-102%);transition:transform .2s;box-shadow:var(--shadow)}
  .side.open{transform:none}
  .content{padding:16px 12px 40px}.grid{grid-template-columns:repeat(3,1fr);gap:3px}.hide-sm{display:none}
  .search.grow{margin:0}.topbar-in.wide{gap:8px;padding:8px 12px}.brand span:last-child{display:none}
}
GALLERY_EOF

cat > /opt/gallery/static/theme.js <<'GALLERY_EOF'
(function () {
  try {
    var t = localStorage.getItem("theme");
    if (!t) t = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage unavailable: stay on light theme */ }
})();
GALLERY_EOF

cat > /opt/gallery/static/login.js <<'GALLERY_EOF'
(() => {
  "use strict";
  const pwd = document.getElementById("password");
  const btn = document.getElementById("reveal");
  const form = document.querySelector("form.auth-card");
  btn.addEventListener("click", () => {
    const show = pwd.type === "password";
    pwd.type = show ? "text" : "password";
    btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
    btn.querySelector("use").setAttribute("href", show ? "#i-eye-off" : "#i-eye");
  });
  form.addEventListener("submit", () => {
    const b = document.getElementById("loginBtn");
    b.disabled = true; b.textContent = "Signing in…";
  });
})();
GALLERY_EOF

cat > /opt/gallery/static/logo.svg <<'GALLERY_EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="PixelVault">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6366f1"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs>
  <rect width="64" height="64" rx="16" fill="url(#g)"/>
    <rect x="13" y="13" width="10" height="10" rx="2.5" fill="#fff" fill-opacity="1"/>
  <rect x="27" y="13" width="10" height="10" rx="2.5" fill="#fff" fill-opacity="0.55"/>
  <rect x="41" y="13" width="10" height="10" rx="2.5" fill="#fff" fill-opacity="0.85"/>
  <rect x="13" y="27" width="10" height="10" rx="2.5" fill="#fff" fill-opacity="0.7"/>
  <rect x="41" y="27" width="10" height="10" rx="2.5" fill="#fff" fill-opacity="0.55"/>
  <rect x="13" y="41" width="10" height="10" rx="2.5" fill="#fff" fill-opacity="0.85"/>
  <rect x="27" y="41" width="10" height="10" rx="2.5" fill="#fff" fill-opacity="0.6"/>
  <rect x="41" y="41" width="10" height="10" rx="2.5" fill="#fff" fill-opacity="1"/>
  <rect x="27" y="27" width="10" height="10" rx="2.5" fill="#fff"/>
  <circle cx="32" cy="31" r="2.2" fill="#4f46e5"/><rect x="31.1" y="31.5" width="1.8" height="3.6" rx=".6" fill="#4f46e5"/>
</svg>
GALLERY_EOF


/opt/gallery/venv/bin/pip install -q -r /opt/gallery/requirements.txt
setenv() { sudo sed -i "/^$1=/d" /etc/gallery.env; echo "$1=$2" | sudo tee -a /etc/gallery.env >/dev/null; }
setenv DDB_TABLE "$TABLE"
if [ -n "${CDN_DOMAIN:-}" ] && [ -n "${CDN_KEY_PAIR_ID:-}" ]; then setenv CDN_DOMAIN "$CDN_DOMAIN"; setenv CDN_KEY_PAIR_ID "$CDN_KEY_PAIR_ID"; fi

echo "Copying existing users, photos and albums into DynamoDB (safe to repeat)..."
if [ -f /var/lib/gallery/gallery.db ]; then
  ( cd /opt/gallery && set -a && source <(sudo cat /etc/gallery.env) && set +a && venv/bin/flask --app app migrate-sqlite )
fi
sudo systemctl daemon-reload
sudo systemctl restart gallery
sleep 4
sudo systemctl is-active gallery
curl -4 -s http://127.0.0.1/health; echo
( cd /opt/gallery && set -a && source <(sudo cat /etc/gallery.env) && set +a && venv/bin/flask --app app backfill ) || true
echo "PixelVault v4 is live. Hard-refresh the page (Ctrl+Shift+R)."
echo "Rollback: cp /opt/gallery/app.py.v3.$STAMP.bak /opt/gallery/app.py && sudo systemctl restart gallery"
