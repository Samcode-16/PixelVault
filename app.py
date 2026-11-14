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
