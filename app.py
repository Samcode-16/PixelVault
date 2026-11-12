"""
PixelVault - multi-user Secure Image Gallery (Flask + SQLite + Amazon S3)
-------------------------------------------------------------------------
* Users register and sign in with their own account; passwords are stored only as salted hashes.
* Every image lives under  images/<user-id>/  in the private bucket, and every request is checked
  against the signed-in user's own rows, so one user can never list, share or delete another's images.
* AWS credentials still come from the EC2 instance role (no access keys anywhere).
"""
import hmac
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
from PIL import Image, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------- config ----
BUCKET = os.environ["S3_BUCKET"]
REGION = os.environ.get("AWS_REGION", "ap-south-2")
PREFIX = "images/"                       # keeps the existing GalleryEC2S3Access policy valid
DB_PATH = os.environ.get("DB_PATH", "/var/lib/gallery/gallery.db")
VIEW_URL_TTL = int(os.environ.get("VIEW_URL_TTL", 900))
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 5))
MAX_IMAGES = int(os.environ.get("MAX_IMAGES_PER_USER", 50))
MAX_STORAGE_MB = int(os.environ.get("MAX_STORAGE_MB_PER_USER", 100))
REGISTRATION_OPEN = os.environ.get("REGISTRATION_OPEN", "true").lower() == "true"
INVITE_CODE = os.environ.get("INVITE_CODE", "")
ADMIN_USER = os.environ.get("APP_USERNAME", "admin")
ADMIN_PASS = os.environ.get("APP_PASSWORD", "")          # optional: seeds the first account
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
MAX_FAILS, LOCKOUT_SECONDS = 5, 300

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

# --------------------------------------------------------------- database ----
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pw_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS images (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  s3_key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_images_user ON images(user_id, created_at DESC);
"""


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.executescript(SCHEMA)
    if ADMIN_PASS and not con.execute("SELECT 1 FROM users WHERE username = ?", (ADMIN_USER,)).fetchone():
        try:
            con.execute("INSERT INTO users (id, username, pw_hash, created_at) VALUES (?, ?, ?, ?)",
                        (uuid.uuid4().hex, ADMIN_USER, generate_password_hash(ADMIN_PASS), int(time.time())))
        except sqlite3.IntegrityError:
            pass                                          # another worker seeded it first
    con.commit()
    con.close()


init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


# -------------------------------------------------------------- security ----
def _eq(a, b):
    return hmac.compare_digest(a.encode(), b.encode())


DUMMY_HASH = generate_password_hash(secrets.token_hex(16))   # equalises timing for unknown usernames


def require_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        uid = session.get("uid")
        row = db().execute("SELECT id, username FROM users WHERE id = ?", (uid,)).fetchone() if uid else None
        if row is None:
            session.pop("uid", None)
            if request.method == "POST":
                return jsonify(ok=False, error="Session expired. Please sign in again."), 401
            return redirect(url_for("login"))
        g.user = row
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
        "default-src 'self'; img-src 'self' data: blob: https://*.amazonaws.com; "
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


def detect_image_format(file_storage):
    name = file_storage.filename or ""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT:
        return None
    try:
        with Image.open(file_storage.stream) as img:
            fmt = img.format
            img.verify()
    except (UnidentifiedImageError, OSError, SyntaxError):
        return None
    finally:
        file_storage.stream.seek(0)
    return fmt if fmt in FORMAT_MIME else None


def presign(key, ttl):
    return s3.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": key}, ExpiresIn=ttl)


def own_image(image_id):
    """Return the image row only if it belongs to the signed-in user."""
    if not isinstance(image_id, str):
        return None
    return db().execute("SELECT * FROM images WHERE id = ? AND user_id = ?",
                        (image_id, g.user["id"])).fetchone()


def start_session(user_id):
    session.clear()                                    # new session on every login/registration
    session["csrf"] = secrets.token_hex(16)
    session["uid"] = user_id
    session.permanent = True


# ---------------------------------------------------------------- routes ----
@app.route("/health")
def health():
    return jsonify(status="ok", time=datetime.now(timezone.utc).isoformat())


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
            try:
                db().execute("INSERT INTO users (id, username, pw_hash, created_at) VALUES (?, ?, ?, ?)",
                             (uid, username, generate_password_hash(pwd), int(time.time())))
                db().commit()
            except sqlite3.IntegrityError:
                error = "That username is already taken."
            else:
                log.info("Registered user %s", username)
                start_session(uid)
                return redirect(url_for("index"))
    return render_template("register.html", closed=False, error=error, username=username,
                           needs_invite=bool(INVITE_CODE)), (400 if error else 200)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("uid"):
        return redirect(url_for("index"))
    error, status = None, 200
    if request.method == "POST":
        username, pwd = request.form.get("username", "").strip(), request.form.get("password", "")
        row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        now = int(time.time())
        if row and row["locked_until"] > now:
            error, status = f"Too many failed attempts. Try again in {row['locked_until'] - now} seconds.", 429
        else:
            ok = check_password_hash(row["pw_hash"] if row else DUMMY_HASH, pwd) and row is not None
            if ok:
                db().execute("UPDATE users SET failed_count = 0, locked_until = 0 WHERE id = ?", (row["id"],))
                db().commit()
                log.info("Login success for %s", username)
                start_session(row["id"])
                return redirect(url_for("index"))
            if row:
                fails = row["failed_count"] + 1
                locked = now + LOCKOUT_SECONDS if fails >= MAX_FAILS else 0
                db().execute("UPDATE users SET failed_count = ?, locked_until = ? WHERE id = ?",
                             (0 if locked else fails, locked, row["id"]))
                db().commit()
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
    uid = g.user["id"]
    rows = db().execute("SELECT * FROM images WHERE user_id = ? ORDER BY created_at DESC", (uid,)).fetchall()
    images, load_error = [], None
    try:
        for r in rows:
            images.append({
                "id": r["id"], "name": r["name"], "size": r["size"], "size_label": human_size(r["size"]),
                "ts": r["created_at"], "date_label": datetime.fromtimestamp(r["created_at"], timezone.utc).strftime("%d %b %Y"),
                "url": presign(r["s3_key"], VIEW_URL_TTL)})
    except (ClientError, BotoCoreError):
        log.exception("Could not build image links")
        images, load_error = [], "We couldn't load your images. Check the instance role and bucket settings."
    return render_template(
        "index.html", images=images, load_error=load_error, bucket=BUCKET, region=REGION, max_mb=MAX_UPLOAD_MB,
        ttl_min=VIEW_URL_TTL // 60, total_size=human_size(sum(r["size"] for r in rows)),
        user=g.user["username"], max_images=MAX_IMAGES, quota_mb=MAX_STORAGE_MB)


@app.route("/upload", methods=["POST"])
@require_auth
def upload():
    f = request.files.get("image")
    if not f or not f.filename:
        return jsonify(ok=False, error="No file received."), 400
    fmt = detect_image_format(f)
    if not fmt:
        return jsonify(ok=False, error="Not a valid PNG, JPG, GIF or WEBP image."), 400
    f.stream.seek(0, 2); size = f.stream.tell(); f.stream.seek(0)

    uid = g.user["id"]
    used = db().execute("SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS b FROM images WHERE user_id = ?",
                        (uid,)).fetchone()
    if used["n"] >= MAX_IMAGES:
        return jsonify(ok=False, error=f"Image limit reached ({MAX_IMAGES}). Delete some images first."), 403
    if used["b"] + size > MAX_STORAGE_MB * 1024 * 1024:
        return jsonify(ok=False, error=f"Storage limit reached ({MAX_STORAGE_MB} MB)."), 403

    ext = f.filename.rsplit(".", 1)[-1].lower()
    name = secure_filename(f.filename)
    if not name.lower().endswith("." + ext):
        name = f"image.{ext}"
    image_id = uuid.uuid4().hex
    key = f"{PREFIX}{uid}/{image_id}-{name}"            # the user id comes from the session, never the client
    try:
        s3.upload_fileobj(f.stream, BUCKET, key,
                          ExtraArgs={"ContentType": FORMAT_MIME[fmt], "ServerSideEncryption": "AES256"})
    except (ClientError, BotoCoreError):
        log.exception("Upload failed for %s", key)
        return jsonify(ok=False, error="Storage error. Please try again."), 502
    try:
        db().execute("INSERT INTO images (id, user_id, s3_key, name, size, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                     (image_id, uid, key, name, size, int(time.time())))
        db().commit()
    except sqlite3.Error:
        log.exception("Database insert failed; removing %s", key)
        try:
            s3.delete_object(Bucket=BUCKET, Key=key)
        except (ClientError, BotoCoreError):
            pass
        return jsonify(ok=False, error="Could not save the image record."), 500
    log.info("Uploaded %s", key)
    return jsonify(ok=True, name=name, id=image_id)


@app.route("/delete", methods=["POST"])
@require_auth
def delete():
    row = own_image((request.get_json(silent=True) or {}).get("id"))
    if row is None:
        return jsonify(ok=False, error="Image not found."), 404
    try:
        s3.delete_object(Bucket=BUCKET, Key=row["s3_key"])    # versioning on: adds a delete marker
    except (ClientError, BotoCoreError):
        log.exception("Delete failed for %s", row["s3_key"])
        return jsonify(ok=False, error="Could not delete the image."), 502
    db().execute("DELETE FROM images WHERE id = ?", (row["id"],))
    db().commit()
    log.info("Deleted %s", row["s3_key"])
    return jsonify(ok=True)


@app.route("/share", methods=["POST"])
@require_auth
def share():
    data = request.get_json(silent=True) or {}
    row = own_image(data.get("id"))
    if row is None:
        return jsonify(ok=False, error="Image not found."), 404
    try:
        minutes = max(1, min(int(data.get("minutes", 60)), 360))
    except (TypeError, ValueError):
        minutes = 60
    try:
        return jsonify(ok=True, url=presign(row["s3_key"], minutes * 60), expires_in_minutes=minutes)
    except (ClientError, BotoCoreError):
        log.exception("Presign failed for %s", row["s3_key"])
        return jsonify(ok=False, error="Could not generate a link."), 502


@app.errorhandler(413)
def too_large(_):
    return jsonify(ok=False, error=f"File too large (max {MAX_UPLOAD_MB} MB)."), 413


# --------------------------------------------------- one-off migration CLI ----
@app.cli.command("adopt-legacy")
@click.argument("username")
def adopt_legacy(username):
    """Move images uploaded by the old single-user version (images/<name>) into USERNAME's folder."""
    user = db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        raise click.ClickException(f"No such user: {username}")
    moved = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix=PREFIX):
        for obj in page.get("Contents", []):
            rest = obj["Key"][len(PREFIX):]
            if not rest or "/" in rest or rest.rsplit(".", 1)[-1].lower() not in ALLOWED_EXT:
                continue
            new_key = f"{PREFIX}{user['id']}/{rest}"
            s3.copy_object(Bucket=BUCKET, Key=new_key, CopySource={"Bucket": BUCKET, "Key": obj["Key"]},
                           ServerSideEncryption="AES256")
            s3.delete_object(Bucket=BUCKET, Key=obj["Key"])
            db().execute("INSERT OR IGNORE INTO images (id, user_id, s3_key, name, size, created_at) "
                         "VALUES (?, ?, ?, ?, ?, ?)",
                         (uuid.uuid4().hex, user["id"], new_key, rest.split("-", 1)[-1], obj["Size"],
                          int(obj["LastModified"].timestamp())))
            moved += 1
    db().commit()
    click.echo(f"Moved {moved} image(s) to {username}.")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
