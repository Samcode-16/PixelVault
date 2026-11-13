#!/bin/bash
# PixelVault multi-user upgrade. Run on the EC2 instance as ec2-user:
INVITE_CODE='pixelvaultsignin' bash upgrade.sh        (INVITE_CODE is optional; omit for open sign-up)
set -euo pipefail

sudo cp -n /opt/gallery/app.py /opt/gallery/app.py.single-user.bak 2>/dev/null || true
sudo mkdir -p /opt/gallery/templates /opt/gallery/static /var/lib/gallery
sudo chown -R ec2-user:ec2-user /opt/gallery /var/lib/gallery
chmod 700 /var/lib/gallery
cat > /opt/gallery/app.py <<'GALLERY_EOF'
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
GALLERY_EOF
cat > /opt/gallery/templates/login.html <<'GALLERY_EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · PixelVault</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%234f46e5'/%3E%3C/svg%3E">
  <script src="{{ url_for('static', filename='theme.js') }}"></script>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
{% include "_icons.html" %}
<main class="auth">
  <aside class="auth-aside">
    <div class="brand light">
      <span class="brand-mark"><svg class="icon"><use href="#i-layers"/></svg></span>
      <span>PixelVault</span>
    </div>
    <div class="aside-copy">
      <h1>Your images,<br>privately stored.</h1>
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
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%234f46e5'/%3E%3C/svg%3E">
  <script src="{{ url_for('static', filename='theme.js') }}"></script>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
{% include "_icons.html" %}
<main class="auth">
  <aside class="auth-aside">
    <div class="brand light">
      <span class="brand-mark"><svg class="icon"><use href="#i-layers"/></svg></span>
      <span>PixelVault</span>
    </div>
    <div class="aside-copy">
      <h1>Your images,<br>privately stored.</h1>
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
  <title>PixelVault · Secure Image Gallery</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%234f46e5'/%3E%3C/svg%3E">
  <script src="{{ url_for('static', filename='theme.js') }}"></script>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
{% include "_icons.html" %}

<header class="topbar">
  <div class="topbar-in">
    <div class="brand">
      <span class="brand-mark"><svg class="icon"><use href="#i-layers"/></svg></span>
      <span>PixelVault<small>Secure Image Gallery</small></span>
    </div>
    <div class="spacer"></div>
    <span class="chip chip-ok" title="Block Public Access is ON for this bucket"><svg class="icon"><use href="#i-lock"/></svg>Private bucket</span>
    <button class="btn-icon" id="themeToggle" type="button" aria-label="Toggle dark mode">
      <svg class="icon i-sun"><use href="#i-sun"/></svg><svg class="icon i-moon"><use href="#i-moon"/></svg>
    </button>
    <span class="user-chip"><span class="avatar">{{ user[:1]|upper }}</span><span class="user-name">{{ user }}</span></span>
    <form method="post" action="{{ url_for('logout') }}">
      <input type="hidden" name="csrf" value="{{ csrf_token }}">
      <button class="btn-icon" type="submit" aria-label="Sign out" title="Sign out"><svg class="icon"><use href="#i-logout"/></svg></button>
    </form>
  </div>
</header>

<main class="container">
  <div class="page-head">
    <h1>Your library</h1>
    <p class="muted">Images are stored privately in Amazon S3 and delivered through time-limited links.</p>
  </div>

  {% if load_error %}
  <div class="alert error" role="alert"><svg class="icon"><use href="#i-alert"/></svg><span>{{ load_error }}</span></div>
  {% endif %}

  <section class="stats" aria-label="Library summary">
    <div class="stat"><span class="stat-ico"><svg class="icon"><use href="#i-image"/></svg></span>
      <div><div class="stat-label">Images</div><div class="stat-value" id="statCount">{{ images|length }}</div><div class="stat-sub">of {{ max_images }} allowed</div></div></div>
    <div class="stat"><span class="stat-ico"><svg class="icon"><use href="#i-database"/></svg></span>
      <div><div class="stat-label">Storage used</div><div class="stat-value" id="statSize">{{ total_size }}</div><div class="stat-sub">of {{ quota_mb }} MB</div></div></div>
    <div class="stat"><span class="stat-ico ok"><svg class="icon"><use href="#i-shield"/></svg></span>
      <div><div class="stat-label">Protection</div><div class="stat-value sm">Versioned &middot; Encrypted</div><div class="stat-sub" title="{{ bucket }}">{{ bucket }}</div></div></div>
    <div class="stat"><span class="stat-ico"><svg class="icon"><use href="#i-clock"/></svg></span>
      <div><div class="stat-label">Link validity</div><div class="stat-value">{{ ttl_min }} min</div><div class="stat-sub">Pre-signed URLs</div></div></div>
  </section>

  <section class="panel" aria-labelledby="uploadTitle">
    <h2 id="uploadTitle" class="sr-only">Upload images</h2>
    <label class="dropzone" id="dropzone" for="fileInput">
      <span class="dz-ico"><svg class="icon"><use href="#i-upload"/></svg></span>
      <span class="dz-title">Drag &amp; drop images here, or <u>browse</u></span>
      <span class="dz-sub">PNG, JPG, GIF or WEBP &middot; up to {{ max_mb }} MB each</span>
      <input class="sr-only" id="fileInput" type="file" multiple accept="image/png,image/jpeg,image/gif,image/webp">
    </label>
    <ul class="queue" id="queue" aria-live="polite"></ul>
    <div class="queue-actions" id="queueActions" hidden>
      <span class="muted" id="uploadStatus"></span>
      <div class="spacer"></div>
      <button class="btn btn-ghost" id="clearBtn" type="button">Clear</button>
      <button class="btn btn-primary" id="uploadBtn" type="button"><svg class="icon"><use href="#i-upload"/></svg><span>Upload</span></button>
    </div>
  </section>

  <section class="toolbar" id="toolbar" aria-label="Gallery controls">
    <div class="section-title">Gallery <span class="badge" id="shownCount">{{ images|length }}</span></div>
    <div class="spacer"></div>
    <div class="search"><svg class="icon"><use href="#i-search"/></svg>
      <input id="search" type="search" placeholder="Search images…" aria-label="Search images" autocomplete="off"></div>
    <label class="select"><span class="sr-only">Sort by</span>
      <select id="sort">
        <option value="ts:desc">Newest first</option>
        <option value="ts:asc">Oldest first</option>
        <option value="name:asc">Name A–Z</option>
        <option value="name:desc">Name Z–A</option>
        <option value="size:desc">Largest first</option>
        <option value="size:asc">Smallest first</option>
      </select></label>
    <div class="segmented compact" role="group" aria-label="Layout">
      <button type="button" data-view="grid" aria-pressed="true" aria-label="Grid view"><svg class="icon"><use href="#i-grid"/></svg></button>
      <button type="button" data-view="list" aria-pressed="false" aria-label="List view"><svg class="icon"><use href="#i-list"/></svg></button>
    </div>
  </section>

  <div class="gallery" id="gallery">
    {% for img in images %}
    <article class="photo" data-id="{{ img.id }}" data-name="{{ img.name }}" data-size="{{ img.size }}" data-ts="{{ img.ts }}" data-url="{{ img.url }}">
      <button class="photo-media" type="button" data-action="open" aria-label="Open {{ img.name }}">
        <span class="skeleton"></span>
        <img src="{{ img.url }}" alt="{{ img.name }}" loading="lazy" decoding="async">
        <span class="broken-msg">Link expired &mdash; refresh the page</span>
      </button>
      <div class="photo-info">
        <div class="photo-name" title="{{ img.name }}">{{ img.name }}</div>
        <div class="photo-meta"><span>{{ img.size_label }}</span><span class="dot"></span><time class="js-ago" data-ts="{{ img.ts }}">{{ img.date_label }}</time></div>
      </div>
      <div class="photo-actions">
        <button class="btn-icon sm" type="button" data-action="share" aria-label="Share {{ img.name }}" title="Get shareable link"><svg class="icon"><use href="#i-link"/></svg></button>
        <button class="btn-icon sm danger" type="button" data-action="delete" aria-label="Delete {{ img.name }}" title="Delete"><svg class="icon"><use href="#i-trash"/></svg></button>
      </div>
    </article>
    {% endfor %}
  </div>

  <div class="empty" id="emptyState" {% if images %}hidden{% endif %}>
    <div class="empty-art"><svg class="icon"><use href="#i-image"/></svg></div>
    <h3>No images yet</h3>
    <p class="muted">Drop your first image in the box above. It will be stored privately in S3.</p>
  </div>
  <div class="empty" id="noResults" hidden>
    <div class="empty-art"><svg class="icon"><use href="#i-search"/></svg></div>
    <h3>No matches</h3>
    <p class="muted">Try a different search term.</p>
  </div>

  <footer class="foot">
    <span>Region <b>{{ region }}</b></span><span class="dot"></span>
    <span>Access via IAM role &mdash; no stored credentials</span><span class="dot"></span>
    <span>Deletions are recoverable (versioning)</span>
  </footer>
</main>

<!-- Lightbox -->
<div class="lightbox" id="lightbox" hidden role="dialog" aria-modal="true" aria-label="Image viewer">
  <div class="lb-top">
    <div class="lb-title"><span id="lbName"></span><small id="lbMeta"></small></div>
    <div class="lb-tools">
      <button class="lb-btn" id="lbShare" type="button" aria-label="Get shareable link"><svg class="icon"><use href="#i-link"/></svg></button>
      <button class="lb-btn" id="lbDelete" type="button" aria-label="Delete image"><svg class="icon"><use href="#i-trash"/></svg></button>
      <button class="lb-btn" id="lbClose" type="button" aria-label="Close viewer"><svg class="icon"><use href="#i-x"/></svg></button>
    </div>
  </div>
  <button class="lb-nav prev" id="lbPrev" type="button" aria-label="Previous image"><svg class="icon"><use href="#i-left"/></svg></button>
  <figure class="lb-stage"><img id="lbImg" alt=""></figure>
  <button class="lb-nav next" id="lbNext" type="button" aria-label="Next image"><svg class="icon"><use href="#i-right"/></svg></button>
  <div class="lb-count" id="lbCount"></div>
</div>

<!-- Share dialog -->
<dialog class="modal" id="shareDialog" aria-labelledby="shareTitle">
  <div class="modal-inner">
    <header class="modal-head"><h3 id="shareTitle">Share image</h3>
      <button class="btn-icon sm" type="button" data-close aria-label="Close"><svg class="icon"><use href="#i-x"/></svg></button></header>
    <p class="muted modal-sub" id="shareName"></p>
    <fieldset class="segmented">
      <legend>Link expires after</legend>
      <label><input type="radio" name="minutes" value="5"><span>5 minutes</span></label>
      <label><input type="radio" name="minutes" value="60" checked><span>1 hour</span></label>
      <label><input type="radio" name="minutes" value="360"><span>6 hours</span></label>
    </fieldset>
    <div class="copy-field">
      <input id="shareUrl" type="text" readonly aria-label="Shareable URL">
      <button class="btn btn-primary" id="copyBtn" type="button"><svg class="icon"><use href="#i-copy"/></svg><span>Copy</span></button>
    </div>
    <p class="hint" id="shareHint"></p>
    <div class="notice"><svg class="icon"><use href="#i-shield"/></svg>
      <span>Anyone with this link can view the image until it expires. The bucket itself stays private.</span></div>
  </div>
</dialog>

<!-- Delete dialog -->
<dialog class="modal" id="deleteDialog" aria-labelledby="delTitle">
  <div class="modal-inner">
    <div class="del-ico"><svg class="icon"><use href="#i-trash"/></svg></div>
    <h3 id="delTitle">Delete this image?</h3>
    <p class="muted" id="delName"></p>
    <p class="muted small">It will be removed from the gallery. Because S3 versioning is enabled, the previous version is retained and an administrator can restore it.</p>
    <div class="modal-actions">
      <button class="btn btn-ghost" type="button" data-close>Cancel</button>
      <button class="btn btn-danger" id="delConfirm" type="button">Delete</button>
    </div>
  </div>
</dialog>

<div class="toasts" id="toasts" aria-live="polite"></div>
<script src="{{ url_for('static', filename='app.js') }}"></script>
</body>
</html>
GALLERY_EOF
cat > /opt/gallery/static/app.js <<'GALLERY_EOF'
/* PixelVault front-end: gallery, uploads, lightbox, share/delete dialogs. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const meta = n => $(`meta[name="${n}"]`).content;
  const CSRF = meta("csrf");
  const MAX_MB = Number(meta("max-mb"));
  const MAX_BYTES = MAX_MB * 1024 * 1024;
  const TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp"];
  const MAX_QUEUE = 20;
  const NS = "http://www.w3.org/2000/svg";

  /* ---------- helpers ---------- */
  const fmtBytes = b => {
    if (b < 1024) return `${b} B`;
    const u = ["KB", "MB", "GB"]; let i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return `${b.toFixed(1)} ${u[i]}`;
  };
  const svg = name => {
    const s = document.createElementNS(NS, "svg"); s.setAttribute("class", "icon");
    const u = document.createElementNS(NS, "use"); u.setAttribute("href", "#i-" + name);
    s.appendChild(u); return s;
  };
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const ago = ts => {
    const s = (ts * 1000 - Date.now()) / 1000;
    for (const [unit, sec] of [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]])
      if (Math.abs(s) >= sec) return rtf.format(Math.round(s / sec), unit);
    return "just now";
  };

  function toast(message, type = "info", ms = 4200) {
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.setAttribute("role", type === "error" ? "alert" : "status");
    const text = document.createElement("span"); text.textContent = message;
    const x = document.createElement("button");
    x.type = "button"; x.className = "toast-x"; x.setAttribute("aria-label", "Dismiss"); x.appendChild(svg("x"));
    el.append(svg({ success: "check", error: "alert", info: "shield" }[type] || "shield"), text, x);
    const close = () => { el.classList.add("out"); setTimeout(() => el.remove(), 200); };
    x.addEventListener("click", close);
    $("#toasts").appendChild(el);
    setTimeout(close, ms);
  }

  async function api(url, body) {
    const res = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify(body),
    });
    if (res.status === 401) { location.href = "/login"; throw new Error("Session expired"); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) throw new Error(data.error || "Request failed");
    return data;
  }

  /* ---------- theme ---------- */
  $("#themeToggle").addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("theme", next); } catch (e) { /* ignore */ }
  });

  /* ---------- gallery: filter / sort / layout ---------- */
  const gallery = $("#gallery");
  const photos = () => $$(".photo", gallery);
  const visible = () => photos().filter(p => !p.hidden);

  function updateStats() {
    const l = photos();
    $("#statCount").textContent = l.length;
    $("#statSize").textContent = fmtBytes(l.reduce((s, p) => s + Number(p.dataset.size), 0));
  }

  function refresh() {
    const q = $("#search").value.trim().toLowerCase();
    const [field, dir] = $("#sort").value.split(":");
    const list = photos().sort((a, b) => {
      const r = field === "name"
        ? a.dataset.name.localeCompare(b.dataset.name, undefined, { numeric: true, sensitivity: "base" })
        : Number(a.dataset[field]) - Number(b.dataset[field]);
      return dir === "desc" ? -r : r;
    });
    list.forEach(p => { p.hidden = !!q && !p.dataset.name.toLowerCase().includes(q); gallery.appendChild(p); });
    const total = list.length, shown = list.filter(p => !p.hidden).length;
    $("#shownCount").textContent = q ? `${shown} of ${total}` : String(total);
    $("#emptyState").hidden = total !== 0;
    $("#noResults").hidden = !(total > 0 && shown === 0);
    $("#toolbar").hidden = total === 0;
    gallery.hidden = total === 0;
  }
  $("#search").addEventListener("input", refresh);
  $("#sort").addEventListener("change", refresh);

  function setView(v) {
    gallery.classList.toggle("view-list", v === "list");
    $$("[data-view]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.view === v)));
    try { localStorage.setItem("view", v); } catch (e) { /* ignore */ }
  }
  $$("[data-view]").forEach(b => b.addEventListener("click", () => setView(b.dataset.view)));
  try { setView(localStorage.getItem("view") || "grid"); } catch (e) { setView("grid"); }

  $$(".js-ago").forEach(el => {
    const ts = Number(el.dataset.ts);
    el.textContent = ago(ts);
    el.title = new Date(ts * 1000).toLocaleString();
  });

  photos().forEach(p => {
    const img = $("img", p);
    const ok = () => p.classList.add("loaded");
    img.addEventListener("load", ok, { once: true });
    img.addEventListener("error", () => p.classList.add("loaded", "broken"), { once: true });
    if (img.complete && img.naturalWidth > 0) ok();
  });

  /* ---------- dialogs ---------- */
  $$("dialog").forEach(d => {
    d.addEventListener("click", e => { if (e.target === d) d.close(); });
    $$("[data-close]", d).forEach(b => b.addEventListener("click", () => d.close()));
  });

  /* share */
  const shareDlg = $("#shareDialog");
  let shareCard = null, shareReq = 0;
  async function loadShare() {
    if (!shareCard) return;
    const req = ++shareReq;
    const minutes = Number($('input[name="minutes"]:checked').value);
    const urlEl = $("#shareUrl"), btn = $("#copyBtn");
    urlEl.value = "Generating link…"; btn.disabled = true; $("#shareHint").textContent = "";
    try {
      const d = await api("/share", { id: shareCard.dataset.id, minutes });
      if (req !== shareReq) return;
      urlEl.value = d.url; btn.disabled = false;
      const exp = new Date(Date.now() + d.expires_in_minutes * 60000);
      $("#shareHint").textContent = `Expires at ${exp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    } catch (e) {
      if (req !== shareReq) return;
      urlEl.value = ""; $("#shareHint").textContent = e.message;
    }
  }
  function openShare(card) {
    shareCard = card;
    $("#shareName").textContent = card.dataset.name;
    shareDlg.showModal();
    loadShare();
  }
  $$('input[name="minutes"]').forEach(r => r.addEventListener("change", loadShare));
  $("#copyBtn").addEventListener("click", async () => {
    const el = $("#shareUrl");
    try { await navigator.clipboard.writeText(el.value); }
    catch (e) { el.select(); document.execCommand("copy"); }   // fallback for plain-HTTP origins
    const label = $("#copyBtn span"); label.textContent = "Copied!";
    toast("Link copied to clipboard", "success", 2000);
    setTimeout(() => { label.textContent = "Copy"; }, 1800);
  });

  /* delete */
  const delDlg = $("#deleteDialog");
  let delCard = null;
  function openDelete(card) {
    delCard = card;
    $("#delName").textContent = card.dataset.name;
    $("#delConfirm").disabled = false;
    delDlg.showModal();
  }
  $("#delConfirm").addEventListener("click", async () => {
    if (!delCard) return;
    const card = delCard, btn = $("#delConfirm");
    btn.disabled = true;
    try {
      await api("/delete", { id: card.dataset.id });
      delDlg.close();
      card.classList.add("removing");
      setTimeout(() => {
        card.remove(); updateStats(); refresh();
        if (!lb.hidden) {
          lbList = visible();
          if (!lbList.length) closeLb(); else { lbIndex = Math.min(lbIndex, lbList.length - 1); showLb(); }
        }
      }, 250);
      toast(`Deleted ${card.dataset.name}`, "success");
    } catch (e) {
      btn.disabled = false; toast(e.message, "error");
    }
  });

  /* ---------- lightbox ---------- */
  const lb = $("#lightbox");
  let lbList = [], lbIndex = 0;
  function showLb() {
    const c = lbList[lbIndex];
    $("#lbImg").src = c.dataset.url; $("#lbImg").alt = c.dataset.name;
    $("#lbName").textContent = c.dataset.name;
    $("#lbMeta").textContent = `${fmtBytes(Number(c.dataset.size))} · ${new Date(c.dataset.ts * 1000).toLocaleString()}`;
    $("#lbCount").textContent = `${lbIndex + 1} / ${lbList.length}`;
    $("#lbPrev").hidden = $("#lbNext").hidden = lbList.length < 2;
  }
  function openLb(card) {
    lbList = visible(); lbIndex = Math.max(0, lbList.indexOf(card));
    showLb(); lb.hidden = false; document.body.classList.add("noscroll"); $("#lbClose").focus();
  }
  function closeLb() { lb.hidden = true; $("#lbImg").removeAttribute("src"); document.body.classList.remove("noscroll"); }
  const stepLb = d => { lbIndex = (lbIndex + d + lbList.length) % lbList.length; showLb(); };
  $("#lbClose").addEventListener("click", closeLb);
  $("#lbPrev").addEventListener("click", () => stepLb(-1));
  $("#lbNext").addEventListener("click", () => stepLb(1));
  $("#lbShare").addEventListener("click", () => openShare(lbList[lbIndex]));
  $("#lbDelete").addEventListener("click", () => openDelete(lbList[lbIndex]));
  lb.addEventListener("click", e => { if (e.target === lb || e.target.classList.contains("lb-stage")) closeLb(); });
  document.addEventListener("keydown", e => {
    if (lb.hidden || $("dialog[open]")) return;
    if (e.key === "Escape") closeLb();
    else if (e.key === "ArrowLeft") stepLb(-1);
    else if (e.key === "ArrowRight") stepLb(1);
  });

  gallery.addEventListener("click", e => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const card = btn.closest(".photo");
    ({ open: openLb, share: openShare, delete: openDelete })[btn.dataset.action](card);
  });

  /* ---------- upload ---------- */
  const dz = $("#dropzone"), input = $("#fileInput"), queueEl = $("#queue");
  const upBtn = $("#uploadBtn"), clearBtn = $("#clearBtn"), upStatus = $("#uploadStatus");
  let queue = [], busy = false;

  function makeItem(item) {
    const li = document.createElement("li"); li.className = "q-item"; li.dataset.state = "ready";
    const img = document.createElement("img"); img.src = item.url; img.alt = "";
    const body = document.createElement("div"); body.className = "q-body";
    const name = document.createElement("div"); name.className = "q-name"; name.textContent = item.file.name;
    const metaEl = document.createElement("div"); metaEl.className = "q-meta"; metaEl.textContent = fmtBytes(item.file.size);
    const bar = document.createElement("div"); bar.className = "bar";
    const fill = document.createElement("i"); bar.appendChild(fill);
    body.append(name, metaEl, bar);
    const rm = document.createElement("button");
    rm.type = "button"; rm.className = "btn-icon sm"; rm.setAttribute("aria-label", `Remove ${item.file.name}`);
    rm.appendChild(svg("x"));
    rm.addEventListener("click", () => {
      if (busy) return;
      URL.revokeObjectURL(item.url);
      queue = queue.filter(q => q !== item); renderQueue();
    });
    li.append(img, body, rm);
    Object.assign(item, { li, metaEl, fill });
    return li;
  }
  function renderQueue() {
    queueEl.replaceChildren(...queue.map(makeItem));
    $("#queueActions").hidden = queue.length === 0;
    upBtn.querySelector("span").textContent = `Upload ${queue.length} image${queue.length === 1 ? "" : "s"}`;
    upStatus.textContent = "";
  }
  function addFiles(files) {
    for (const f of files) {
      if (!TYPES.includes(f.type)) { toast(`${f.name}: unsupported file type`, "error"); continue; }
      if (f.size > MAX_BYTES) { toast(`${f.name}: larger than ${MAX_MB} MB`, "error"); continue; }
      if (queue.some(q => q.file.name === f.name && q.file.size === f.size && q.file.lastModified === f.lastModified)) continue;
      if (queue.length >= MAX_QUEUE) { toast(`Up to ${MAX_QUEUE} images at a time`, "info"); break; }
      queue.push({ file: f, url: URL.createObjectURL(f) });
    }
    renderQueue();
  }
  const setProgress = (item, f) => {
    const pct = Math.round(f * 100);
    item.fill.style.width = pct + "%"; item.metaEl.textContent = `Uploading… ${pct}%`;
  };
  const mark = (item, state, text) => {
    item.li.dataset.state = state; item.metaEl.textContent = text;
    if (state === "done") item.fill.style.width = "100%";
  };

  function sendOne(item) {
    return new Promise(resolve => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/upload");
      xhr.setRequestHeader("X-CSRF-Token", CSRF);
      xhr.responseType = "json";
      xhr.upload.onprogress = e => { if (e.lengthComputable) setProgress(item, e.loaded / e.total); };
      xhr.onload = () => {
        if (xhr.status === 401) { location.href = "/login"; return resolve(false); }
        const d = xhr.response || {};
        if (xhr.status >= 200 && xhr.status < 300 && d.ok) { mark(item, "done", "Uploaded"); resolve(true); }
        else { mark(item, "error", d.error || "Upload failed"); resolve(false); }
      };
      xhr.onerror = () => { mark(item, "error", "Network error"); resolve(false); };
      const fd = new FormData(); fd.append("image", item.file);
      xhr.send(fd);
    });
  }

  upBtn.addEventListener("click", async () => {
    if (busy || !queue.length) return;
    busy = true; upBtn.disabled = clearBtn.disabled = true;
    const todo = queue.filter(q => q.li.dataset.state !== "done");
    let okCount = 0;
    for (let i = 0; i < todo.length; i++) {
      upStatus.textContent = `Uploading ${i + 1} of ${todo.length}…`;
      if (await sendOne(todo[i])) okCount++;
    }
    const failed = todo.length - okCount;
    if (okCount) toast(`${okCount} image${okCount === 1 ? "" : "s"} uploaded`, "success");
    if (failed) toast(`${failed} upload${failed === 1 ? "" : "s"} failed`, "error");
    if (okCount && !failed) { upStatus.textContent = "Done — refreshing gallery…"; setTimeout(() => location.reload(), 900); }
    else { busy = false; upBtn.disabled = clearBtn.disabled = false; upStatus.textContent = failed ? "Some files failed. Remove them or retry." : ""; }
  });
  clearBtn.addEventListener("click", () => { queue.forEach(q => URL.revokeObjectURL(q.url)); queue = []; renderQueue(); });

  ["dragenter", "dragover"].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.remove("drag"); }));
  dz.addEventListener("drop", e => { if (!busy) addFiles(e.dataTransfer.files); });
  input.addEventListener("change", () => { if (!busy) addFiles(input.files); input.value = ""; });
  ["dragover", "drop"].forEach(t => window.addEventListener(t, e => e.preventDefault()));  // don't navigate away on stray drops

  refresh();
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

setenv() { sudo sed -i "/^$1=/d" /etc/gallery.env; echo "$1=$2" | sudo tee -a /etc/gallery.env >/dev/null; }
setenv DB_PATH /var/lib/gallery/gallery.db
setenv AWS_METADATA_SERVICE_TIMEOUT 5
setenv AWS_METADATA_SERVICE_NUM_ATTEMPTS 3
sudo grep -q '^REGISTRATION_OPEN=' /etc/gallery.env || setenv REGISTRATION_OPEN true
if [ -n "${INVITE_CODE:-}" ]; then setenv INVITE_CODE "$INVITE_CODE"; fi

# start only after the network (and the metadata service) is reachable
sudo sed -i 's/^After=network.target$/After=network-online.target/' /etc/systemd/system/gallery.service
sudo grep -q '^Wants=network-online.target' /etc/systemd/system/gallery.service || \
  sudo sed -i '/^After=network-online.target$/a Wants=network-online.target' /etc/systemd/system/gallery.service

sudo systemctl daemon-reload
sudo systemctl restart gallery
sleep 3
sudo systemctl is-active gallery
curl -4 -s http://127.0.0.1/health; echo
echo "Upgrade complete. Open the site and use 'Create an account'."
