"""Flask file server application. Serve with: gunicorn --workers 1 --bind 0.0.0.0:8888 server:app"""

import logging
import os
import secrets
import re
import sqlite3
import hmac
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


APP_DIR = Path(__file__).resolve().parent
STORAGE_DIR = Path(os.environ.get("FILESERVER_STORAGE_DIR", APP_DIR / "storage")).expanduser().resolve()
# Keep ordinary-user folders separate from the administrator's exposed tree.
# In full-host mode (FILESERVER_STORAGE_DIR=/), this avoids creating /users.
USERS_DIR = Path(os.environ.get("FILESERVER_USERS_DIR", APP_DIR / "users")).expanduser().resolve()
DATABASE_PATH = APP_DIR / "fileserver.db"
TRASH_DIR = APP_DIR / "trash"
IS_PRODUCTION = os.environ.get("FILESERVER_ENV", "production").lower() == "production"
if not STORAGE_DIR.is_dir():
    raise RuntimeError(f"FILESERVER_STORAGE_DIR is not an existing directory: {STORAGE_DIR}")
USERS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
TRASH_DIR.mkdir(exist_ok=True)


def required_environment(name):
    """Return a required setting without ever logging its value."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be set in the environment")
    return value


def secret_key():
    value = os.environ.get("SECRET_KEY")
    if value:
        return value
    if IS_PRODUCTION:
        raise RuntimeError("SECRET_KEY must be set in the production environment")
    logging.getLogger(__name__).warning("Using an ephemeral development SECRET_KEY")
    return secrets.token_urlsafe(48)


app = Flask(__name__)
app.secret_key = secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FILESERVER_SECURE_COOKIES", "false").lower() == "true",
)
app.logger.info("File server initialized")

USERNAME = required_environment("FILESERVER_USERNAME")
PASSWORD_HASH = required_environment("FILESERVER_PASSWORD_HASH")

# Deliberately in-memory for now.  This small interface makes a later SQLite
# implementation possible without changing route code.
SHARED_LINKS = {}

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}$")


def database_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with database_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                quota_bytes INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        if "enabled" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        if "quota_bytes" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN quota_bytes INTEGER")
        connection.execute("CREATE TABLE IF NOT EXISTS trash_items (item_id TEXT PRIMARY KEY, owner TEXT NOT NULL, storage_path TEXT NOT NULL, original_path TEXT NOT NULL, created_at TEXT NOT NULL)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                remote_address TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS protected_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)


initialize_database()
TRASH_RETENTION_DAYS = 30


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def audit_event(action, details="", *, actor=None, role=None):
    """Record useful activity without logging credentials or sensitive settings."""
    current_actor = actor or session.get("username", "anonymous")
    current_role = role or session.get("role", "anonymous")
    remote_address = request.remote_addr or "unknown"
    with database_connection() as connection:
        connection.execute(
            "INSERT INTO audit_events (created_at, actor, role, action, details, remote_address) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), current_actor, current_role, action, details[:500], remote_address),
        )


@app.context_processor
def inject_template_values():
    return {"csrf_token": csrf_token()}


@app.before_request
def protect_state_changing_requests():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    submitted = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    expected = session.get("csrf_token", "")
    if not submitted or not expected or not hmac.compare_digest(submitted, expected):
        abort(400, description="Invalid CSRF token")


def reject_unsafe_relative_path(value):
    """Reject absolute and cross-platform traversal input before resolving it."""
    if not isinstance(value, str) or "\x00" in value or "\\" in value:
        abort(403)
    path = Path(value)
    if path.is_absolute() or (len(value) >= 2 and value[1] == ":") or any(part == ".." for part in path.parts):
        abort(403)
    return path


def contained_path(base, relative_path, *, must_be_directory=False, must_be_file=False):
    """Resolve a user path and ensure it remains under base, including symlinks."""
    relative = reject_unsafe_relative_path(relative_path)
    base = Path(base).resolve(strict=True)
    candidate = (base / relative).resolve(strict=False)
    try:
        candidate.relative_to(base)
    except ValueError:
        abort(403)

    if not candidate.exists():
        abort(404)
    # resolve() above follows existing symlinks; this second containment check
    # prevents a symlink inside storage from granting access outside storage.
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(base)
    except ValueError:
        abort(403)
    if must_be_directory and not resolved.is_dir():
        abort(404)
    if must_be_file and not resolved.is_file():
        abort(404)
    return resolved


def safe_filename(filename):
    if not isinstance(filename, str) or not filename or "\x00" in filename:
        abort(404)
    # A filename is a single path component, never a client-provided path.
    if filename in {".", ".."} or "/" in filename or "\\" in filename or Path(filename).name != filename:
        abort(403)
    return filename


def access_base():
    """Admins use the configured host tree; users stay in their private tree."""
    if session.get("role") == "admin":
        return STORAGE_DIR
    username = session.get("username")
    if not username:
        abort(403)
    with database_connection() as connection:
        user = connection.execute("SELECT enabled FROM users WHERE username = ?", (username,)).fetchone()
    if user is None or not user["enabled"]:
        session.clear()
        abort(403)
    return contained_path(USERS_DIR, username, must_be_directory=True)


def safe_path(rel_path):
    return contained_path(access_base(), rel_path, must_be_directory=True)


def shared_link(token):
    link = SHARED_LINKS.get(token)
    if link is None:
        app.logger.warning("Invalid shared-link token requested")
        abort(404)
    return link


def list_directory(directory, sort_by="name_asc"):
    folders, files = [], []
    for entry in directory.iterdir():
        # Never list links that resolve outside the directory being exposed.
        try:
            resolved = entry.resolve(strict=True)
            resolved.relative_to(directory)
        except (OSError, RuntimeError, ValueError):
            continue
            
        try:
            stat = resolved.stat()
        except OSError:
            continue
            
        item = {
            "name": entry.name,
            "size": stat.st_size,
            "mtime": stat.st_mtime
        }
        
        if resolved.is_dir():
            folders.append(item)
        elif resolved.is_file():
            files.append(item)
            
    if sort_by == "name_desc":
        key, rev = lambda x: x["name"].lower(), True
    elif sort_by == "size_asc":
        key, rev = lambda x: x["size"], False
    elif sort_by == "size_desc":
        key, rev = lambda x: x["size"], True
    elif sort_by == "date_asc":
        key, rev = lambda x: x["mtime"], False
    elif sort_by == "date_desc":
        key, rev = lambda x: x["mtime"], True
    else: # name_asc
        key, rev = lambda x: x["name"].lower(), False

    return [f["name"] for f in sorted(folders, key=key, reverse=rev)], [f["name"] for f in sorted(files, key=key, reverse=rev)]


def storage_usage(directory):
    """Return regular-file usage without following symlinks."""
    total = 0
    for root, directories, files in os.walk(directory, followlinks=False):
        directories[:] = [item for item in directories if not (Path(root) / item).is_symlink()]
        for filename in files:
            item = Path(root) / filename
            try:
                if not item.is_symlink():
                    total += item.stat().st_size
            except OSError:
                continue
    return total


def user_quota(username):
    with database_connection() as connection:
        user = connection.execute("SELECT quota_bytes FROM users WHERE username = ?", (username,)).fetchone()
    return user["quota_bytes"] if user else None


def quota_information():
    if session.get("role") != "user":
        return None, None
    base = access_base()
    return storage_usage(base), user_quota(session["username"])


def candidate_drive_paths():
    """Return actual mounted drive directories for an admin NAS view.

    We intentionally skip generic system roots such as /, /mnt, /media and focus
    on the real mounted drive directories the user actually cares about.
    """
    roots = (Path("/mnt"), Path("/media"), Path("/run/media"), Path("/srv"))
    candidates = []
    for root in roots:
        try:
            if not root.exists() or not root.is_dir():
                continue
            for entry in sorted(root.iterdir(), key=lambda item: item.name.lower()):
                if entry.is_dir() and entry.name not in {"lost+found"}:
                    candidates.append(entry)
        except OSError:
            continue

    seen = set()
    ordered = []
    for path in candidates:
        try:
            resolved = path.resolve(strict=False)
        except OSError:
            continue
        if resolved in seen or not resolved.is_dir():
            continue
        seen.add(resolved)
        ordered.append(resolved)
    return ordered


def drive_usage_summary():
    results = []
    for path in candidate_drive_paths():
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            continue
        total = usage.total
        if total <= 0:
            continue
        used = usage.used
        percent = round((used / total) * 100, 1)
        results.append({
            "path": str(path),
            "name": path.name or "/",
            "used": used,
            "free": usage.free,
            "total": total,
            "percent": percent,
        })
    return results


def protected_folder_record(path):
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    with database_connection() as connection:
        rows = connection.execute("SELECT * FROM protected_folders WHERE enabled = 1").fetchall()
    for row in rows:
        protected = Path(row["path"]).resolve(strict=False)
        try:
            resolved.relative_to(protected)
            return row
        except ValueError:
            continue
    return None


def folder_access_allowed(path):
    if session.get("role") == "admin":
        return True
    row = protected_folder_record(path)
    if row is None:
        return True
    access_map = session.get("folder_access", {})
    protected_path = str(Path(row["path"]).resolve(strict=False))
    return bool(access_map.get(protected_path))


def require_folder_access(path):
    if folder_access_allowed(path):
        return True
    abort(403)


def relative_parent(path):
    if not path:
        return None
    parent = Path(path).parent
    return "" if str(parent) == "." else str(parent)


def admin_drive_shortcuts():
    """Return friendly entry points for a full-host administrator view.

    Linux exposes additional disks as mounted directories rather than drive
    letters.  Present the useful mount locations directly at the top level so
    a personal NAS does not require browsing the entire operating-system tree.
    """
    if session.get("role") != "admin" or STORAGE_DIR != Path("/"):
        return []

    shortcuts = [{"name": "System files", "path": "", "detail": "/"}]
    candidates = [(Path("/home"), "Home folders")]
    for mount_parent in (Path("/mnt"), Path("/media"), Path("/run/media")):
        try:
            candidates.extend((entry, entry.name) for entry in mount_parent.iterdir() if entry.is_dir())
        except OSError:
            continue

    seen = {""}
    for directory, label in candidates:
        try:
            resolved = directory.resolve(strict=True)
            relative = str(resolved.relative_to(STORAGE_DIR)).replace(os.sep, "/")
        except (OSError, RuntimeError, ValueError):
            continue
        if relative and relative not in seen:
            shortcuts.append({"name": label, "path": relative, "detail": f"/{relative}"})
            seen.add(relative)
    return shortcuts


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        with database_connection() as connection:
            user = connection.execute("SELECT username, password_hash FROM users WHERE username = ? AND enabled = 1", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            csrf_token()
            session["role"] = "user"
            session["username"] = user["username"]
            audit_event("login", "User signed in")
            return redirect(url_for("index"))
        app.logger.warning("Failed login attempt")
        flash("Invalid credentials", "error")
    return render_template("login.html", admin_login=False)


@app.route("/login/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
            session.clear()
            csrf_token()
            session["role"] = "admin"
            session["username"] = username
            audit_event("admin_login", "Administrator signed in")
            return redirect(url_for("index"))
        app.logger.warning("Failed admin login attempt")
        flash("Invalid credentials", "error")
    return render_template("login.html", admin_login=True)


@app.route("/logout", methods=["POST"])
def logout():
    audit_event("logout", "Signed out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
def index():
    if not session.get("role"):
        return redirect(url_for("login"))
    rel_path = request.args.get("path", "")
    sort_by = request.args.get("sort", "name_asc")
    current_path = safe_path(rel_path)
    protected = protected_folder_record(current_path)
    if protected and not folder_access_allowed(current_path):
        return render_template(
            "index.html",
            folders=[],
            files=[],
            path=rel_path,
            parent=relative_parent(rel_path),
            is_admin=session.get("role") == "admin",
            username=session.get("username"),
            usage_bytes=None,
            quota_bytes=None,
            current_sort=sort_by,
            drive_shortcuts=admin_drive_shortcuts(),
            drive_usage=drive_usage_summary() if session.get("role") == "admin" else [],
            protected_required=True,
            protected_path=str(Path(protected["path"]).resolve(strict=False)),
        )
    folders, files = list_directory(current_path, sort_by=sort_by)
    usage, quota = quota_information()
    return render_template(
        "index.html",
        folders=folders,
        files=files,
        path=rel_path,
        parent=relative_parent(rel_path),
        is_admin=session.get("role") == "admin",
        username=session.get("username"),
        usage_bytes=usage,
        quota_bytes=quota,
        current_sort=sort_by,
        drive_shortcuts=admin_drive_shortcuts(),
        drive_usage=drive_usage_summary() if session.get("role") == "admin" else [],
        protected_required=False,
        protected_path="",
    )


@app.route("/search", methods=["GET"])
def search():
    require_login()
    query = request.args.get("q", "").strip()
    if not query:
        return redirect(url_for("index"))
        
    base = access_base()
    results = []
    
    for root, directories, files in os.walk(base, followlinks=False):
        directories[:] = [item for item in directories if not (Path(root) / item).is_symlink()]
        
        for directory in directories:
            if query.lower() in directory.lower():
                full_path = Path(root) / directory
                results.append({
                    "name": directory,
                    "rel_path": str(full_path.relative_to(base)).replace(os.sep, "/"),
                    "rel_parent": str(full_path.parent.relative_to(base)).replace(os.sep, "/") if full_path.parent != base else "",
                    "is_dir": True
                })
        
        for filename in files:
            if query.lower() in filename.lower():
                full_path = Path(root) / filename
                if not full_path.is_symlink():
                    results.append({
                        "name": filename,
                        "rel_path": str(full_path.relative_to(base)).replace(os.sep, "/"),
                        "rel_parent": str(full_path.parent.relative_to(base)).replace(os.sep, "/") if full_path.parent != base else "",
                        "is_dir": False
                    })
                    
    usage, quota = quota_information()
    return render_template("index.html", search_query=query, results=results, is_admin=session.get("role") == "admin", username=session.get("username"), usage_bytes=usage, quota_bytes=quota)


def authenticated_file():
    if not session.get("role"):
        return None
    folder = safe_path(request.args.get("path", ""))
    file_path = contained_path(folder, safe_filename(request.args.get("file")), must_be_file=True)
    if not folder_access_allowed(file_path.parent):
        abort(403)
    return file_path


def require_login():
    if not session.get("role"):
        abort(403)
    if session.get("role") == "user":
        access_base()


def require_admin():
    if session.get("role") != "admin":
        abort(403)


def upload_filename(filename):
    """Sanitize a browser filename and reject paths rather than silently using one."""
    safe_filename(filename)
    sanitized = secure_filename(filename)
    if not sanitized:
        abort(400, description="The filename contains no usable characters")
    return sanitized


def upload_destination(folder, uploaded, relative_path):
    """Return a safe destination for a file or a browser-selected folder upload."""
    filename = upload_filename(uploaded.filename)
    if not relative_path:
        return folder / filename
    # webkitRelativePath is browser metadata (for example
    # Photos/2026/.flask_secret), not a trusted filesystem path. Sanitize every
    # component rather than requiring it to match the browser filename exactly.
    relative = reject_unsafe_relative_path(relative_path)
    if len(relative.parts) < 2:
        abort(400, description="Invalid folder upload path")
    safe_parts = []
    for part in relative.parts[:-1]:
        safe_part = secure_filename(part)
        if not safe_part:
            abort(400, description="Folder upload contains an invalid folder name")
        safe_parts.append(safe_part)
    # Use the separately validated upload filename for the final component.
    # This accepts harmless dot-files (such as .flask_secret) as flask_secret
    # instead of letting one hidden file fail the entire selected folder.
    destination = folder.joinpath(*safe_parts, filename)
    try:
        destination.resolve(strict=False).relative_to(folder.resolve())
    except ValueError:
        abort(403)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.parent.resolve(strict=True).relative_to(folder.resolve())
    except ValueError:
        abort(403)
    return destination


@app.route("/view")
def view():
    file_path = authenticated_file()
    if file_path is None:
        return redirect(url_for("login"))
    return send_file(file_path)


@app.route("/download")
def download():
    file_path = authenticated_file()
    if file_path is None:
        return redirect(url_for("login"))
    audit_event("download", str(file_path.relative_to(access_base())).replace(os.sep, "/"))
    return send_file(file_path, as_attachment=True, download_name=file_path.name)


@app.route("/api/folder", methods=["POST"])
def create_folder():
    require_login()
    payload = request.get_json(silent=True) or {}
    parent = safe_path(payload.get("path", ""))
    require_folder_access(parent)
    name = payload.get("name", "").strip() if isinstance(payload.get("name"), str) else ""
    if not name or name in {".", ".."}:
        return jsonify({"error": "Enter a valid folder name"}), 400
    safe_filename(name)
    destination = parent / name
    try:
        destination.mkdir()
    except FileExistsError:
        return jsonify({"error": "A file or folder with that name already exists"}), 409
    except OSError:
        app.logger.exception("Unable to create folder")
        return jsonify({"error": "Could not create folder"}), 500
    audit_event("create_folder", str(destination.relative_to(access_base())).replace(os.sep, "/"))
    return jsonify({"name": name}), 201


@app.route("/api/folder/protect", methods=["POST"])
def protect_folder():
    require_admin()
    payload = request.get_json(silent=True) or {}
    path = safe_path(payload.get("path", ""))
    password = payload.get("password", "")
    if not isinstance(password, str) or len(password) < 4:
        return jsonify({"error": "Folder password must be at least 4 characters"}), 400
    resolved = str(path.resolve(strict=True))
    with database_connection() as connection:
        connection.execute(
            "INSERT INTO protected_folders (path, password_hash, enabled) VALUES (?, ?, 1) ON CONFLICT(path) DO UPDATE SET password_hash = excluded.password_hash, enabled = 1",
            (resolved, generate_password_hash(password)),
        )
    return jsonify({"path": resolved, "protected": True})


@app.route("/api/folder/unlock", methods=["POST"])
def unlock_folder():
    require_login()
    payload = request.get_json(silent=True) or {}
    path = safe_path(payload.get("path", ""))
    password = payload.get("password", "")
    row = protected_folder_record(path)
    if row is None:
        return jsonify({"error": "Folder is not protected"}), 404
    if not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Incorrect folder password"}), 401
    access_map = session.setdefault("folder_access", {})
    access_map[str(Path(row["path"]).resolve(strict=False))] = True
    session["folder_access"] = access_map
    return jsonify({"unlocked": True, "path": row["path"]})


@app.route("/api/upload", methods=["POST"])
def upload_file():
    require_login()
    folder = safe_path(request.form.get("path", ""))
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Choose a file to upload"}), 400
    destination = upload_destination(folder, uploaded, request.form.get("relative_path", ""))
    remaining_quota = None
    if session.get("role") == "user":
        quota = user_quota(session["username"])
        if quota is not None:
            usage = storage_usage(access_base())
            remaining_quota = max(quota - usage, 0)
    # Exclusive creation avoids accidental overwrites and prevents an existing
    # symlink from being followed. Write in chunks to avoid loading files in RAM.
    try:
        written = 0
        with destination.open("xb") as output:
            while chunk := uploaded.stream.read(64 * 1024):
                written += len(chunk)
                if remaining_quota is not None and written > remaining_quota:
                    output.close()
                    destination.unlink(missing_ok=True)
                    return jsonify({"error": "Upload would exceed your storage quota"}), 413
                output.write(chunk)
    except FileExistsError:
        return jsonify({"error": "A file with that name already exists"}), 409
    except OSError:
        app.logger.exception("Unable to save uploaded file")
        return jsonify({"error": "Could not save upload"}), 500
    audit_event("upload", str(destination.relative_to(access_base())).replace(os.sep, "/"))
    return jsonify({"name": destination.name}), 201


def item_from_request(payload):
    parent = safe_path(payload.get("path", ""))
    name = safe_filename(payload.get("name"))
    return parent, contained_path(parent, name)


@app.route("/api/rename", methods=["POST"])
def rename_item():
    require_login()
    payload = request.get_json(silent=True) or {}
    parent, source = item_from_request(payload)
    require_folder_access(parent)
    new_name = payload.get("new_name", "").strip() if isinstance(payload.get("new_name"), str) else ""
    safe_filename(new_name)
    destination = parent / new_name
    if destination.exists():
        return jsonify({"error": "A file or folder with that name already exists"}), 409
    try:
        source.rename(destination)
    except OSError:
        app.logger.exception("Unable to rename item")
        return jsonify({"error": "Could not rename item"}), 500
    return jsonify({"name": new_name})


@app.route("/api/move-copy", methods=["POST"])
def move_or_copy_item():
    require_login()
    payload = request.get_json(silent=True) or {}
    parent, source = item_from_request(payload)
    require_folder_access(parent)
    destination_parent = safe_path(payload.get("destination", ""))
    require_folder_access(destination_parent)
    operation = payload.get("operation")
    if operation not in {"move", "copy"}:
        return jsonify({"error": "Invalid operation"}), 400
    destination = destination_parent / source.name
    if destination.exists():
        return jsonify({"error": "Destination already contains that name"}), 409
    if source.is_dir():
        try:
            destination_parent.resolve().relative_to(source)
            return jsonify({"error": "Cannot move or copy a folder inside itself"}), 400
        except ValueError:
            pass
    try:
        if operation == "move":
            shutil.move(str(source), str(destination))
        elif source.is_dir():
            shutil.copytree(source, destination, symlinks=True)
        else:
            shutil.copy2(source, destination, follow_symlinks=False)
    except OSError:
        app.logger.exception("Unable to %s item", operation)
        return jsonify({"error": f"Could not {operation} item"}), 500
    return jsonify({"name": source.name, "operation": operation})


@app.route("/api/trash", methods=["POST"])
def trash_item():
    require_login()
    payload = request.get_json(silent=True) or {}
    _, source = item_from_request(payload)
    owner = session.get("username", "admin")
    destination_dir = TRASH_DIR / owner
    destination_dir.mkdir(mode=0o700, exist_ok=True)
    item_id = secrets.token_hex(16)
    destination = destination_dir / f"{item_id}_{source.name}"
    original_path = str(source.relative_to(access_base())).replace(os.sep, "/")
    try:
        shutil.move(str(source), str(destination))
    except OSError:
        app.logger.exception("Unable to move item to trash")
        return jsonify({"error": "Could not move item to trash"}), 500
    with database_connection() as connection:
        connection.execute("INSERT INTO trash_items VALUES (?, ?, ?, ?, ?)", (item_id, owner, str(destination.relative_to(TRASH_DIR)).replace(os.sep, "/"), original_path, datetime.now(timezone.utc).isoformat()))
    return jsonify({"name": source.name})


@app.route("/api/batch-trash", methods=["POST"])
def batch_trash_items():
    require_login()
    payload = request.get_json(silent=True) or {}
    parent_path = safe_path(payload.get("path", ""))
    names = payload.get("names", [])
    if not isinstance(names, list):
        return jsonify({"error": "Invalid payload"}), 400
    
    owner = session.get("username", "admin")
    destination_dir = TRASH_DIR / owner
    destination_dir.mkdir(mode=0o700, exist_ok=True)
    
    count = 0
    for name in names:
        try:
            source = contained_path(parent_path, safe_filename(name))
            item_id = secrets.token_hex(16)
            destination = destination_dir / f"{item_id}_{source.name}"
            original_path = str(source.relative_to(access_base())).replace(os.sep, "/")
            shutil.move(str(source), str(destination))
            with database_connection() as connection:
                connection.execute("INSERT INTO trash_items VALUES (?, ?, ?, ?, ?)", (item_id, owner, str(destination.relative_to(TRASH_DIR)).replace(os.sep, "/"), original_path, datetime.now(timezone.utc).isoformat()))
            count += 1
        except Exception:
            continue
            
    if count == 0 and names:
        return jsonify({"error": "Could not trash items"}), 500
    return jsonify({"trashed": count})


@app.route("/zip")
def download_folder_zip():
    require_login()
    folder = safe_path(request.args.get("path", ""))
    temporary = tempfile.NamedTemporaryFile(prefix="fileserver-", suffix=".zip", delete=False)
    temporary.close()
    archive_path = Path(temporary.name)
    try:
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for root, directories, files in os.walk(folder, followlinks=False):
                directories[:] = [item for item in directories if not (Path(root) / item).is_symlink()]
                for filename in files:
                    item = Path(root) / filename
                    if not item.is_symlink():
                        archive.write(item, item.relative_to(folder.parent))
    except OSError:
        archive_path.unlink(missing_ok=True)
        app.logger.exception("Unable to create ZIP archive")
        abort(500)
    response = send_file(archive_path, as_attachment=True, download_name=f"{folder.name or 'files'}.zip")
    response.call_on_close(lambda: archive_path.unlink(missing_ok=True))
    return response


@app.route("/admin/users", methods=["GET"])
def admin_users():
    require_admin()
    with database_connection() as connection:
        users = connection.execute("SELECT username, enabled, quota_bytes, created_at FROM users ORDER BY username COLLATE NOCASE").fetchall()
    usage = {user["username"]: storage_usage(USERS_DIR / user["username"]) for user in users}
    return render_template("admin_users.html", users=users, user_usage=usage)


@app.route("/admin/logs", methods=["GET"])
def admin_logs():
    require_admin()
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = 100
    with database_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        events = connection.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?",
            (per_page, (page - 1) * per_page),
        ).fetchall()
    return render_template("admin_logs.html", events=events, page=page, has_next=page * per_page < total)


@app.route("/account", methods=["GET"])
def account_settings():
    require_login()
    if session.get("role") == "admin":
        return redirect(url_for("admin_users"))
    return render_template("account.html", username=session["username"])


@app.route("/api/account/password", methods=["POST"])
def change_own_password():
    require_login()
    if session.get("role") == "admin":
        abort(403)
    payload = request.get_json(silent=True) or {}
    current_password = payload.get("current_password", "")
    new_password = payload.get("new_password", "")
    if not isinstance(new_password, str) or len(new_password) < 10:
        return jsonify({"error": "New password must be at least 10 characters"}), 400
    with database_connection() as connection:
        user = connection.execute("SELECT password_hash FROM users WHERE username = ? AND enabled = 1", (session["username"],)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], current_password):
            app.logger.warning("Failed password-change verification")
            return jsonify({"error": "Current password is incorrect"}), 400
        connection.execute("UPDATE users SET password_hash = ? WHERE username = ?", (generate_password_hash(new_password), session["username"]))
    session.clear()
    app.logger.info("User changed own password")
    return jsonify({"changed": True})


def format_size(size):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024


def cleanup_expired_trash():
    cutoff = (datetime.now(timezone.utc) - timedelta(days=TRASH_RETENTION_DAYS)).isoformat()
    with database_connection() as connection:
        records = connection.execute("SELECT * FROM trash_items WHERE created_at < ?", (cutoff,)).fetchall()
        for record in records:
            target = TRASH_DIR / record["storage_path"]
            try:
                if target.is_dir(): shutil.rmtree(target)
                else: target.unlink(missing_ok=True)
            except OSError: continue
            connection.execute("DELETE FROM trash_items WHERE item_id = ?", (record["item_id"],))


def render_trash(is_admin):
    cleanup_expired_trash()
    with database_connection() as connection:
        records = connection.execute("SELECT * FROM trash_items ORDER BY created_at DESC" if is_admin else "SELECT * FROM trash_items WHERE owner = ? ORDER BY created_at DESC", () if is_admin else (session["username"],)).fetchall()
    items = []
    for record in records:
        path = TRASH_DIR / record["storage_path"]
        try:
            if path.exists() and not path.is_symlink(): items.append({**dict(record), "name": path.name.split("_", 1)[-1], "kind": "Folder" if path.is_dir() else "File", "size": storage_usage(path) if path.is_dir() else path.stat().st_size})
        except OSError: continue
    return render_template("trash.html", items=items, format_size=format_size, is_admin=is_admin)


@app.route("/trash", methods=["GET"])
def user_trash():
    require_login()
    return render_trash(session.get("role") == "admin")


@app.route("/admin/trash", methods=["GET"])
def admin_trash():
    require_admin()
    return render_trash(True)


@app.route("/api/trash", methods=["DELETE"])
def permanently_delete_trash():
    require_login()
    payload = request.get_json(silent=True) or {}
    item_id = payload.get("item_id", "")
    with database_connection() as connection:
        record = connection.execute("SELECT * FROM trash_items WHERE item_id = ?", (item_id,)).fetchone()
    if record is None or (session.get("role") != "admin" and record["owner"] != session.get("username")):
        abort(404)
    target = contained_path(TRASH_DIR, record["storage_path"])
    try:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    except OSError:
        app.logger.exception("Unable to permanently delete trash item")
        return jsonify({"error": "Could not permanently delete item"}), 500
    app.logger.warning("Permanently deleted trashed item")
    with database_connection() as connection:
        connection.execute("DELETE FROM trash_items WHERE item_id = ?", (item_id,))
    return jsonify({"deleted": True})


@app.route("/api/trash/restore", methods=["POST"])
def restore_trash_item():
    require_login()
    payload = request.get_json(silent=True) or {}
    item_id = payload.get("item_id", "")
    with database_connection() as connection:
        record = connection.execute("SELECT * FROM trash_items WHERE item_id = ?", (item_id,)).fetchone()
    if record is None or (session.get("role") != "admin" and record["owner"] != session.get("username")):
        abort(404)
    source = contained_path(TRASH_DIR, record["storage_path"])
    base = STORAGE_DIR if record["owner"] == USERNAME else contained_path(USERS_DIR, record["owner"], must_be_directory=True)
    destination = base / reject_unsafe_relative_path(record["original_path"])
    if destination.exists():
        return jsonify({"error": "Original location already contains an item with that name"}), 409
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    with database_connection() as connection:
        connection.execute("DELETE FROM trash_items WHERE item_id = ?", (item_id,))
    return jsonify({"restored": True})


@app.route("/api/trash/empty", methods=["DELETE"])
def empty_trash():
    require_login()
    is_admin = session.get("role") == "admin"
    with database_connection() as connection:
        records = connection.execute("SELECT * FROM trash_items" if is_admin else "SELECT * FROM trash_items WHERE owner = ?", () if is_admin else (session["username"],)).fetchall()
    for record in records:
        target = TRASH_DIR / record["storage_path"]
        try:
            if target.is_dir(): shutil.rmtree(target)
            else: target.unlink(missing_ok=True)
        except OSError: continue
        with database_connection() as connection:
            connection.execute("DELETE FROM trash_items WHERE item_id = ?", (record["item_id"],))
    return jsonify({"emptied": True})


@app.route("/api/admin/users", methods=["POST"])
def create_user():
    require_admin()
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "").strip() if isinstance(payload.get("username"), str) else ""
    password = payload.get("password", "")
    quota_mb = payload.get("quota_mb")
    if not USERNAME_PATTERN.fullmatch(username):
        return jsonify({"error": "Username must be 3–32 letters, numbers, _ or -"}), 400
    if not isinstance(password, str) or len(password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400
    quota_bytes = None
    if quota_mb is not None:
        if not isinstance(quota_mb, int) or quota_mb < 1:
            return jsonify({"error": "Quota must be a positive whole number of MB, or unlimited"}), 400
        quota_bytes = quota_mb * 1024 * 1024
    user_folder = USERS_DIR / username
    try:
        with database_connection() as connection:
            connection.execute("INSERT INTO users (username, password_hash, quota_bytes) VALUES (?, ?, ?)", (username, generate_password_hash(password), quota_bytes))
        user_folder.mkdir(mode=0o700)
    except sqlite3.IntegrityError:
        return jsonify({"error": "That username already exists"}), 409
    except OSError:
        app.logger.exception("Unable to create user folder")
        with database_connection() as connection:
            connection.execute("DELETE FROM users WHERE username = ?", (username,))
        return jsonify({"error": "Could not create the user folder"}), 500
    app.logger.info("Created user account: %s", username)
    audit_event("create_user", username)
    return jsonify({"username": username}), 201


@app.route("/api/admin/users/<username>/quota", methods=["POST"])
def set_user_quota(username):
    require_admin()
    if not USERNAME_PATTERN.fullmatch(username):
        abort(404)
    payload = request.get_json(silent=True) or {}
    quota_mb = payload.get("quota_mb")
    if quota_mb is None:
        quota_bytes = None
    elif isinstance(quota_mb, int) and quota_mb >= 1:
        quota_bytes = quota_mb * 1024 * 1024
    else:
        return jsonify({"error": "Quota must be a positive whole number of MB, or unlimited"}), 400
    with database_connection() as connection:
        updated = connection.execute("UPDATE users SET quota_bytes = ? WHERE username = ?", (quota_bytes, username)).rowcount
    if not updated:
        abort(404)
    return jsonify({"username": username, "quota_bytes": quota_bytes})


@app.route("/api/admin/users/<username>/password", methods=["POST"])
def reset_user_password(username):
    require_admin()
    if not USERNAME_PATTERN.fullmatch(username):
        abort(404)
    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or len(password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400
    with database_connection() as connection:
        updated = connection.execute("UPDATE users SET password_hash = ? WHERE username = ?", (generate_password_hash(password), username)).rowcount
    if not updated:
        abort(404)
    app.logger.info("Reset password for user account: %s", username)
    audit_event("admin_reset_password", username)
    return jsonify({"username": username})


@app.route("/api/admin/users/<username>/enabled", methods=["POST"])
def set_user_enabled(username):
    require_admin()
    if not USERNAME_PATTERN.fullmatch(username):
        abort(404)
    payload = request.get_json(silent=True) or {}
    enabled = payload.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"error": "enabled must be true or false"}), 400
    with database_connection() as connection:
        updated = connection.execute("UPDATE users SET enabled = ? WHERE username = ?", (enabled, username)).rowcount
    if not updated:
        abort(404)
    app.logger.info("%s user account: %s", "Enabled" if enabled else "Disabled", username)
    audit_event("enable_user" if enabled else "disable_user", username)
    return jsonify({"username": username, "enabled": enabled})


@app.route("/api/admin/users/<username>", methods=["DELETE"])
def delete_user(username):
    require_admin()
    if not USERNAME_PATTERN.fullmatch(username):
        abort(404)
    with database_connection() as connection:
        deleted = connection.execute("DELETE FROM users WHERE username = ?", (username,)).rowcount
    if not deleted:
        abort(404)
    app.logger.warning("Deleted user account; files retained: %s", username)
    audit_event("delete_user", username)
    return jsonify({"username": username, "files_retained": True})


@app.route("/api/share", methods=["POST"])
def share_folder():
    require_login()
    payload = request.get_json(silent=True) or {}
    rel_path = payload.get("path", "")
    current_path = safe_path(rel_path)
    token = secrets.token_urlsafe(32)
    SHARED_LINKS[token] = {"base_path": current_path}
    return jsonify({"token": token, "url": url_for("shared_index", token=token, _external=True)})


def shared_directory(token, subpath):
    base_path = shared_link(token)["base_path"]
    return contained_path(base_path, subpath, must_be_directory=True)


@app.route("/s/<token>", methods=["GET"])
def shared_index(token):
    subpath = request.args.get("path", "")
    current_path = shared_directory(token, subpath)
    folders, files = list_directory(current_path)
    return render_template("shared.html", folders=folders, files=files, path=subpath, parent=relative_parent(subpath), token=token)


def shared_file(token):
    folder = shared_directory(token, request.args.get("path", ""))
    return contained_path(folder, safe_filename(request.args.get("file")), must_be_file=True)


@app.route("/s/<token>/view")
def shared_view(token):
    return send_file(shared_file(token))


@app.route("/s/<token>/download")
def shared_download(token):
    file_path = shared_file(token)
    return send_file(file_path, as_attachment=True, download_name=file_path.name)


@app.errorhandler(403)
def forbidden(error):
    return "Forbidden", 403


@app.errorhandler(404)
def not_found(error):
    return "Not found", 404


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("Unexpected server error")
    return "Internal server error", 500


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        return error
    app.logger.exception("Unhandled application error")
    return "Internal server error", 500


if __name__ == "__main__":
    # Convenient for trusted LAN testing; production uses Gunicorn below.
    app.run(host="0.0.0.0", port=8888, debug=False)
