"""Flask file server application. Serve with: gunicorn --workers 1 --bind 0.0.0.0:8888 server:app"""

import logging
import os
import secrets
from pathlib import Path

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename


APP_DIR = Path(__file__).resolve().parent
STORAGE_DIR = Path(os.environ.get("FILESERVER_STORAGE_DIR", APP_DIR / "storage")).expanduser().resolve()
IS_PRODUCTION = os.environ.get("FILESERVER_ENV", "production").lower() == "production"
if not STORAGE_DIR.is_dir():
    raise RuntimeError(f"FILESERVER_STORAGE_DIR is not an existing directory: {STORAGE_DIR}")


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


def safe_path(rel_path):
    """Compatibility helper for authenticated directory browsing."""
    return contained_path(STORAGE_DIR, rel_path, must_be_directory=True)


def shared_link(token):
    link = SHARED_LINKS.get(token)
    if link is None:
        app.logger.warning("Invalid shared-link token requested")
        abort(404)
    return link


def list_directory(directory):
    folders, files = [], []
    for entry in directory.iterdir():
        # Never list links that resolve outside the directory being exposed.
        try:
            resolved = entry.resolve(strict=True)
            resolved.relative_to(directory)
        except (OSError, RuntimeError, ValueError):
            continue
        if resolved.is_dir():
            folders.append(entry.name)
        elif resolved.is_file():
            files.append(entry.name)
    return sorted(folders, key=str.lower), sorted(files, key=str.lower)


def relative_parent(path):
    if not path:
        return None
    parent = Path(path).parent
    return "" if str(parent) == "." else str(parent)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))
        app.logger.warning("Failed login attempt")
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
def index():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    rel_path = request.args.get("path", "")
    current_path = safe_path(rel_path)
    folders, files = list_directory(current_path)
    return render_template("index.html", folders=folders, files=files, path=rel_path, parent=relative_parent(rel_path))


def authenticated_file():
    if not session.get("logged_in"):
        return None
    folder = safe_path(request.args.get("path", ""))
    return contained_path(folder, safe_filename(request.args.get("file")), must_be_file=True)


def require_login():
    if not session.get("logged_in"):
        abort(403)


def upload_filename(filename):
    """Sanitize a browser filename and reject paths rather than silently using one."""
    safe_filename(filename)
    sanitized = secure_filename(filename)
    if not sanitized:
        abort(400, description="The filename contains no usable characters")
    return sanitized


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
    return send_file(file_path, as_attachment=True, download_name=file_path.name)


@app.route("/api/folder", methods=["POST"])
def create_folder():
    require_login()
    payload = request.get_json(silent=True) or {}
    parent = safe_path(payload.get("path", ""))
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
    return jsonify({"name": name}), 201


@app.route("/api/upload", methods=["POST"])
def upload_file():
    require_login()
    folder = safe_path(request.form.get("path", ""))
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Choose a file to upload"}), 400
    filename = upload_filename(uploaded.filename)
    destination = folder / filename
    # Exclusive creation avoids accidental overwrites and prevents an existing
    # symlink from being followed. Write in chunks to avoid loading files in RAM.
    try:
        with destination.open("xb") as output:
            while chunk := uploaded.stream.read(64 * 1024):
                output.write(chunk)
    except FileExistsError:
        return jsonify({"error": "A file with that name already exists"}), 409
    except OSError:
        app.logger.exception("Unable to save uploaded file")
        return jsonify({"error": "Could not save upload"}), 500
    return jsonify({"name": filename}), 201


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
