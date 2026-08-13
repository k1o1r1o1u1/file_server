# Ubuntu deployment

This application serves **only** `FILESERVER_STORAGE_DIR` (by default, the
project's `storage/` directory). Keep application code, `.env`, `.venv`, and
the Git repository outside that directory. Shared links are intentionally
unauthenticated: anyone who has a link can browse and download the selected
directory until Gunicorn restarts. Links are held in memory and do not survive
a restart.

## Install

Copy the project to a normal user's directory (shown below as
`/home/YOUR_USER/file-server`) and put the files to be served in `storage/`.

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip
cd /home/YOUR_USER/file-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
```

Edit `.env`. Generate a secret and password hash without placing the plaintext
password in the repository:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
python3 -c "from werkzeug.security import generate_password_hash; import getpass; print(generate_password_hash(getpass.getpass('Password: ')))"
```

Set the generated values as `SECRET_KEY` and `FILESERVER_PASSWORD_HASH`, set
`FILESERVER_USERNAME`, and set `FILESERVER_STORAGE_DIR` to the absolute storage
directory (for example `/home/YOUR_USER/file-server/storage`). `FILESERVER_ENV`
must remain `production`. Do not use the old example password/hash.

## Test locally

Load the environment and start the same conservative Gunicorn configuration
that systemd will use:

```bash
cd /home/YOUR_USER/file-server
set -a; . ./.env; set +a
.venv/bin/gunicorn --workers 1 --bind 0.0.0.0:8888 --access-logfile - --error-logfile - server:app
```

Or use the included launcher. This is the easiest way to run it manually after
the initial setup:

```bash
chmod +x run.sh
./run.sh
```

On the Ubuntu server, open `http://127.0.0.1:8888` or run
`curl -I http://127.0.0.1:8888`. It redirects to `/login` until authenticated.
Gunicorn listens on all local interfaces: use `http://SERVER_LAN_IP:8888` from
a trusted LAN device, or `http://SERVER_TAILSCALE_IP:8888` from a connected
Tailscale device outside the LAN. Allow port 8888 only on the LAN/private
firewall profile if you use a firewall. Do not add router port forwarding or
expose port 8888 publicly.

## Install the systemd service

Replace `YOUR_USER` and `/path/to/file-server` in
`deployment/fileserver.service`, then install it:

```bash
cd /home/YOUR_USER/file-server
sudo cp deployment/fileserver.service /etc/systemd/system/fileserver.service
sudo systemctl daemon-reload
sudo systemctl enable fileserver
sudo systemctl start fileserver
sudo systemctl status fileserver
journalctl -u fileserver
journalctl -u fileserver -f
```

The service runs as the specified non-root user, restarts after a crash, and
uses one Gunicorn worker for the low-resource host. After changing `.env` or
the service file, run `sudo systemctl daemon-reload` (for service changes) and
`sudo systemctl restart fileserver`.

## Security notes

The server resolves requested paths and rejects absolute paths, `..`, Windows
separators, and symlinks that escape the exposed directory. Put only intended
files in `storage/`; filesystem permissions still apply. `FILESERVER_SECURE_COOKIES`
should be changed to `true` only when clients access the application through
HTTPS; it must remain `false` for direct HTTP testing on localhost.

Authenticated users can create folders and upload files through the browser.
Uploads cannot overwrite an existing file and reject path-like filenames. The
browser shows upload progress and approximate speed; available disk space and
any outer web-server limit determine the maximum upload size.

There is no application file-size limit. Gunicorn's worker timeout is disabled
(`--timeout 0`) so large uploads can run for as long as an active LAN/Tailscale
connection needs. This is appropriate for this private, authenticated server,
but one slow or stalled upload uses its single worker until the connection ends.
Uploading a folder from supported browsers preserves its internal folder
structure below the current directory. A folder upload is still subject to the
user's quota and available server disk space.

## User accounts and administrator

`/admin/login` is the administrator login. Its credentials remain the
`FILESERVER_USERNAME` and `FILESERVER_PASSWORD_HASH` values in `.env`. The
administrator can browse all storage and use **Users** in the top navigation to
create ordinary accounts, reset passwords, disable/enable accounts, and delete
accounts. Disabling takes effect on the user's next request. Deleting removes
only the account; its `storage/users/USERNAME/` files are deliberately retained
to avoid accidental data loss. This is application-level administrator access,
not Linux `sudo` access.

Ordinary users log in at `/login`. Every account gets a private directory at
`storage/users/USERNAME/` and cannot browse, upload to, or download from any
other directory. Accounts and password hashes are stored in `fileserver.db` in
the project directory; it is excluded from Git. Back up that file together with
`storage/`, keep it private, and make sure the service user can write the
project directory and `storage/`.

Users can rename, move, copy, ZIP-download, and move their own files and
folders to trash. Administrators can do the same anywhere in storage. Trashed
items are kept in the project `trash/` directory; they are not automatically
deleted, so periodically review and remove only items you no longer need.
Folder ZIP downloads are created temporarily on the server before transfer, so
ensure there is enough free disk space for the archive.

When creating or editing a user, set a storage quota in MB or leave it blank
for unlimited storage. The user sees their quota/usage bar while browsing, and
the administrator sees each user's usage and quota in the Users panel. Uploads
that would exceed the quota are rejected.

All state-changing browser requests use a session CSRF token. If you later add
your own HTML forms or JavaScript API calls, include the template value
`{{ csrf_token }}` as a form field named `csrf_token`, or send it in the
`X-CSRF-Token` request header.
