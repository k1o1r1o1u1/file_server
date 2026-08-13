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
