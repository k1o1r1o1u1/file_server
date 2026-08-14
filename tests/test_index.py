import os, traceback, sys
from pathlib import Path
# Ensure imports find the application module when running from tests/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
# Ensure environment matches a running instance
os.environ['FILESERVER_USERNAME'] = 'admin'
os.environ['FILESERVER_PASSWORD_HASH'] = 'pbkdf2:sha256:600000$test$test'
os.environ['SECRET_KEY'] = 'dev-secret'
os.environ['FILESERVER_STORAGE_DIR'] = r'E:\projects\server_sharing\storage'
os.environ['FILESERVER_USERS_DIR'] = r'E:\projects\server_sharing\users'

try:
    from server import app
    app.testing = True
    client = app.test_client()
    # set admin session
    with client.session_transaction() as sess:
        sess['role'] = 'admin'
        sess['username'] = 'admin'
    resp = client.get('/')
    print('STATUS', resp.status_code)
    data = resp.data.decode('utf-8', errors='replace')
    print(data[:4000])
except Exception:
    traceback.print_exc()
