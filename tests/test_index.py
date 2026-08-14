import os, traceback, sys, tempfile
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
    from server import app, list_directory
    app.testing = True

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / 'demo.txt').write_text('hello world', encoding='utf-8')
        (base / 'demo-folder').mkdir()
        items = list_directory(base)
        assert items[0] and items[1], 'directory listing should include folder and file entries'
        assert all('name' in item and 'size' in item for item in items[0] + items[1]), 'entries must carry size metadata'

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['role'] = 'admin'
        sess['username'] = 'admin'
    resp = client.get('/')
    print('STATUS', resp.status_code)
    data = resp.data.decode('utf-8', errors='replace')
    print(data[:4000])
except Exception:
    traceback.print_exc()
    raise
