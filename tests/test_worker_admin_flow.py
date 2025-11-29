import io
from werkzeug.security import generate_password_hash


def ensure_user(db_session, username, role='worker'):
    from models import User
    u = db_session.query(User).filter_by(username=username).first()
    if not u:
        u = User(username=username, email_hash='eh', password_hash=generate_password_hash('Workerpass1A'), role=role, email_verified=True)
        db_session.add(u)
        db_session.commit()
    return u


def test_worker_upload_and_admin_verify(client, db_session, tmp_path):
    # create worker
    worker = ensure_user(db_session, 'worker_test1', role='worker')
    worker_id = worker.id
    # login as worker
    resp = client.post('/login', data={'username': worker.username, 'password': 'Workerpass1A'}, follow_redirects=True)
    assert resp.status_code == 200

    # upload certificate
    data = {
        'certificate': (io.BytesIO(b'PDF-DATA'), 'cert.pdf')
    }
    resp = client.post('/upload_certificate', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert resp.status_code == 200
    # verify file saved in uploads
    import os
    from app import app as flask_app
    uploads_dir = flask_app.config.get('UPLOAD_FOLDER')
    saved_files = os.listdir(uploads_dir)
    assert any(f.startswith(f"user_{worker_id}_") for f in saved_files)

    # create admin and login
    admin = ensure_user(db_session, 'admin_test1', role='admin')
    resp = client.post('/login', data={'username': admin.username, 'password': 'Workerpass1A'}, follow_redirects=True)
    assert resp.status_code == 200

    # admin verify worker
    resp = client.post(f'/admin/verify/{worker_id}', follow_redirects=True)
    assert resp.status_code == 200
    from models import User
    refreshed = db_session.query(User).get(worker_id)
    assert getattr(refreshed, 'is_verified', False) is True

    # admin block and unblock
    resp = client.post(f'/admin/block/{worker_id}', follow_redirects=True)
    assert resp.status_code == 200
    refreshed = db_session.query(User).get(worker_id)
    assert getattr(refreshed, 'is_blocked', False) is True

    resp = client.post(f'/admin/unblock/{worker_id}', follow_redirects=True)
    assert resp.status_code == 200
    refreshed = db_session.query(User).get(worker_id)
    assert getattr(refreshed, 'is_blocked', False) is False
