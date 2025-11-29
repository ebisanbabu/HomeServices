import pytest
from werkzeug.security import generate_password_hash


def test_register_and_login(client, db_session):
    username = 'auto_user_1'
    # ensure user not present
    db_session.query(db_session.bind.table_names and None)
    # perform register
    resp = client.post('/register', data={
        'username': username,
        'email': f'{username}@example.com',
        'password': 'Testpass1A',
        'role': 'client'
    }, follow_redirects=True)
    assert resp.status_code in (200, 302)

    # login
    resp = client.post('/login', data={'username': username, 'password': 'Testpass1A'}, follow_redirects=True)
    assert resp.status_code == 200
    assert b'Logged in' in resp.data or b'Dashboard' in resp.data


def test_password_reset_flow(client, db_session):
    from app import ts
    # create user directly
    uname = 'pw_user1'
    u = db_session.query(db_session.bind.table_names and None)
    from models import User
    existing = db_session.query(User).filter_by(username=uname).first()
    if not existing:
        new_u = User(username=uname, email_hash='dummy', password_hash=generate_password_hash('Resetpass1A'), role='client', email_verified=True)
        db_session.add(new_u)
        db_session.commit()
    # request reset
    resp = client.post('/reset/request', data={'username': uname}, follow_redirects=True)
    assert resp.status_code == 200
    # extract token from session
    with client.session_transaction() as sess:
        token = sess.get('pw_reset_token')
    assert token
    data = ts.loads(token, salt='pw-reset')
    otp = data.get('otp')
    # perform verify
    resp = client.post('/reset/verify', data={'username': uname, 'otp': otp, 'password': 'Newpass1A'}, follow_redirects=True)
    assert resp.status_code == 200
