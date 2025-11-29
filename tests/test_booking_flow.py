import io
from werkzeug.security import generate_password_hash


def ensure_service(db_session):
    from models import ServiceType
    s = db_session.query(ServiceType).first()
    if not s:
        s = ServiceType(name='General Cleaning')
        db_session.add(s)
        db_session.commit()
    return s


def ensure_user(db_session, username='booking_user'):
    from models import User
    u = db_session.query(User).filter_by(username=username).first()
    if not u:
        u = User(username=username, email_hash='eh', password_hash=generate_password_hash('Bookpass1A'), role='client', email_verified=True)
        db_session.add(u)
        db_session.commit()
    return u


def test_create_booking(client, db_session):
    svc = ensure_service(db_session)
    svc_id = svc.id
    user = ensure_user(db_session, 'booking_user1')
    user_id = user.id

    # login via post
    resp = client.post('/login', data={'username': user.username, 'password': 'Bookpass1A'}, follow_redirects=True)
    assert resp.status_code == 200

    # get book page
    resp = client.get('/book')
    assert resp.status_code == 200

    # post booking
    data = {
        'service_type': str(svc_id),
        'scheduled_time': '2025-12-01 10:00',
        'description': 'Please come to 10 Example St.'
    }
    resp = client.post('/book', data=data, follow_redirects=True)
    assert resp.status_code == 200
    assert b'Service requested' in resp.data

    # check booking exists
    from models import Booking
    b = db_session.query(Booking).filter_by(client_id=user_id).order_by(Booking.created_at.desc()).first()
    assert b is not None
