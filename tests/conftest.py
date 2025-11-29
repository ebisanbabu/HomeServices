import os
from cryptography.fernet import Fernet

# Ensure required env vars before importing app
os.environ.setdefault('FERNET_KEYS', Fernet.generate_key().decode())
os.environ.setdefault('MAIL_BYPASS', 'True')

import pytest

import app as myapp


@pytest.fixture(scope='session')
def app():
    # configure app for testing
    myapp.app.config['WTF_CSRF_ENABLED'] = False
    myapp.app.config['TESTING'] = True
    return myapp.app


@pytest.fixture(scope='session')
def client(app):
    return app.test_client()


@pytest.fixture()
def db_session():
    # provide a DB session for tests
    s = myapp.SessionLocal()
    try:
        yield s
    finally:
        s.close()


def random_username(prefix='test'):
    import random, string
    return prefix + ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
