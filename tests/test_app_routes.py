import os
from cryptography.fernet import Fernet

# Ensure FERNET_KEYS is set before importing the application (app.py requires it at import)
os.environ.setdefault('FERNET_KEYS', Fernet.generate_key().decode())

import importlib

# Import the app after setting env
import app as myapp


def test_allowed_file_util():
    assert myapp.allowed_file('document.pdf')
    assert myapp.allowed_file('image.JPG')
    assert not myapp.allowed_file('binary.exe')
    assert not myapp.allowed_file('noextension')


def test_public_pages_load():
    client = myapp.app.test_client()
    resp = client.get('/')
    assert resp.status_code == 200

    resp = client.get('/register')
    assert resp.status_code == 200

    resp = client.get('/login')
    assert resp.status_code == 200

    resp = client.get('/reset/request')
    assert resp.status_code == 200
