import pytest
import os
import sys
import base64
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.crypto_engine import generate_salt, derive_key
from backend.vault_manager import VAULT_PATH

TEST_VAULT_PATH = "vault/test_flask_vault.json"

@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr('backend.vault_manager.VAULT_PATH', TEST_VAULT_PATH)
    
    from backend.app import app
    app.config["TESTING"] = True
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_FILE_DIR"] = str(tmp_path)
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["SESSION_PERMANENT"] = False
    
    with app.test_client() as client:
        yield client
    
    if os.path.exists(TEST_VAULT_PATH):
        os.remove(TEST_VAULT_PATH)

def get_test_key():
    salt = generate_salt()
    key = derive_key("TestPassword123!", salt)
    key_b64 = base64.b64encode(key).decode()
    salt_b64 = base64.b64encode(salt).decode()
    return key_b64, salt_b64

def test_login_page_loads(client):
    response = client.get('/login')
    assert response.status_code == 200

def test_new_user_login_creates_vault(client):
    key_b64, salt_b64 = get_test_key()
    response = client.post('/login',
        json={"key": key_b64, "salt": salt_b64},
        content_type='application/json'
    )
    data = response.get_json()
    assert response.status_code == 200
    assert data['success'] == True
    assert os.path.exists(TEST_VAULT_PATH)

def test_wrong_key_returns_401(client):
    correct_key, salt_b64 = get_test_key()
    client.post('/login',
        json={"key": correct_key, "salt": salt_b64},
        content_type='application/json'
    )
    
    client.get('/logout')
    
    wrong_key, new_salt = get_test_key()
    response = client.post('/login',
        json={"key": wrong_key, "salt": new_salt},
        content_type='application/json'
    )
    assert response.status_code == 401

def test_add_credential(client):
    key_b64, salt_b64 = get_test_key()
    client.post('/login',
        json={"key": key_b64, "salt": salt_b64},
        content_type='application/json'
    )
    
    response = client.post('/add',
        json={
            "service": "Netflix",
            "username": "test@test.com",
            "password": "pass123"
        },
        content_type='application/json'
    )
    data = response.get_json()
    assert response.status_code == 200
    assert data['success'] == True

def test_delete_credential(client):
    key_b64, salt_b64 = get_test_key()
    client.post('/login',
        json={"key": key_b64, "salt": salt_b64},
        content_type='application/json'
    )
    
    client.post('/add',
        json={
            "service": "Netflix",
            "username": "test@test.com",
            "password": "pass123"
        },
        content_type='application/json'
    )
    
    response = client.post('/delete',
        json={"index": 0},
        content_type='application/json'
    )
    data = response.get_json()
    assert response.status_code == 200
    assert data['success'] == True

def test_dashboard_requires_login(client):
    response = client.get('/dashboard')
    assert response.status_code == 302

def test_logout_clears_session(client):
    key_b64, salt_b64 = get_test_key()
    client.post('/login',
        json={"key": key_b64, "salt": salt_b64},
        content_type='application/json'
    )
    
    client.get('/logout')
    
    response = client.get('/dashboard')
    assert response.status_code == 302

def test_invalid_delete_index(client):
    key_b64, salt_b64 = get_test_key()
    client.post('/login',
        json={"key": key_b64, "salt": salt_b64},
        content_type='application/json'
    )
    
    response = client.post('/delete',
        json={"index": 99},
        content_type='application/json'
    )
    assert response.status_code == 400