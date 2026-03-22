import pytest
import sys
import os
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
    return base64.b64encode(key).decode()

# Test 1: GET /login returns 200
def test_login_page_loads(client):
    response = client.get('/login')
    assert response.status_code == 200

# Test 2: New user can login and vault gets created
def test_new_user_login_creates_vault(client):
    key_b64 = get_test_key()
    response = client.post('/login',
        json={"key": key_b64},
        content_type='application/json'
    )
    data = response.get_json()
    assert response.status_code == 200
    assert data['success'] == True
    assert os.path.exists(TEST_VAULT_PATH)

# Test 3: Wrong key returns 401
def test_wrong_key_returns_401(client):
    # first create a vault with one key
    correct_key = get_test_key()
    client.post('/login',
        json={"key": correct_key},
        content_type='application/json'
    )
    
    # log out
    client.get('/logout')
    
    # try to login with a different key
    wrong_key = get_test_key()
    response = client.post('/login',
        json={"key": wrong_key},
        content_type='application/json'
    )
    assert response.status_code == 401

# Test 4: Add credential works
def test_add_credential(client):
    key_b64 = get_test_key()
    client.post('/login',
        json={"key": key_b64},
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

# Test 5: Delete credential works
def test_delete_credential(client):
    key_b64 = get_test_key()
    client.post('/login',
        json={"key": key_b64},
        content_type='application/json'
    )
    
    # add a credential first
    client.post('/add',
        json={
            "service": "Netflix",
            "username": "test@test.com",
            "password": "pass123"
        },
        content_type='application/json'
    )
    
    # now delete it
    response = client.post('/delete',
        json={"index": 0},
        content_type='application/json'
    )
    data = response.get_json()
    assert response.status_code == 200
    assert data['success'] == True

# Test 6: Dashboard requires login
def test_dashboard_requires_login(client):
    response = client.get('/dashboard')
    assert response.status_code == 302

# Test 7: Logout clears session
def test_logout_clears_session(client):
    key_b64 = get_test_key()
    client.post('/login',
        json={"key": key_b64},
        content_type='application/json'
    )
    
    client.get('/logout')
    
    # after logout dashboard should redirect to login
    response = client.get('/dashboard')
    assert response.status_code == 302

# Test 8: Invalid delete index returns 400
def test_invalid_delete_index(client):
    key_b64 = get_test_key()
    client.post('/login',
        json={"key": key_b64},
        content_type='application/json'
    )
    
    # try to delete index 99 when vault is empty
    response = client.post('/delete',
        json={"index": 99},
        content_type='application/json'
    )
    assert response.status_code == 400