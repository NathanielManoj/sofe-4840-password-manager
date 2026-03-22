import pytest
import os
import sys
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.vault_manager import save_vault, load_vault, vault_exists, VAULT_PATH
from backend.crypto_engine import generate_salt, derive_key

TEST_VAULT_PATH = "vault/test_vault.json"

@pytest.fixture
def setup_vault(monkeypatch):
    monkeypatch.setattr('backend.vault_manager.VAULT_PATH', TEST_VAULT_PATH)
    yield
    if os.path.exists(TEST_VAULT_PATH):
        os.remove(TEST_VAULT_PATH)

def test_save_vault_creates_file(setup_vault):
    password = "TestPassword123!"
    salt = generate_salt()
    key = derive_key(password, salt)
    credentials = [{"service": "Netflix", 
                    "username": "test@test.com", 
                    "password": "pass123"}]
    
    save_vault(credentials, key)
    
    assert vault_exists() == True

def test_load_vault_returns_credentials(setup_vault):
    password = "TestPassword123!"
    salt = generate_salt()
    key = derive_key(password, salt)
    credentials = [{"service": "Netflix", 
                    "username": "test@test.com", 
                    "password": "pass123"}]
    
    save_vault(credentials, key)
    loaded = load_vault(key)
    
    assert loaded == credentials

def test_wrong_key_returns_none(setup_vault):
    salt = generate_salt()
    correct_key = derive_key("CorrectPassword123!", salt)
    wrong_key = derive_key("WrongPassword123!", salt)
    credentials = [{"service": "Netflix", 
                    "username": "test", 
                    "password": "pass"}]
    
    save_vault(credentials, correct_key)
    result = load_vault(wrong_key)
    
    assert result is None

def test_salt_preserved_between_saves(setup_vault):
    salt = generate_salt()
    key = derive_key("TestPassword123!", salt)
    credentials1 = [{"service": "Netflix", 
                     "username": "test", 
                     "password": "pass"}]
    credentials2 = [{"service": "Netflix", 
                     "username": "test", 
                     "password": "pass"},
                    {"service": "Gmail", 
                     "username": "test2", 
                     "password": "pass2"}]
    
    save_vault(credentials1, key)
    with open(TEST_VAULT_PATH) as f:
        first_salt = json.load(f)['salt']
    
    save_vault(credentials2, key)
    with open(TEST_VAULT_PATH) as f:
        second_salt = json.load(f)['salt']
    
    assert first_salt == second_salt

def test_vault_exists(setup_vault):
    salt = generate_salt()
    key = derive_key("TestPassword123!", salt)
    credentials = []
    
    assert vault_exists() == False
    
    save_vault(credentials, key)
    assert vault_exists() == True