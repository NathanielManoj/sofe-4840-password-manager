# vault_manager.py
# Hermon Estifanos 100803620
# SOFE 4840U - Computer Security
# This module provides functions for managing a vault that securely stores user credentials. It uses the `crypto_engine` module for encryption and decryption of the vault data, and it handles saving and loading the vault to and from a file in an encrypted format.
import os
import json
import base64
from backend.crypto_engine import generate_salt, encrypt, decrypt
from cryptography.exceptions import InvalidTag

VAULT_PATH = "vault/vault.json"
# The `vault_exists` function checks if the vault file exists on disk, returning `True` if it does and `False` otherwise.
def vault_exists():
    return os.path.exists(VAULT_PATH)

# The `save_vault` function takes a dictionary of credentials and a key, and it saves the credentials to the vault file in an encrypted format. If the vault file does not exist, it generates a new salt. If the vault file already exists, it reads the existing salt from the file. The credentials are encrypted using AES-GCM, and the salt, IV, and ciphertext are stored in the vault file as base64-encoded strings for JSON serialization.
def save_vault(credentials, key, salt=None):
    if not vault_exists():
        if salt is None:
            salt = generate_salt()
    else:
        with open(VAULT_PATH, 'r') as f:
            vault_data = json.load(f)
            salt = base64.b64decode(vault_data['salt'])

    plaintext = json.dumps(credentials).encode('utf-8')
    ciphertext, iv = encrypt(plaintext, key)
    
    vault_data = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }
    
    os.makedirs(os.path.dirname(VAULT_PATH), exist_ok=True)
    with open(VAULT_PATH, 'w') as f:
        json.dump(vault_data, f)

# The `load_vault` function reads the vault file, decodes the salt, IV, and ciphertext from base64, and attempts to decrypt the vault data using the provided key. If decryption is successful, it returns the credentials as a Python dictionary. If decryption fails (e.g., due to an invalid key), it returns `None`.     
def load_vault(key):

    with open(VAULT_PATH, 'r') as f:
        vault_data = json.load(f)
    # decode iv and ciphertext from base64
    iv = base64.b64decode(vault_data['iv'])
    ciphertext = base64.b64decode(vault_data['ciphertext'])
    # attempt to decrypt and return credentials
    try:
        plaintext = decrypt(ciphertext, key, iv)
        credentials = json.loads(plaintext.decode('utf-8'))
        return credentials
    # if decryption fails (e.g., due to invalid key), return None
    except InvalidTag:
        return None
