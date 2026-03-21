# crypto_engine.py
# Nathaniel Manoj 100817043
# SOFE 4840U - Computer Security
# This module provides functions for generating salts, deriving keys from passwords, and encrypting/decrypting data using AES-GCM.
# It uses the `cryptography` library for AES-GCM encryption and decryption, and the `hashlib` library for key derivation using PBKDF2.
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# The `generate_salt` function generates a random salt using `os.urandom`.
def generate_salt():
    return os.urandom(16)

# The `derive_key` function derives a key from a password and salt using PBKDF2 with HMAC-SHA256, 600,000 iterations, and a key length of 32 bytes (256 bits).
def derive_key(password, salt):
    return hashlib.pbkdf2_hmac(
    'sha256',
    password.encode('utf-8'),
    salt,
    600000,
    dklen=32
    )

def encrypt(plaintext, key):
# plaintext is expected to be bytes, and key is expected to be a 32-byte key derived from the `derive_key` function.
# generating IV using os.urandom
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return ciphertext, iv
    
def decrypt(ciphertext, key, iv):
# ciphertext is expected to be bytes, key is expected to be a 32-byte key derived from the `derive_key` function, and iv is expected to be a 12-byte initialization vector.
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext
    
