import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_salt():
    return os.urandom(16)
