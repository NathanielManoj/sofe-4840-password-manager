import sys
import os
from cryptography.exceptions import InvalidTag
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.crypto_engine import generate_salt, derive_key, encrypt, decrypt
#  The `test_encrypt_decrypt_roundtrip` function tests that encrypting a plaintext message and then decrypting it with the same key returns the original message, ensuring that the encryption and decryption functions work correctly together.
def test_encrypt_decrypt_roundtrip():
  
    password = "TestPassword123!"
    salt = generate_salt()
    key = derive_key(password, salt)
    original_message = b"hello this is a secret message"

 
    ciphertext, iv = encrypt(original_message, key)
    decrypted = decrypt(ciphertext, key, iv)


    assert decrypted == original_message
    
    from cryptography.exceptions import InvalidTag
# The `test_wrong_key_fails` function tests that using the wrong key to decrypt a ciphertext results in an `InvalidTag` exception, ensuring that decryption fails when the key is incorrect.
def test_wrong_key_fails():

    salt = generate_salt()
    correct_key = derive_key("CorrectPassword123!", salt)
    wrong_key = derive_key("WrongPassword123!", salt)
    message = b"secret message"


    ciphertext, iv = encrypt(message, correct_key)


    try:
        decrypt(ciphertext, wrong_key, iv)
        assert False, "Should have raised InvalidTag"
    except InvalidTag:
        pass 
    # The `test_tampered_ciphertext_fails` function tests that tampering with the ciphertext (e.g., flipping a bit) causes decryption to fail with an `InvalidTag` exception, ensuring the integrity of the encrypted data.
def test_tampered_ciphertext_fails():
   
    salt = generate_salt()
    key = derive_key("TestPassword123!", salt)
    message = b"secret message"


    ciphertext, iv = encrypt(message, key)


    tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]


    try:
        decrypt(tampered, key, iv)
        assert False, "Should have raised InvalidTag"
    except InvalidTag:
        pass
    
    # The `test_iv_is_unique` function tests that encrypting the same message twice with the same key produces different IVs and ciphertexts, ensuring that the encryption is non-deterministic.
def test_iv_is_unique():
    
    salt = generate_salt()
    key = derive_key("TestPassword123!", salt)
    message = b"same message"


    ciphertext1, iv1 = encrypt(message, key)
    ciphertext2, iv2 = encrypt(message, key)

    assert iv1 != iv2
    assert ciphertext1 != ciphertext2
    
    # The `test_derive_key_is_deterministic` function tests that deriving a key from the same password and salt produces the same key, ensuring that the key derivation is deterministic.
def test_derive_key_is_deterministic():
    
    password = "TestPassword123!"
    salt = generate_salt()


    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)

  
    assert key1 == key2