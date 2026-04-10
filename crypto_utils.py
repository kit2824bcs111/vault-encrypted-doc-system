import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> str:
    """Generate a new AES-256 key, returned as a base64 string."""
    key = os.urandom(32)  # 256 bits
    return base64.b64encode(key).decode("utf-8")


def encrypt_data(plaintext: str, key_b64: str) -> str:
    """
    Encrypt plaintext using AES-256-GCM.
    Returns base64-encoded (nonce + ciphertext).
    """
    key = base64.b64decode(key_b64)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_data(encrypted_b64: str, key_b64: str) -> str:
    """
    Decrypt AES-256-GCM data.
    Returns original plaintext string.
    """
    key = base64.b64decode(key_b64)
    combined = base64.b64decode(encrypted_b64)
    nonce = combined[:12]
    ciphertext = combined[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
