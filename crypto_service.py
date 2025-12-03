import base64
from hashlib import sha256
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import PasswordHasher
import os

# =======================================================
# ====================== HASHES ==========================
# =======================================================

ph = PasswordHasher()

def hash_sha256(texto: str) -> str:
    return sha256(texto.encode()).hexdigest()

def hash_argon2(texto: str) -> str:
    return ph.hash(texto)

def verify_argon2(texto: str, hash_value: str) -> bool:
    try:
        ph.verify(hash_value, texto)
        return True
    except Exception:
        return False


# =======================================================
# ======================== AES ===========================
# =======================================================

def aes_encrypt_bytes(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # PKCS7 padding
    padding_len = 16 - (len(data) % 16)
    data += bytes([padding_len]) * padding_len

    return encryptor.update(data) + encryptor.finalize()


def aes_decrypt_bytes(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    padding_len = data[-1]
    return data[:-padding_len]


# =======================================================
# ========================= RSA ==========================
# =======================================================

def generar_rsa_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public = private.public_key()
    return private, public

def rsa_encrypt(data: bytes, public_key):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(ciphertext: bytes, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# =======================================================
# ========================== DSA =========================
# =======================================================

def generar_dsa_keys():
    private = dsa.generate_private_key(key_size=2048)
    public = private.public_key()
    return private, public

def dsa_sign(data: bytes, private_key):
    return private_key.sign(
        data,
        hashes.SHA256()
    )

def dsa_verify(data: bytes, signature: bytes, public_key):
    try:
        public_key.verify(signature, data, hashes.SHA256())
        return True
    except Exception:
        return False
