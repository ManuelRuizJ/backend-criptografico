import hashlib
import base64
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa
from cryptography.hazmat.primitives import serialization

# ---------------- HASHING ----------------

def hash_sha256(text: str) -> str:
    h = hashlib.sha256(text.encode()).hexdigest()
    return h

def hash_argon2(password: str) -> str:
    # Para simplificar, usamos argon2_cffi si se instala
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    return ph.hash(password)

# ---------------- AES-256-CBC ----------------
def aes_encrypt_bytes(data: bytes, key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Padding simple PKCS7
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len])*pad_len
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt_bytes(data: bytes, key: bytes):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# ---------------- RSA ----------------
def generar_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(message: bytes, public_key) -> bytes:
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ---------------- DSA ----------------
def generar_dsa_keys():
    private_key = dsa.generate_private_key(
        key_size=1024,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def dsa_sign(message: bytes, private_key) -> bytes:
    return private_key.sign(message, hashes.SHA256())

def dsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(signature, message, hashes.SHA256())
        return True
    except:
        return False
