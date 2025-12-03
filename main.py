from fastapi import FastAPI
from pydantic import BaseModel
import base64
from crypto_service import (
    hash_sha256, hash_argon2, verify_argon2,
    aes_encrypt_bytes, aes_decrypt_bytes,
    generar_rsa_keys, rsa_encrypt, rsa_decrypt,
    generar_dsa_keys, dsa_sign, dsa_verify
)
import os

app = FastAPI()

# ==========================================================
# ======================== HASHING ==========================
# ==========================================================

class HashRequest(BaseModel):
    texto: str

class VerifyHashRequest(BaseModel):
    texto: str
    hash_b64: str


# 1. SHA256
@app.post("/api/hash/sha256")
def sha256_endpoint(req: HashRequest):
    return {"hash": hash_sha256(req.texto)}


# 2. Argon2 Hash
@app.post("/api/hash/argon2")
def argon2_endpoint(req: HashRequest):
    hash_value = hash_argon2(req.texto)
    return {"hash": hash_value}


# 3. Argon2 Verify
@app.post("/api/hash/argon2/verify")
def argon2_verify_endpoint(req: VerifyHashRequest):
    valido = verify_argon2(req.texto, req.hash_b64)
    return {"valido": valido}


# ==========================================================
# ========================== AES ============================
# ==========================================================

class AESRequest(BaseModel):
    key_b64: str
    texto_b64: str


# 4. AES Encrypt
@app.post("/api/encrypt/aes_cbc")
def encrypt_aes(req: AESRequest):
    key = base64.b64decode(req.key_b64)
    data = base64.b64decode(req.texto_b64)
    iv = os.urandom(16)
    ciphertext = aes_encrypt_bytes(data, key, iv)

    result_b64 = base64.b64encode(iv + ciphertext).decode()
    return {"ciphertext_b64": result_b64}


# 5. AES Decrypt
@app.post("/api/decrypt/aes_cbc")
def decrypt_aes(req: AESRequest):
    key = base64.b64decode(req.key_b64)
    data = base64.b64decode(req.texto_b64)

    iv = data[:16]
    ciphertext = data[16:]

    plaintext = aes_decrypt_bytes(ciphertext, key, iv)

    return {"texto_b64": base64.b64encode(plaintext).decode()}


# ==========================================================
# =========================== RSA ===========================
# ==========================================================

PRIVATE_RSA, PUBLIC_RSA = generar_rsa_keys()

class RSARequest(BaseModel):
    mensaje_b64: str


# 6. RSA Encrypt
@app.post("/api/encrypt/rsa")
def encrypt_rsa(req: RSARequest):
    data = base64.b64decode(req.mensaje_b64)
    ciphertext = rsa_encrypt(data, PUBLIC_RSA)
    return {"ciphertext_b64": base64.b64encode(ciphertext).decode()}


# 7. RSA Decrypt
@app.post("/api/decrypt/rsa")
def decrypt_rsa(req: RSARequest):
    ciphertext = base64.b64decode(req.mensaje_b64)
    plaintext = rsa_decrypt(ciphertext, PRIVATE_RSA)
    return {"mensaje_b64": base64.b64encode(plaintext).decode()}


# ==========================================================
# ============================ DSA ==========================
# ==========================================================

PRIVATE_DSA, PUBLIC_DSA = generar_dsa_keys()

class DSASignRequest(BaseModel):
    mensaje_b64: str

class DSAVerifyRequest(BaseModel):
    mensaje_b64: str
    firma_b64: str


# 8. DSA Sign
@app.post("/api/sign/dsa")
def sign_dsa(req: DSASignRequest):
    data = base64.b64decode(req.mensaje_b64)
    signature = dsa_sign(data, PRIVATE_DSA)
    return {"firma_b64": base64.b64encode(signature).decode()}


# 9. DSA Verify
@app.post("/api/verify/dsa")
def verify_dsa(req: DSAVerifyRequest):
    data = base64.b64decode(req.mensaje_b64)
    signature = base64.b64decode(req.firma_b64)
    valido = dsa_verify(data, signature, PUBLIC_DSA)
    return {"valido": valido}
