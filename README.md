"# backend-criptografico"

# Crypto Service – FastAPI

Servicio de criptografía desarrollado con FastAPI, implementa funciones de hashing, verificación, cifrado simétrico (AES), cifrado asimétrico (RSA) y firmas digitales (DSA).

Incluye 10 endpoints funcionales.

---

## Requisitos

- Python 3.10+
- Pip
- FastAPI
- Uvicorn

---

## Ejecución

```bash
uvicorn main:app --reload
```

Accede a la documentación interactiva en:

```
http://127.0.0.1:8000/docs
```

## Endpoints y seguridad

### 1️⃣ SHA-256

**POST** `/api/hash/sha256`  
**Descripción:** Genera el hash SHA-256 de un texto.  
**Seguridad:** SHA-256 es rápido y resistente a colisiones, pero no es recomendable para almacenar contraseñas porque es susceptible a ataques de fuerza bruta con hardware moderno.

**Request Body:**

```json
{
  "texto": "Hola"
}
```

**Response:**

```json
{
  "hash": "e633f4fc79badea1dc5db970cf397c8248bac47cc3acf9915ba60b5d76b0e88f"
}
```

---

### 2️⃣ Argon2

**POST** `/api/hash/argon2`  
**Descripción:** Genera hash seguro para contraseñas.  
**Seguridad:** Argon2 es resistente a ataques de GPU y ASIC, configurable en memoria, tiempo y paralelismo. Por esto es más seguro que SHA-256 para contraseñas.

**Request Body:**

```json
{
  "texto": "Hola"
}
```

**Response:**

```json
{
  "hash": "$argon2id$v=19$m=65536,t=3,p=4$9yXg0TQtgLQ+aaPj6+HTJg$tHW/K+Mo+lphBR/mMBLF+YUIaXjytzNA3LPwB+gzMGs"
}
```

---

### 3️⃣ Verificar Argon2

**POST** `/api/hash/argon2/verify`  
**Descripción:** Verifica si un texto coincide con un hash Argon2.

**Request Body:**

```json
{
  "texto": "Hola",
  "hash_b64": "$argon2id$v=19$m=65536,t=3,p=4$9yXg0TQtgLQ+aaPj6+HTJg$tHW/K+Mo+lphBR/mMBLF+YUIaXjytzNA3LPwB+gzMGs"
}
```

**Response:**

```json
{
  "valido": true
}
```

---

### 4️⃣ AES-CBC Cifrar

**POST** `/api/encrypt/aes_cbc`  
**Descripción:** Cifra un texto en Base64 usando AES-CBC.  
**Seguridad:** AES es ampliamente usado, seguro y más rápido que DES. DES tiene solo 56 bits de clave, vulnerable a ataques de fuerza bruta.

**Request Body:**

```json
{
  "key_b64": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
  "texto_b64": "SG9sYQ=="
}
```

**Response:**

```json
{
  "ciphertext_b64": "APry/lGI6F5I72mIFVHEjbkVWsDXsML1gZDMfFGYITw="
}
```

---

### 5️⃣ AES-CBC Descifrar

**POST** `/api/decrypt/aes_cbc`

**Request Body:**

```json
{
  "key_b64": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
  "texto_b64": "APry/lGI6F5I72mIFVHEjbkVWsDXsML1gZDMfFGYITw="
}
```

**Response:**

```json
{
  "texto_b64": "SG9sYQ=="
}
```

---

### 6️⃣ RSA Cifrar

**POST** `/api/encrypt/rsa`  
**Seguridad:** RSA permite cifrado asimétrico, ideal para intercambio de claves y mensajes cortos. Se basa en la dificultad de factorizar números grandes.

**Request Body:**

```json
{
  "mensaje_b64": "SG9sYQ=="
}
```

**Response:**

```json
{
  "ciphertext_b64": "kORBO4LwB1tZP..."
}
```

---

### 7️⃣ RSA Descifrar

**POST** `/api/decrypt/rsa`

**Request Body:**

```json
{
  "mensaje_b64": "kORBO4LwB1tZP..."
}
```

**Response:**

```json
{
  "mensaje_b64": "SG9sYQ=="
}
```

---

### 8️⃣ Firmar DSA

**POST** `/api/sign/dsa`  
**Seguridad:** DSA asegura la autenticidad de un mensaje. No cifra el contenido, solo crea una firma digital basada en claves privadas.

**Request Body:**

```json
{
  "mensaje_b64": "SG9sYQ=="
}
```

**Response:**

```json
{
  "firma_b64": "MEQCIFAkvepPps5VaUw4XbAqqw8XmeX3ZiCkw1+MgH/XugEKAiAvClzj+SkdMaUnVp9ejC4Gu/l6HdplcLK0tKdRxT76Xw=="
}
```

---

### 9️⃣ Verificar DSA

**POST** `/api/verify/dsa`

**Request Body:**

```json
{
  "mensaje_b64": "SG9sYQ==",
  "firma_b64": "MEQCIFAkvepPps5VaUw4XbAqqw8XmeX3ZiCkw1+MgH/XugEKAiAvClzj+SkdMaUnVp9ejC4Gu/l6HdplcLK0tKdRxT76Xw=="
}
```

**Response:**

```json
{
  "valido": true
}
```

---

## Esquemas de Request

- `AESRequest`
- `DSASignRequest`
- `DSAVerifyRequest`
- `HashRequest`
- `RSARequest`
- `VerifyHashRequest`
- `HTTPValidationError`
- `ValidationError`

---

**Notas de seguridad generales:**

- **SHA-256:** Es un algoritmo de hash rápido y ampliamente usado que genera un resumen de 256 bits a partir de cualquier entrada. Es resistente a colisiones y modificaciones accidentales, pero no es ideal para almacenar contraseñas directamente porque, al ser muy rápido, los atacantes pueden realizar ataques de fuerza bruta o de diccionario usando hardware moderno muy eficiente. Se usa principalmente para integridad de datos y firmas digitales.

- **Argon2:** Es un algoritmo de hash diseñado específicamente para contraseñas. Es resistente a ataques de fuerza bruta realizados con GPUs o ASICs gracias a su consumo de memoria configurable y su paralelismo ajustable. Esto lo hace mucho más seguro que SHA-256 para proteger contraseñas. Además, permite ajustar la dificultad según la capacidad del servidor, haciendo más costoso para un atacante intentar romper los hashes.

- **AES-CBC:** AES (Advanced Encryption Standard) en modo CBC es un cifrado simétrico moderno y seguro. Proporciona confidencialidad de datos y es eficiente tanto en software como en hardware. Se prefiere sobre DES porque DES tiene solo 56 bits de clave, lo que lo hace vulnerable a ataques de fuerza bruta. AES permite claves de 128, 192 o 256 bits, aumentando significativamente la seguridad frente a ataques actuales.

- **RSA:** Es un algoritmo de cifrado asimétrico que utiliza un par de claves (pública y privada). Permite cifrar datos de forma que solo quien tenga la clave privada pueda descifrarlos. RSA se basa en la dificultad de factorizar números grandes, lo que lo hace seguro para el intercambio de claves y para cifrar mensajes cortos. Es ampliamente usado en protocolos como TLS/SSL para proteger la comunicación en Internet.

- **DSA:** Digital Signature Algorithm se utiliza para crear firmas digitales que verifican la autenticidad e integridad de un mensaje. No cifra el contenido, sino que permite al receptor comprobar que el mensaje proviene realmente del remitente y que no ha sido alterado. Es una herramienta clave en sistemas que requieren validación de identidad y seguridad en la transmisión de datos.
