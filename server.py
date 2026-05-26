"""
IAS 102 - Day 3 - Lab 1: Padding Oracle Lab
=============================================
VULNERABLE SERVER (server.py)

This server is DELIBERATELY broken to teach how padding oracle attacks work.
It encrypts a secret message with AES-CBC and exposes a /decrypt endpoint
that leaks information about whether the padding is valid.

In a real production server, this leakage would let an attacker recover
the plaintext WITHOUT knowing the key.

DO NOT USE THIS CODE IN PRODUCTION. It is intentionally vulnerable.
Only run it on localhost for educational purposes.

USAGE:
    pip install flask cryptography
    python server.py
"""

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import binascii

app = Flask(__name__)

# ============================================================
# Setup — runs ONCE when the server starts
# ============================================================
# The "secret" key the attacker is trying to defeat.
# In a real system, this would be hidden from everyone.
KEY = os.urandom(16)  # 128-bit AES key

# The secret message we want to protect.
# The attacker will recover this without ever seeing the key.
SECRET_MESSAGE = b"The IAS102 lab works! Password is pizza42"


def pad(data):
    """PKCS#7 padding: add bytes to make length a multiple of 16."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    """Remove PKCS#7 padding. Raises ValueError if padding is invalid."""
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError("Invalid block size")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length")
    # All padding bytes must equal pad_len
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def encrypt(plaintext):
    """Encrypt plaintext with AES-CBC and a random IV."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pad(plaintext)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV so receiver can decrypt


def decrypt(blob):
    """Decrypt blob (IV + ciphertext) with AES-CBC. Raises on bad padding."""
    iv = blob[:16]
    ciphertext = blob[16:]
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded)  # Will raise if padding is bad


# ============================================================
# Endpoints
# ============================================================
@app.route("/")
def home():
    return """
    <h2>IAS 102 - Padding Oracle Lab Server</h2>
    <p>This server is DELIBERATELY VULNERABLE for educational use.</p>
    <ul>
      <li>GET <code>/get_ciphertext</code> &mdash; receive the encrypted secret</li>
      <li>POST <code>/decrypt</code> &mdash; submit ciphertext for decryption (the vulnerable oracle)</li>
    </ul>
    <p>Run <code>attack.py</code> to attempt recovery of the plaintext.</p>
    """


@app.route("/get_ciphertext")
def get_ciphertext():
    """Give the attacker the encrypted secret message to attack."""
    blob = encrypt(SECRET_MESSAGE)
    return jsonify({"ciphertext_hex": binascii.hexlify(blob).decode()})


@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    """
    THE VULNERABLE ORACLE.

    This endpoint accepts a hex-encoded blob, attempts to decrypt it,
    and returns DIFFERENT error messages depending on what failed.

    The vulnerability is the distinguishable error messages. A real
    secure implementation would return identical errors for all failures.
    """
    try:
        blob_hex = request.json.get("ciphertext_hex", "")
        blob = binascii.unhexlify(blob_hex)
    except Exception:
        return jsonify({"status": "error", "message": "invalid hex"}), 400

    try:
        plaintext = decrypt(blob)
        # In a real app, we'd check a MAC here. We don't, on purpose.
        return jsonify({"status": "ok", "message": "decryption successful"}), 200
    except ValueError as e:
        # *** THE BUG ***
        # Returning the specific error message leaks padding validity.
        # An attacker uses this to slowly recover the plaintext.
        return jsonify({"status": "error", "message": str(e)}), 400


# ============================================================
# Run the server
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("IAS 102 Padding Oracle Lab - VULNERABLE SERVER")
    print("=" * 60)
    print(f"[+] Random AES-128 key generated (hidden from attacker)")
    print(f"[+] Secret message length: {len(SECRET_MESSAGE)} bytes")
    print(f"[+] Listening on http://127.0.0.1:5000")
    print(f"[+] Press CTRL+C to stop")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
