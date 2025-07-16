import os
import uuid
import io
import sqlite3
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_key_pair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def generate_certificate(private_key, username, email):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    cert_builder = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(int(uuid.uuid4().int >> 64))\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))

    certificate = cert_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return certificate

def register_user(username, email):
    # Check if user already exists
    conn = sqlite3.connect('pki_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    existing = cursor.fetchone()
    if existing:
        conn.close()
        raise ValueError(f"User with email'{email}' already exists")

    # Proceed with key/cert generation
    key = generate_key_pair()
    cert = generate_certificate(key, username, email)

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    cert_path = f'uploads/{username}_cert.pem'
    with open(cert_path, 'wb') as f:
        f.write(cert_bytes)

    # Insert into DB
    cursor.execute(
        'INSERT INTO users (username, email, cert_path) VALUES (?, ?, ?)',
        (username, email, cert_path)
    )
    conn.commit()
    conn.close()

    key_stream = io.BytesIO(key_bytes)
    key_stream.seek(0)

    return cert_path, key_stream

def authenticate_user(email, key_path):
    conn = sqlite3.connect('pki_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, cert_path FROM users WHERE email = ?', (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    username, cert_path = row

    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        # Match public key in cert and private key
        cert_pubkey = cert.public_key()
        if cert_pubkey.public_numbers() == private_key.public_key().public_numbers():
            return {'username': username, 'email': email}
    except Exception as e:
        print(f"[AUTH ERROR] {e}")
    
    return None

