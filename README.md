# 🔐 PKISecureSignApp

**PKISecureSignApp** is a secure Flask-based web application for digitally signing, encrypting, verifying, decrypting, and co-signing documents using **Public Key Infrastructure (PKI)**.

This platform ensures confidentiality, integrity, and authenticity of legal documents shared between multiple parties.

---

## 🚀 Use Case

### ✍️ Legal Contract Signing

- A user uploads and signs a legal document using their **private key**.
- The document is **encrypted** and shared with specified recipients.
- Each recipient:
  - Verifies their access
  - Decrypts and views the document
  - **Co-signs** the document
- The final `.enc` file includes all valid signatures — proving mutual agreement.

---

## ✅ Core Features

### 🔐 Secure Login

- Authenticate using your **email** and **private RSA key**.
- Ensures user authenticity with no passwords and private keys stored.

### ✍️ Sign & Encrypt Documents

- Sign uploaded PDF files using your private key.
- Encrypt the document with a symmetric AES key.
- AES key is encrypted per recipient using their public certificates.
- Final `.enc` file is downloaded for secure sharing.

### ✅ Verify, Decrypt & Co-sign

- Recipients upload the encrypted file and their private key.
- The app:
  - Verifies access rights and document integrity
  - Decrypts content
  - Allows co-signing if verification passes
- A new `.enc` is generated with additional signatures.

---

## 🔐 Cryptographic Standards

| Operation        | Technique                        |
| ---------------- | -------------------------------- |
| Digital Signing  | RSA with SHA-256 and PSS padding |
| Symmetric Crypto | AES-256 in CBC mode              |
| Key Encryption   | RSA with OAEP and SHA-256        |
| Certificate Type | X.509 (PEM format)               |

---

## 🔮 Future Enhancements

- 📂 **Dashboard for Shared Files**  
  View files shared with you, decrypt, and co-sign directly from the dashboard.

- 🖋️ **Editable Document Collaboration**  
  After decryption, allow inline edits and re-signing.

- 📬 **Notifications**  
  Get alerts when a file is signed, shared, or awaiting your signature.

- 🧾 **Audit Trail & Logs**  
  Keep track of who signed, when, and ensure non-repudiation.

---

## 🛠️ Setup & Deployment

### 🔧 Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the Flask app
python app.py
```

### 🐳 Docker Deployment

```bash
# Build and run using Docker
docker-compose up --build
```

Visit the app at: `http://localhost:5000`

---

## 🧪 Security Notes

- Private keys are **not stored** on the server.
- Uploaded keys are used in-memory for signing or decryption only.
- For production: integrate CA-based certificate validation, revocation checks (CRL/OCSP), and audit logging.

---
