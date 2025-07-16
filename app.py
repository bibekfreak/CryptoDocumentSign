from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
from werkzeug.utils import secure_filename
import os
import json
import base64
import sqlite3
from modules.auth import register_user, authenticate_user
from modules.crypto_ops import (
    sign_document,
    encrypt_document_hybrid,
    append_signature_metadata
)
from modules.db import init_db
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import logging
import struct
app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
app.secret_key = 'secure-app-secret'
UPLOAD_FOLDER = 'uploads'
SIGNED_FOLDER = 'signed_docs'
ENCRYPTED_FOLDER = 'encrypted_docs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)


@app.route('/health')
def health():
    return jsonify({"status": "ok"}), 200

def allowed_file(filename):
    return '.' in filename and filename.lower().endswith('.pdf')

def generate_unique_filename(original_name, user_email):
    name, ext = os.path.splitext(original_name)
    safe_email = user_email.replace('@', '_at_').replace('.', '_dot_')
    
    if f"__{safe_email}" in name:
        return f"{name}{ext}"
    
    return f"{name}__{safe_email}{ext}"



@app.route('/')
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login_page'))

    show_flash = session.pop('show_flash', None)
    if show_flash:
        flash(show_flash, 'success')

    return render_template('dashboard.html', user={
        'username': session['username'],
        'email': session['user_email']
    })



@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email']
        key_file = request.files['private_key']

        if not email or not key_file:
            flash("Email and private key are required.", "danger")
            return redirect(url_for('login_page'))

        key_path = os.path.join(UPLOAD_FOLDER, secure_filename(key_file.filename))
        key_file.save(key_path)

        user = authenticate_user(email, key_path)
        os.remove(key_path)  

        if user:
            session['user_email'] = user['email']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))  

        flash("Authentication failed. Invalid credentials.", "danger")
        return redirect(url_for('login_page'))

    session.pop('download_key', None)
    session.pop('download_filename', None)
    return render_template('index.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        try:
            cert_path, key_stream = register_user(username, email)

            key_data = key_stream.read()
            session['download_filename'] = f"{username}_private_key.pem"
            session['download_key'] = base64.b64encode(key_data).decode()

            flash("Registration successful. Your key will now download.", "success")
            
            return render_template('index.html', auto_download=True)

        except ValueError as ve:
            flash(str(ve), "danger")
            return redirect(url_for('register'))
    return render_template('register.html')



@app.route('/download-key')
def download_key():
    filename = request.args.get('file')
    if not filename:
        return "Missing file parameter", 400

    paths = [
        os.path.join(UPLOAD_FOLDER, filename),
        os.path.join(ENCRYPTED_FOLDER, filename),
        os.path.join(SIGNED_FOLDER, filename)
    ]

    for path in paths:
        if os.path.exists(path):
            display_name = filename
            if '__' in filename:
                name_part, ext = filename.split('.enc')[0], '.enc'
                if '__' in name_part:
                    name_part = name_part.split('__')[0]
                    display_name = name_part + ext
            return send_file(path, as_attachment=True, download_name=display_name)

    return "File not found", 404

@app.route('/users', methods=['GET'])
def get_users():
    conn = sqlite3.connect('pki_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, email FROM users')
    users = [{'username': row[0], 'email': row[1]} for row in cursor.fetchall()]
    conn.close()
    return jsonify(users), 200


@app.route('/sign-encrypt', methods=['POST'])
def sign_encrypt():
    document = request.files.get("document")
    if not document or not allowed_file(document.filename):
        flash("Please upload a valid .pdf file.", "danger")
        return redirect(url_for("dashboard"))

    if 'user_email' not in session:
        flash("You must be logged in.", "danger")
        return redirect(url_for('login_page'))

    email = session['user_email']
    username = session['username']
    user_key = request.files['user_key']
    doc = request.files['document']
    selected_emails = request.form.getlist('recipients')

    if not user_key or not doc or not selected_emails:
        flash("All fields are required.", "danger")
        return redirect(url_for('dashboard'))

    if email not in selected_emails:
        selected_emails.append(email)

    key_path = os.path.join(UPLOAD_FOLDER, secure_filename(user_key.filename))
    doc_path = os.path.join(UPLOAD_FOLDER, secure_filename(doc.filename))
    user_key.save(key_path)
    doc.save(doc_path)

    conn = sqlite3.connect('pki_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT cert_path FROM users WHERE email = ?', (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        flash("Could not find sender certificate.", "danger")
        os.remove(key_path)
        return redirect(url_for('dashboard'))

    sender_cert_path = row[0]

    try:
        with open(sender_cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            pubkey_from_cert = cert.public_key()

        with open(key_path, 'rb') as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            pubkey_from_key = priv_key.public_key()

        if pubkey_from_key.public_numbers() != pubkey_from_cert.public_numbers():
            os.remove(key_path)
            flash("The uploaded private key does not belong to the logged-in user.", "danger")
            return redirect(url_for('dashboard'))

    except Exception as e:
        os.remove(key_path)
        flash("Error validating private key: " + str(e), "danger")
        return redirect(url_for('dashboard'))

    final_encrypted_name = generate_unique_filename(doc.filename, email)
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, final_encrypted_name + '.enc')
    if os.path.exists(encrypted_path):
        flash(f"A file named '{doc.filename}' already exists for your account.", "danger")
        return redirect(url_for('dashboard'))

    signed_path = sign_document(doc_path, key_path)
    append_signature_metadata(doc_path, sender_cert_path, signed_path)

    conn = sqlite3.connect('pki_users.db')
    cursor = conn.cursor()
    placeholders = ', '.join(['?'] * len(selected_emails))
    cursor.execute(f'SELECT email, cert_path FROM users WHERE email IN ({placeholders})', tuple(selected_emails))
    recipients = cursor.fetchall()
    conn.close()

    encrypted_path = encrypt_document_hybrid(
        doc_path,
        recipients,
        output_filename=final_encrypted_name
    )

    os.remove(key_path)
    session['download_filename'] = os.path.basename(encrypted_path)
    session['show_flash'] = "Document signed and encrypted successfully."
    return redirect(url_for('dashboard'))


@app.route('/decrypt-preview', methods=['POST'])
def decrypt_preview():
    if 'user_email' not in session:
        flash("Login required.", "danger")
        return redirect(url_for('login_page'))

    email = session['user_email']
    user_key = request.files['user_key']
    encrypted_file = request.files['encrypted_file']

    if not user_key or not encrypted_file:
        flash('Missing required fields.', "danger")
        return redirect(url_for('dashboard', tab='decrypt'))

    encrypted_path = os.path.join(ENCRYPTED_FOLDER, secure_filename(encrypted_file.filename))
    key_path = os.path.join(UPLOAD_FOLDER, secure_filename(user_key.filename))
    encrypted_file.save(encrypted_path)
    user_key.save(key_path)

    conn = sqlite3.connect('pki_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT cert_path FROM users WHERE email = ?', (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        os.remove(key_path)
        flash("User certificate not found.", "danger")
        return redirect(url_for('dashboard', tab='decrypt'))

    cert_path = row[0]
    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), None, backend=default_backend())

        if private_key.public_key().public_numbers() != cert.public_key().public_numbers():
            os.remove(key_path)
            flash("Private key does not match the user's certificate.", "danger")
            return redirect(url_for('dashboard', tab='decrypt'))
    except Exception as e:
        os.remove(key_path)
        flash("Key validation failed: " + str(e), "danger")
        return redirect(url_for('dashboard', tab='decrypt'))

    try:
        import struct
        with open(encrypted_path, 'rb') as f:
            bundle_len_bytes = f.read(4)
            bundle_len = struct.unpack('>I', bundle_len_bytes)[0]
            bundle_json = f.read(bundle_len)
            bundle = json.loads(bundle_json.decode('utf-8'))
            iv = f.read(16)
            ciphertext = f.read()
    except Exception as e:
        os.remove(key_path)
        flash("Failed to read embedded key bundle: " + str(e), "danger")
        return redirect(url_for('dashboard', tab='decrypt'))

    if email not in bundle:
        os.remove(key_path)
        flash(f"You don't have permission to decrypt this resource.", "danger")
        return redirect(url_for('dashboard', tab='decrypt'))

    try:
        encrypted_aes_key = base64.b64decode(bundle[email])
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        os.remove(key_path)
        flash("Failed to decrypt AES key: " + str(e), "danger")
        return redirect(url_for('dashboard', tab='decrypt'))

    try:
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except Exception as e:
        os.remove(key_path)
        flash("Decryption failed: " + str(e), "danger")
        return redirect(url_for('dashboard', tab='decrypt'))

    preview_filename = os.path.splitext(encrypted_file.filename)[0] + "_preview.pdf"
    preview_path = os.path.join("static", "temp", preview_filename)
    os.makedirs(os.path.dirname(preview_path), exist_ok=True)
    with open(preview_path, 'wb') as f:
        f.write(plaintext)

    session["decrypted_file"] = preview_filename
    session["decryption_cert"] = cert_path
    session["decryption_key"] = key_path
    session["original_enc_file"] = encrypted_path

    flash("File decrypted. Ready for review and co-signing.", "success")
    return redirect(url_for('dashboard', tab='decrypt'))


@app.route('/co-sign', methods=['POST'])
def co_sign():
    if 'user_email' not in session:
        flash("Login required.", "danger")
        return redirect(url_for('login_page'))

    email = session['user_email']
    decrypted_file = session.get("decrypted_file")
    cert_path = session.get("decryption_cert")
    key_path = session.get("decryption_key")
    enc_file_path = session.get("original_enc_file")

    if not decrypted_file or not cert_path or not key_path or not enc_file_path:
        flash("Missing session data for co-signing.", "danger")
        return redirect(url_for('dashboard', tab='decrypt'))

    decrypted_path = os.path.join("static", "temp", decrypted_file)

    try:
        import struct
        with open(enc_file_path, 'rb') as f:
            bundle_len = struct.unpack('>I', f.read(4))[0]
            bundle = json.loads(f.read(bundle_len).decode())
            original_filename = bundle.get("__original_filename__", f"encrypted_{email}.pdf")

        final_name = generate_unique_filename(original_filename, email)
        output_name = final_name if not final_name.endswith('.pdf') else final_name

        signed_path = sign_document(decrypted_path, key_path)
        append_signature_metadata(decrypted_path, cert_path, signed_path)

        conn = sqlite3.connect('pki_users.db')
        cursor = conn.cursor()
        cert_map = {}
        for rec_email in bundle:
            if rec_email == "__original_filename__":
                continue
            cursor.execute('SELECT cert_path FROM users WHERE email = ?', (rec_email,))
            row = cursor.fetchone()
            if row:
                cert_map[rec_email] = row[0]
        conn.close()

        recipients = [(email, cert) for email, cert in cert_map.items()]

        re_encrypted_path = encrypt_document_hybrid(decrypted_path, recipients, output_filename=output_name)

        session["download_filename"] = os.path.basename(re_encrypted_path)

        session.pop("decrypted_file", None)
        session.pop("decryption_cert", None)
        session.pop("decryption_key", None)
        session.pop("original_enc_file", None)

        flash("Document co-signed and re-encrypted successfully.", "success")
        return redirect(url_for('dashboard', tab='decrypt'))

    except Exception as e:
        flash("Error during co-signing: " + str(e), "danger")
        return redirect(url_for('dashboard', tab='decrypt'))

@app.route('/clear-download-flag', methods=['POST'])
def clear_download_flag():
    session.pop('download_filename', None)
    return '', 204

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
