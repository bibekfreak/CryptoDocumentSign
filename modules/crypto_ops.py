import os, json, base64, struct
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def sign_document(document_path, key_path):
    with open(document_path, 'rb') as f:
        data = f.read()

    with open(key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signed_path = document_path + '.sig'
    with open(signed_path, 'wb') as f:
        f.write(signature)
    return signed_path

def encrypt_document_hybrid(doc_path, recipient_list, output_filename=None):
    aes_key = os.urandom(32)
    with open(doc_path, 'rb') as f:
        doc_data = f.read()

    padder = sym_padding.PKCS7(128).padder()
    padded_doc = padder.update(doc_data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_doc = encryptor.update(padded_doc) + encryptor.finalize()

    final_name = output_filename if output_filename else os.path.basename(doc_path)
    encrypted_doc_path = os.path.join('encrypted_docs', final_name + '.enc')

    key_bundle = {}
    for email, cert_path in recipient_list:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        pub_key = cert.public_key()
        encrypted_key = pub_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        key_bundle[email] = base64.b64encode(encrypted_key).decode('utf-8')

    key_bundle["__original_filename__"] = final_name

    with open(encrypted_doc_path, 'wb') as f:
        bundle_json = json.dumps(key_bundle).encode('utf-8')
        f.write(struct.pack('>I', len(bundle_json)))  # 4 bytes
        f.write(bundle_json)
        f.write(iv)
        f.write(encrypted_doc)

    return encrypted_doc_path

def append_signature_metadata(doc_path, cert_path, sig_path):
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        subject = cert.subject
        common_name_attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name_attrs[0].value if common_name_attrs else "Unknown"
        email_attrs = subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        email = email_attrs[0].value if email_attrs else "Not provided"
        metadata = {
            'common_name': common_name,
            'email': email,
            'timestamp': datetime.utcnow().isoformat(),
            'signature_path': sig_path
        }

    meta_path = doc_path + '.signatures.json'
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            signatures = json.load(f)
    else:
        signatures = []
    signatures.append(metadata)
    with open(meta_path, 'w') as f:
        json.dump(signatures, f, indent=4)