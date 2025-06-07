import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from werkzeug.utils import secure_filename
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_with_rsa(public_key, data):
    encrypted = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def encrypt_file(file, algorithm, upload_folder):
    try:
        file_data = file.read()
        original_filename = secure_filename(file.filename)

        if algorithm == 'AES-256':
            key = os.urandom(32)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
        elif algorithm == 'TripleDES':
            key = os.urandom(24)
            iv = os.urandom(8)
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        elif algorithm == 'RSA':
            private_key, public_key = generate_rsa_keys()
            encrypted_data = encrypt_with_rsa(public_key, file_data)
            encrypted_filename = f'encrypted_{original_filename}'
            encrypted_file_path = os.path.join(upload_folder, encrypted_filename)
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
            return encrypted_file_path, private_key
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        padded_data = padder.update(file_data) + padder.finalize()
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_filename = f'encrypted_{original_filename}'
        encrypted_file_path = os.path.join(upload_folder, encrypted_filename)

        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + encrypted_data)

        return encrypted_file_path, key.hex()
    except Exception as e:
        logging.error(f"Encryption failed: {str(e)}")
        raise 