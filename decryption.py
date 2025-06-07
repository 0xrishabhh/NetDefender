import os
import time
import logging
from flask import send_file, flash, request, render_template, send_from_directory, url_for
from flask_login import login_required
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from utils import allowed_file

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def clean_key(key_hex):
    """Clean and validate the hex key string."""
    # Remove spaces, hyphens, and convert to lowercase
    cleaned = key_hex.replace(' ', '').replace('-', '').lower()
    
    # Validate hex string
    try:
        int(cleaned, 16)
    except ValueError:
        raise ValueError("Invalid key format - must be a valid hex string")
        
    return cleaned

def decrypt_file(file, key_hex, algorithm, upload_folder):
    """
    Decrypt a file using the specified algorithm and key.
    
    Args:
        file: File object to decrypt
        key_hex: Hex string representation of the encryption key
        algorithm: Encryption algorithm used ('AES-256' or 'TripleDES')
        upload_folder: Path to the upload folder
        
    Returns:
        str: Path to the decrypted file
    """
    try:
        logger.debug(f"Starting decryption with algorithm: {algorithm}")
        
        # Validate inputs
        if not file or not file.filename:
            raise ValueError("No file selected")
            
        if not allowed_file(file.filename):
            raise ValueError("Invalid file type")
            
        if algorithm not in ['AES-256', 'TripleDES']:
            raise ValueError("Invalid algorithm selected")
            
        # Clean and validate the key
        cleaned_key = clean_key(key_hex)
        logger.debug(f"Cleaned key length: {len(cleaned_key)}")
        
        try:
            key = bytes.fromhex(cleaned_key)
            logger.debug(f"Key length in bytes: {len(key)}")
        except ValueError as e:
            raise ValueError(f"Invalid key format: {str(e)}")

        # Read file data
        try:
            file_data = file.read()
            logger.debug(f"File data length: {len(file_data)}")
        except Exception as e:
            raise ValueError(f"Error reading file: {str(e)}")
        
        # Extract IV and encrypted data
        iv_size = 16 if algorithm == 'AES-256' else 8
        if len(file_data) < iv_size:
            raise ValueError("File is too short to be a valid encrypted file")
            
        iv = file_data[:iv_size]
        encrypted_data = file_data[iv_size:]
        logger.debug(f"IV size: {len(iv)}, Encrypted data length: {len(encrypted_data)}")

        # Set up decryption
        try:
            if algorithm == 'AES-256':
                if len(key) != 32:
                    raise ValueError("AES-256 requires a 32-byte key")
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            elif algorithm == 'TripleDES':
                if len(key) != 24:
                    raise ValueError("TripleDES requires a 24-byte key")
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
        except Exception as e:
            raise ValueError(f"Error setting up decryption: {str(e)}")
        
        # Perform decryption
        try:
            logger.debug("Starting decryption process")
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            logger.debug("Decryption completed, removing padding")
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
            logger.debug("Padding removed successfully")
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise ValueError(f"Decryption failed - invalid key or corrupted file: {str(e)}")
        
        # Save decrypted file
        timestamp = str(int(time.time()))
        decrypted_filename = f'decrypted_{timestamp}_{os.path.basename(file.filename.replace("encrypted_", ""))}'
        decrypted_file_path = os.path.join(upload_folder, decrypted_filename)
        
        try:
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)
            logger.debug(f"Decrypted file saved to: {decrypted_file_path}")
            return decrypted_file_path
        except Exception as e:
            raise ValueError(f"Error saving decrypted file: {str(e)}")
            
    except ValueError as e:
        raise ValueError(str(e))
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def handle_decryption_routes(app):
    """Register decryption routes with the Flask app"""
    
    @app.route('/decryption', methods=['GET', 'POST'])
    @login_required
    def decryption():
        if request.method == 'POST':
            try:
                # Get form data
                file = request.files.get('file')
                key = request.form.get('key', '').strip()
                algorithm = request.form.get('algorithm')
                
                # Validate inputs
                if not file or not file.filename:
                    raise ValueError("No file selected")
                    
                if not allowed_file(file.filename):
                    raise ValueError("Invalid file type")
                    
                if not key:
                    raise ValueError("No key provided")
                    
                if not algorithm:
                    raise ValueError("No algorithm selected")
                    
                if algorithm not in ['AES-256', 'TripleDES']:
                    raise ValueError("Invalid algorithm selected")

                # Perform decryption
                decrypted_file_path = decrypt_file(file, key, algorithm, app.config['UPLOAD_FOLDER'])
                
                # Verify file exists
                if not os.path.exists(decrypted_file_path):
                    raise ValueError("Decrypted file not found")
                
                try:
                    # Get original filename without the encrypted_ prefix
                    original_filename = os.path.basename(file.filename)
                    if original_filename.startswith('encrypted_'):
                        original_filename = original_filename[len('encrypted_'):]
                    
                    # Return JSON with file information
                    return {
                        'success': True,
                        'message': 'File decrypted successfully',
                        'file_url': url_for('serve_uploads', filename=os.path.basename(decrypted_file_path)),
                        'original_filename': original_filename,
                        'file_size': os.path.getsize(decrypted_file_path)
                    }
                    
                except Exception as e:
                    logger.error(f"Error preparing response: {str(e)}")
                    # Clean up the file if sending failed
                    if os.path.exists(decrypted_file_path):
                        try:
                            os.remove(decrypted_file_path)
                        except:
                            pass
                    raise ValueError(f"Error processing decrypted file: {str(e)}")
                    
            except Exception as e:
                return {'success': False, 'error': str(e)}, 400
                
        return render_template('decryption.html') 