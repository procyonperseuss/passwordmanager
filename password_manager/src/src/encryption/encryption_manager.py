"""Encryption manager for the password manager."""
import os
import base64
import bcrypt
from cryptography.fernet import Fernet
from ..config.settings import KEY_FILE

class EncryptionManager:
    def __init__(self):
        """Initialize encryption manager."""
        self.key = self._load_or_generate_key()
        self.fernet = Fernet(self.key)

    def _load_or_generate_key(self):
        """Load the encryption key from file or generate a new one."""
        try:
            with open(KEY_FILE, 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open(KEY_FILE, 'wb') as key_file:
                key_file.write(key)
            return key

    def encrypt_data(self, data):
        """Encrypt data and return base64 encoded string."""
        if isinstance(data, str):
            data = data.encode()
        encrypted_data = self.fernet.encrypt(data)
        # Convert to base64 string for JSON serialization
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        """Decrypt base64 encoded encrypted data."""
        try:
            # Convert from base64 string back to bytes
            if isinstance(encrypted_data, str):
                encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            print(f"Error decrypting data: {str(e)}")
            return None

    def hash_master_password(self, password):
        """Hash the master password using bcrypt."""
        try:
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode(), salt)
        except Exception as e:
            print(f"Error hashing password: {str(e)}")
            return None

    def verify_master_password(self, password, stored_hash):
        """Verify the master password against a stored hash."""
        try:
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode()
            return bcrypt.checkpw(password.encode(), stored_hash)
        except Exception as e:
            print(f"Error verifying password: {str(e)}")
            return False 