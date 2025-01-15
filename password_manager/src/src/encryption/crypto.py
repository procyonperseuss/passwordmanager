"""
Encryption and decryption functionality for the password manager.
"""

from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
import bcrypt
from ..config.settings import KEY_FILE

class EncryptionManager:
    def __init__(self):
        self.cipher_suite = None
        self._load_or_generate_key()

    def _generate_key(self):
        """Generate an encryption key and save it to a file."""
        salt = b'salt_'  # In a real application, use a random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(b"temporary_master_password"))
        
        # Save the key to a file
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        
        return key

    def _load_or_generate_key(self):
        """Load the encryption key from file or generate a new one if it doesn't exist."""
        try:
            with open(KEY_FILE, 'rb') as key_file:
                key = key_file.read()
        except FileNotFoundError:
            key = self._generate_key()
        
        self.cipher_suite = Fernet(key)

    def encrypt_data(self, data):
        """Encrypt a string."""
        return self.cipher_suite.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        """Decrypt an encrypted string."""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

    @staticmethod
    def hash_master_password(password):
        """Hash the master password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    @staticmethod
    def verify_master_password(password, stored_hash):
        """Verify the master password against stored hash."""
        return bcrypt.checkpw(password.encode(), stored_hash) 