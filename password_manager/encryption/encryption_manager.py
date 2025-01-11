"""Encryption manager for the password manager."""
import os
import base64
import bcrypt
from cryptography.fernet import Fernet
from ..config.settings import KEY_FILE

class EncryptionManager:
    def __init__(self):
        """Initialize the encryption manager."""
        self.key = self._load_or_generate_key()
        self.fernet = Fernet(self.key)

    def _generate_key(self):
        """Generate a new encryption key."""
        key = Fernet.generate_key()
        os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

    def _load_or_generate_key(self):
        """Load existing key or generate a new one."""
        try:
            if os.path.exists(KEY_FILE):
                with open(KEY_FILE, 'rb') as f:
                    return f.read()
            return self._generate_key()
        except Exception as e:
            print(f"Error loading encryption key: {str(e)}")
            return self._generate_key()

    def encrypt_data(self, data):
        """Encrypt a string."""
        try:
            if isinstance(data, str):
                data = data.encode()
            return self.fernet.encrypt(data)
        except Exception as e:
            print(f"Error encrypting data: {str(e)}")
            return None

    def decrypt_data(self, encrypted_data):
        """Decrypt an encrypted string."""
        try:
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return decrypted_data.decode()
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