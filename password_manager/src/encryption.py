"""
Encryption module for the password manager.
Handles all encryption and decryption operations.
"""

from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class EncryptionManager:
    """Handles encryption and decryption operations for the password manager."""
    
    KEY_FILE = "data/key.key"
    
    def __init__(self):
        """Initialize the encryption manager with a key."""
        self.encryption_key = self.load_or_generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
    
    def generate_key(self):
        """Generate an encryption key using PBKDF2."""
        salt = b'salt_'  # In a real application, use a random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(b"temporary_master_password"))
        
        # Save the key to a file
        os.makedirs(os.path.dirname(self.KEY_FILE), exist_ok=True)
        with open(self.KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        
        return key
    
    def load_or_generate_key(self):
        """Load the encryption key from file or generate a new one if it doesn't exist."""
        try:
            with open(self.KEY_FILE, 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            return self.generate_key()
    
    def encrypt(self, data: str) -> str:
        """
        Encrypt a string.
        
        Args:
            data: The string to encrypt
            
        Returns:
            The encrypted string in base64 format
        """
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            encrypted_data: The encrypted string in base64 format
            
        Returns:
            The decrypted string
        """
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
