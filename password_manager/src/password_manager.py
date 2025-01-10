"""
Password management module for the password manager.
Handles password storage, retrieval, and generation.
"""

import json
import os
import random
import string
from datetime import datetime
from typing import Dict, List, Tuple, Optional

from .encryption import EncryptionManager

class PasswordManager:
    """Handles password management operations."""
    
    PASSWORDS_FILE = "data/passwords.json"
    
    def __init__(self, encryption_manager: EncryptionManager):
        """
        Initialize the password manager.
        
        Args:
            encryption_manager: Instance of EncryptionManager for encryption operations
        """
        self.encryption_manager = encryption_manager
        self.passwords = self.load_passwords()
        os.makedirs(os.path.dirname(self.PASSWORDS_FILE), exist_ok=True)
    
    def load_passwords(self) -> Dict:
        """
        Load passwords from the JSON file.
        
        Returns:
            Dict: Dictionary of stored passwords
        """
        try:
            with open(self.PASSWORDS_FILE, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {}
    
    def save_passwords(self) -> None:
        """Save passwords to the JSON file."""
        with open(self.PASSWORDS_FILE, 'w') as file:
            json.dump(self.passwords, file, indent=4)
    
    def add_password(self, account_name: str, username: str, password: str) -> bool:
        """
        Add a new password entry.
        
        Args:
            account_name: Name of the account
            username: Username for the account
            password: Password to store
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            encrypted_password = self.encryption_manager.encrypt(password)
            
            self.passwords[account_name] = {
                "username": username,
                "password": encrypted_password,
                "created_date": datetime.now().isoformat()
            }
            
            self.save_passwords()
            return True
            
        except Exception as e:
            print(f"Error adding password: {e}")
            return False
    
    def retrieve_password(self, account_name: str) -> Optional[Dict]:
        """
        Retrieve password details for an account.
        
        Args:
            account_name: Name of the account to retrieve
            
        Returns:
            Optional[Dict]: Account details if found, None otherwise
        """
        if account_name not in self.passwords:
            return None
        
        account = self.passwords[account_name]
        try:
            decrypted_password = self.encryption_manager.decrypt(account['password'])
            return {
                "account": account_name,
                "username": account['username'],
                "password": decrypted_password,
                "created_date": account['created_date']
            }
        except Exception as e:
            print(f"Error retrieving password: {e}")
            return None
    
    def remove_password(self, account_name: str) -> bool:
        """
        Remove a password entry.
        
        Args:
            account_name: Name of the account to remove
            
        Returns:
            bool: True if successful, False otherwise
        """
        if account_name not in self.passwords:
            return False
        
        try:
            del self.passwords[account_name]
            self.save_passwords()
            return True
        except Exception as e:
            print(f"Error removing password: {e}")
            return False
    
    def list_accounts(self) -> List[Dict]:
        """
        Get a list of all stored accounts.
        
        Returns:
            List[Dict]: List of account details
        """
        accounts = []
        for account_name, details in self.passwords.items():
            accounts.append({
                "account": account_name,
                "username": details["username"],
                "created_date": details["created_date"]
            })
        return sorted(accounts, key=lambda x: x["account"])
    
    def generate_password(self, length: int = 16) -> str:
        """
        Generate a strong random password.
        
        Args:
            length: Length of the password to generate
            
        Returns:
            str: Generated password
        """
        if length < 8:
            length = 8  # Minimum length for security
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each set
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill the rest with random characters from all sets
        all_characters = lowercase + uppercase + digits + special
        for _ in range(length - 4):
            password.append(random.choice(all_characters))
        
        # Shuffle the password
        random.shuffle(password)
        
        return ''.join(password)
    
    def check_password_strength(self, password: str) -> Tuple[bool, str, List[str], List[str]]:
        """
        Check password strength and provide feedback.
        
        Args:
            password: Password to check
            
        Returns:
            Tuple[bool, str, List[str], List[str]]: 
                - bool: True if password is strong enough
                - str: Overall strength assessment
                - List[str]: List of strengths
                - List[str]: List of weaknesses
        """
        score = 0
        strengths = []
        weaknesses = []
        
        # Length check
        if len(password) >= 12:
            score += 2
            strengths.append("Good length (12+ characters)")
        elif len(password) >= 8:
            score += 1
            strengths.append("Minimum length met (8+ characters)")
        else:
            weaknesses.append("Password is too short (minimum 8 characters)")
        
        # Character type checks
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if has_upper:
            score += 1
            strengths.append("Contains uppercase letters")
        else:
            weaknesses.append("Missing uppercase letters")
        
        if has_lower:
            score += 1
            strengths.append("Contains lowercase letters")
        else:
            weaknesses.append("Missing lowercase letters")
        
        if has_digit:
            score += 1
            strengths.append("Contains numbers")
        else:
            weaknesses.append("Missing numbers")
        
        if has_special:
            score += 1
            strengths.append("Contains special characters")
        else:
            weaknesses.append("Missing special characters")
        
        # Additional checks
        if len(set(password)) < len(password) * 0.75:
            weaknesses.append("Too many repeated characters")
            score -= 1
        
        if len(password) >= 14:
            score += 1
            strengths.append("Extra long password (bonus)")
        
        # Determine strength level
        if score >= 6:
            strength = "Strong"
        elif score >= 4:
            strength = "Medium"
        else:
            strength = "Weak"
        
        return score >= 4, strength, strengths, weaknesses
