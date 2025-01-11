"""
Authentication management for the password manager.
"""

import os
import pyotp
import platform
import subprocess
from datetime import datetime
from ..config.settings import (
    MASTER_PASSWORD_FILE,
    MFA_CONFIG_FILE,
    BACKUP_CODES_FILE,
    BIOMETRIC_CONFIG_FILE
)
from ..encryption.crypto import EncryptionManager
from ..storage.file_handler import FileHandler

class AuthenticationManager:
    def __init__(self):
        self.file_handler = FileHandler()
        self.encryption_manager = EncryptionManager()

    def verify_master_password(self):
        """Verify the master password or set it up if it's the first time."""
        if not os.path.exists(MASTER_PASSWORD_FILE):
            return self.setup_master_password()
        
        # Check for biometric authentication first
        biometric_config = self.file_handler.load_json_file(BIOMETRIC_CONFIG_FILE, {"enabled": False})
        if biometric_config["enabled"]:
            print("\nBiometric authentication available.")
            use_biometric = input("Would you like to use biometric authentication? (y/n): ")
            
            if use_biometric.lower() == 'y':
                if self.authenticate_with_biometrics():
                    print("\nBiometric authentication successful!")
                    return True
                else:
                    print("\nBiometric authentication failed. Falling back to master password.")
        
        return self.check_master_password()

    def setup_master_password(self):
        """Set up the master password for the first time."""
        print("\nWelcome to Password Manager!")
        print("Please set up your master password.")
        
        while True:
            master_pass = self.secure_password_input("Enter master password: ")
            confirm_pass = self.secure_password_input("Confirm master password: ")
            
            if master_pass == confirm_pass:
                # Hash the password and save it
                hashed = self.encryption_manager.hash_master_password(master_pass)
                
                with open(MASTER_PASSWORD_FILE, 'wb') as f:
                    f.write(hashed)
                
                print("\nMaster password set successfully!")
                return True
            else:
                print("\nPasswords don't match! Please try again.")

    def check_master_password(self):
        """Verify the entered master password against stored hash."""
        try:
            with open(MASTER_PASSWORD_FILE, 'rb') as f:
                stored_hash = f.read()
            
            master_pass = self.secure_password_input("\nEnter master password: ")
            
            if self.encryption_manager.verify_master_password(master_pass, stored_hash):
                print("\nAccess granted!")
                return True
            else:
                print("\nIncorrect master password!")
                return False
                
        except Exception as e:
            print(f"An error occurred: {e}")
            return False

    @staticmethod
    def secure_password_input(prompt):
        """Get password input securely and show dots while typing."""
        import sys
        password = ""
        print(prompt, end='', flush=True)
        
        while True:
            try:
                # Save terminal settings
                subprocess.run(['stty', '-echo', '-icanon'], check=True)
                
                char = sys.stdin.read(1)
                
                if char == '\n':
                    print()
                    break
                elif char == '\x7f' or char == '\x08':  # Backspace
                    if password:
                        password = password[:-1]
                        print('\b \b', end='', flush=True)  # Erase dot
                else:
                    password += char
                    print('*', end='', flush=True)  # Show dot for each character
                    
            except subprocess.CalledProcessError:
                # If stty fails, fall back to regular input
                return input(prompt)
            finally:
                # Restore terminal settings
                subprocess.run(['stty', 'echo', 'icanon'], check=True)
        
        return password

    def setup_mfa(self):
        """Enable MFA for the password manager."""
        print("\nEnable Multi-Factor Authentication")
        print("-" * 20)
        
        # Generate a random secret key for TOTP
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        
        # Generate QR code for authenticator apps
        provisioning_uri = totp.provisioning_uri("Password Manager", issuer_name="Secure Password Manager")
        
        print("\nPlease follow these steps to enable MFA:")
        print("1. Open your authenticator app (Google Authenticator, Authy, etc.)")
        print("2. Scan the QR code or manually enter the secret key")
        print(f"\nSecret Key: {secret_key}")
        
        # Generate and save backup codes
        backup_codes = self.generate_backup_codes()
        
        # Verify setup
        print("\nTo verify setup, please enter the code from your authenticator app:")
        for _ in range(3):  # Give user 3 attempts
            verification_code = input("Enter verification code: ")
            if totp.verify(verification_code):
                self.save_mfa_config(secret_key, backup_codes)
                print("\nMFA enabled successfully!")
                print("\nBACKUP CODES (save these in a secure location):")
                for code in backup_codes:
                    print(code)
                return True
            print("Invalid code, please try again.")
        
        print("Failed to verify MFA setup. Please try again later.")
        return False

    def verify_mfa(self):
        """Verify MFA code during login."""
        mfa_config = self.file_handler.load_json_file(MFA_CONFIG_FILE, {"enabled": False})
        if not mfa_config["enabled"]:
            return True
        
        print("\nMulti-Factor Authentication Required")
        print("-" * 20)
        
        for _ in range(3):  # Give user 3 attempts
            print("\nEnter your verification code from your authenticator app")
            print("Or enter a backup code")
            code = input("Code: ").strip()
            
            # Check if it's a backup code
            if len(code) == 10 and self.verify_backup_code(code):
                print("Backup code accepted!")
                return True
            
            # Check if it's a valid TOTP code
            totp = pyotp.TOTP(mfa_config["secret_key"])
            if totp.verify(code):
                return True
            
            print("Invalid code, please try again.")
        
        print("Too many failed attempts.")
        return False

    @staticmethod
    def generate_backup_codes(num_codes=8):
        """Generate backup codes for MFA recovery."""
        import random
        import string
        backup_codes = []
        for _ in range(num_codes):
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            backup_codes.append(code)
        return backup_codes

    def save_mfa_config(self, secret_key, backup_codes):
        """Save MFA configuration and backup codes."""
        mfa_config = {
            "enabled": True,
            "secret_key": secret_key,
            "enabled_date": datetime.now().isoformat()
        }
        
        self.file_handler.save_json_file(MFA_CONFIG_FILE, mfa_config)
        self.file_handler.save_json_file(BACKUP_CODES_FILE, {"backup_codes": backup_codes})

    def verify_backup_code(self, entered_code):
        """Verify a backup code and remove it if valid."""
        backup_data = self.file_handler.load_json_file(BACKUP_CODES_FILE, {"backup_codes": []})
        backup_codes = backup_data["backup_codes"]
        
        if entered_code in backup_codes:
            # Remove used backup code
            backup_codes.remove(entered_code)
            self.file_handler.save_json_file(BACKUP_CODES_FILE, {"backup_codes": backup_codes})
            return True
        return False

    @staticmethod
    def is_biometric_available():
        """Check if biometric authentication is available on the system."""
        system = platform.system().lower()
        
        if system == "darwin":  # macOS
            try:
                result = subprocess.run(["bioutil", "-c"], capture_output=True, text=True)
                return result.returncode == 0
            except FileNotFoundError:
                return False
        elif system == "windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio",
                                   0, winreg.KEY_READ)
                winreg.CloseKey(key)
                return True
            except WindowsError:
                return False
        elif system == "linux":
            try:
                result = subprocess.run(["fprintd-list"], capture_output=True, text=True)
                return result.returncode == 0
            except FileNotFoundError:
                return False
        
        return False

    def authenticate_with_biometrics(self):
        """Authenticate user using biometric authentication."""
        system = platform.system().lower()
        
        try:
            if system == "darwin":  # macOS
                result = subprocess.run(["bioutil", "-c"], capture_output=True, text=True)
                return result.returncode == 0
            elif system == "windows":
                # For Windows, you would typically use the Windows Hello API
                import ctypes
                return ctypes.windll.user32.MessageBoxW(0, 
                    "Please authenticate with Windows Hello", 
                    "Biometric Authentication", 
                    1) == 1
            elif system == "linux":
                result = subprocess.run(["fprintd-verify"], capture_output=True, text=True)
                return result.returncode == 0
            
            return False
        except Exception as e:
            print(f"Biometric authentication error: {e}")
            return False 