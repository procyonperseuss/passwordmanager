"""
Authentication module for the password manager.
Handles user authentication, MFA, and biometric authentication.
"""

import bcrypt
import os
import json
import pyotp
import qrcode
import platform
from datetime import datetime
from typing import Dict, List, Tuple, Optional

class AuthenticationManager:
    """Handles user authentication and MFA operations."""
    
    MASTER_PASSWORD_FILE = "data/master.key"
    MFA_CONFIG_FILE = "data/mfa_config.json"
    BACKUP_CODES_FILE = "data/backup_codes.json"
    BIOMETRIC_CONFIG_FILE = "data/biometric_config.json"
    
    def __init__(self):
        """Initialize the authentication manager."""
        os.makedirs("data", exist_ok=True)
    
    def verify_master_password(self) -> bool:
        """
        Verify the master password or set it up if it's the first time.
        
        Returns:
            bool: True if verification successful, False otherwise
        """
        if not os.path.exists(self.MASTER_PASSWORD_FILE):
            return self.setup_master_password()
        
        # Check for biometric authentication first
        biometric_config = self.load_biometric_config()
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
    
    def setup_master_password(self) -> bool:
        """
        Set up the master password for the first time.
        
        Returns:
            bool: True if setup successful, False otherwise
        """
        print("\nWelcome to Password Manager!")
        print("Please set up your master password.")
        
        while True:
            master_pass = self.secure_password_input("Enter master password: ")
            confirm_pass = self.secure_password_input("Confirm master password: ")
            
            if master_pass == confirm_pass:
                # Hash the password and save it
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(master_pass.encode(), salt)
                
                os.makedirs(os.path.dirname(self.MASTER_PASSWORD_FILE), exist_ok=True)
                with open(self.MASTER_PASSWORD_FILE, 'wb') as f:
                    f.write(hashed)
                
                print("\nMaster password set successfully!")
                return True
            else:
                print("\nPasswords don't match! Please try again.")
    
    def check_master_password(self) -> bool:
        """
        Verify the entered master password against stored hash.
        
        Returns:
            bool: True if password correct, False otherwise
        """
        try:
            with open(self.MASTER_PASSWORD_FILE, 'rb') as f:
                stored_hash = f.read()
            
            master_pass = self.secure_password_input("\nEnter master password: ")
            
            return bcrypt.checkpw(master_pass.encode(), stored_hash)
                
        except Exception as e:
            print(f"An error occurred: {e}")
            return False
    
    def secure_password_input(self, prompt: str) -> str:
        """
        Get password input securely and show dots while typing.
        
        Args:
            prompt: The prompt to display
            
        Returns:
            str: The entered password
        """
        import getpass
        return getpass.getpass(prompt)
    
    def setup_mfa(self) -> bool:
        """
        Enable MFA for the password manager.
        
        Returns:
            bool: True if setup successful, False otherwise
        """
        print("\nEnable Multi-Factor Authentication")
        print("-" * 20)
        
        # Generate a random secret key for TOTP
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        
        # Generate QR code for authenticator apps
        provisioning_uri = totp.provisioning_uri("Password Manager", issuer_name="Secure Password Manager")
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        print("\nPlease follow these steps to enable MFA:")
        print("1. Open your authenticator app (Google Authenticator, Authy, etc.)")
        print("2. Scan the following QR code or manually enter the secret key")
        print(f"\nSecret Key: {secret_key}")
        
        # Display QR code in terminal (ASCII art)
        qr.print_ascii()
        
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
    
    def verify_mfa(self) -> bool:
        """
        Verify MFA code during login.
        
        Returns:
            bool: True if verification successful, False otherwise
        """
        mfa_config = self.load_mfa_config()
        if not mfa_config["enabled"]:
            return True
        
        print("\nMulti-Factor Authentication Required")
        print("-" * 20)
        
        for _ in range(3):  # Give user 3 attempts
            print("\nEnter your verification code from your authenticator app")
            print("Or enter a backup code")
            code = input("Code: ").strip()
            
            # Check if it's a backup code
            if self.verify_backup_code(code):
                print("Backup code accepted!")
                return True
            
            # Check if it's a valid TOTP code
            totp = pyotp.TOTP(mfa_config["secret_key"])
            if totp.verify(code):
                return True
            
            print("Invalid code, please try again.")
        
        print("Too many failed attempts.")
        return False
    
    def generate_backup_codes(self, num_codes: int = 8) -> List[str]:
        """
        Generate backup codes for MFA recovery.
        
        Args:
            num_codes: Number of backup codes to generate
            
        Returns:
            List[str]: List of generated backup codes
        """
        import random
        import string
        
        backup_codes = []
        for _ in range(num_codes):
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            backup_codes.append(code)
        return backup_codes
    
    def save_mfa_config(self, secret_key: str, backup_codes: List[str]) -> None:
        """
        Save MFA configuration and backup codes.
        
        Args:
            secret_key: The TOTP secret key
            backup_codes: List of backup codes
        """
        mfa_config = {
            "enabled": True,
            "secret_key": secret_key,
            "enabled_date": datetime.now().isoformat()
        }
        
        os.makedirs(os.path.dirname(self.MFA_CONFIG_FILE), exist_ok=True)
        with open(self.MFA_CONFIG_FILE, 'w') as f:
            json.dump(mfa_config, f, indent=4)
        
        with open(self.BACKUP_CODES_FILE, 'w') as f:
            json.dump({"backup_codes": backup_codes}, f, indent=4)
    
    def load_mfa_config(self) -> Dict:
        """
        Load MFA configuration if it exists.
        
        Returns:
            Dict: MFA configuration
        """
        try:
            with open(self.MFA_CONFIG_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {"enabled": False}
    
    def verify_backup_code(self, entered_code: str) -> bool:
        """
        Verify a backup code and remove it if valid.
        
        Args:
            entered_code: The backup code to verify
            
        Returns:
            bool: True if code is valid, False otherwise
        """
        try:
            with open(self.BACKUP_CODES_FILE, 'r') as f:
                backup_data = json.load(f)
                backup_codes = backup_data["backup_codes"]
            
            if entered_code in backup_codes:
                # Remove used backup code
                backup_codes.remove(entered_code)
                with open(self.BACKUP_CODES_FILE, 'w') as f:
                    json.dump({"backup_codes": backup_codes}, f, indent=4)
                return True
        except FileNotFoundError:
            pass
        return False
    
    def is_biometric_available(self) -> bool:
        """
        Check if biometric authentication is available on the system.
        
        Returns:
            bool: True if available, False otherwise
        """
        system = platform.system().lower()
        
        if system == "darwin":  # macOS
            try:
                import subprocess
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
                import subprocess
                result = subprocess.run(["fprintd-list"], capture_output=True, text=True)
                return result.returncode == 0
            except FileNotFoundError:
                return False
        
        return False
    
    def authenticate_with_biometrics(self) -> bool:
        """
        Authenticate user using biometric authentication.
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        system = platform.system().lower()
        
        try:
            if system == "darwin":  # macOS
                import subprocess
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
                import subprocess
                result = subprocess.run(["fprintd-verify"], capture_output=True, text=True)
                return result.returncode == 0
            
            return False
        except Exception as e:
            print(f"Error during biometric authentication: {e}")
            return False
    
    def load_biometric_config(self) -> Dict:
        """
        Load biometric authentication configuration.
        
        Returns:
            Dict: Biometric configuration
        """
        try:
            with open(self.BIOMETRIC_CONFIG_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {"enabled": False}
    
    def save_biometric_config(self, config: Dict) -> None:
        """
        Save biometric authentication configuration.
        
        Args:
            config: The configuration to save
        """
        os.makedirs(os.path.dirname(self.BIOMETRIC_CONFIG_FILE), exist_ok=True)
        with open(self.BIOMETRIC_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
