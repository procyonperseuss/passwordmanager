"""Authentication manager module."""

import os
import socket
import requests
import pyotp
import platform
import subprocess
from datetime import datetime
from ..security.session import SessionManager
from ..security.login_tracker import LoginTracker
from ..config.settings import (
    DATA_DIR,
    MASTER_PASSWORD_FILE,
    MFA_CONFIG_FILE,
    BACKUP_CODES_FILE,
    BIOMETRIC_CONFIG_FILE
)
from ..encryption.crypto import EncryptionManager
from ..storage.file_handler import FileHandler

class AuthenticationManager:
    def __init__(self):
        """Initialize authentication manager."""
        self.session_manager = SessionManager()
        self.login_tracker = LoginTracker()
        self.current_session = None
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

    def _get_ip_address(self):
        """Get the current IP address."""
        try:
            # Try to get external IP
            response = requests.get('https://api.ipify.org')
            return response.text
        except Exception:
            # Fallback to local IP
            return socket.gethostbyname(socket.gethostname())

    def login(self, username, password):
        """Authenticate user and create session."""
        ip_address = self._get_ip_address()

        # Check if IP is blocked
        if self.login_tracker.is_ip_blocked(ip_address):
            return False, "Too many failed attempts. Please try again later."

        # Verify credentials
        if not self._verify_credentials(username, password):
            self.login_tracker.record_attempt(ip_address, username, False)
            return False, "Invalid username or password"

        # Create new session
        session_id = self.session_manager.create_session(username, ip_address)
        self.current_session = session_id
        self.login_tracker.record_attempt(ip_address, username, True)

        return True, session_id

    def logout(self):
        """End the current session."""
        if self.current_session:
            self.session_manager.end_session(self.current_session)
            self.current_session = None
            return True
        return False

    def validate_session(self, session_id):
        """Validate a session is active and not expired."""
        return self.session_manager.validate_session(session_id)

    def get_active_sessions(self, username=None):
        """Get all active sessions for a user."""
        return self.session_manager.get_active_sessions(username)

    def end_all_sessions(self, username):
        """End all sessions for a user."""
        self.session_manager.end_all_sessions(username)

    def get_login_history(self, username=None, ip_address=None):
        """Get login attempt history."""
        if username:
            return self.login_tracker.get_attempts_for_user(username)
        elif ip_address:
            return self.login_tracker.get_attempts_for_ip(ip_address)
        return []

    def get_blocked_ips(self):
        """Get list of currently blocked IPs."""
        return self.login_tracker.get_blocked_ips()

    def unblock_ip(self, ip_address):
        """Manually unblock an IP address."""
        self.login_tracker.unblock_ip(ip_address)

    def _verify_credentials(self, username, password):
        """Verify username and password."""
        # TODO: Implement actual credential verification
        # This is a placeholder - replace with your actual verification logic
        return True  # For testing purposes 