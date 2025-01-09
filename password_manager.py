from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import os
import bcrypt
import getpass
import shutil
from datetime import datetime, timedelta
import subprocess
import sys
import random
import string
import pyotp
import qrcode
import requests
from collections import defaultdict
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import platform
import matplotlib.pyplot as plt
from io import BytesIO

# File paths for storing data
PASSWORDS_FILE = "passwords.json"
KEY_FILE = "key.key"
MASTER_PASSWORD_FILE = "master.key"
BACKUP_DIR = "backups"
MFA_CONFIG_FILE = "mfa_config.json"
BACKUP_CODES_FILE = "backup_codes.json"
NOTES_FILE = "secure_notes.json"
AUDIT_LOG_FILE = "audit_logs.json"
TRUSTED_CONTACTS_FILE = "trusted_contacts.json"
EMERGENCY_ACCESS_CONFIG_FILE = "emergency_access_config.json"
BIOMETRIC_CONFIG_FILE = "biometric_config.json"

# Audit log action types
class AuditAction:
    LOGIN_ATTEMPT = "Login Attempt"
    ADD_PASSWORD = "Added Password"
    UPDATE_PASSWORD = "Updated Password"
    REMOVE_PASSWORD = "Removed Password"
    GENERATE_PASSWORD = "Generated Password"
    ADD_NOTE = "Added Note"
    UPDATE_NOTE = "Updated Note"
    REMOVE_NOTE = "Removed Note"
    CREATE_BACKUP = "Created Backup"
    RESTORE_BACKUP = "Restored Backup"
    VIEW_PASSWORD = "Viewed Password"
    VIEW_NOTE = "Viewed Note"
    ADD_TRUSTED_CONTACT = "Added Trusted Contact"
    REMOVE_TRUSTED_CONTACT = "Removed Trusted Contact"
    EMERGENCY_ACCESS_REQUEST = "Emergency Access Request"
    EMERGENCY_ACCESS_GRANTED = "Emergency Access Granted"
    EMERGENCY_ACCESS_DENIED = "Emergency Access Denied"
    BIOMETRIC_AUTH_ATTEMPT = "Biometric Authentication Attempt"
    HARDWARE_TOKEN_AUTH_ATTEMPT = "Hardware Token Authentication Attempt"

class PasswordStrength:
    WEAK = 0
    MEDIUM = 1
    STRONG = 2

# ANSI color codes
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'

def verify_master_password():
    """Verify the master password or set it up if it's the first time."""
    if not os.path.exists(MASTER_PASSWORD_FILE):
        return setup_master_password()
    
    # Check for biometric authentication first
    biometric_config = load_biometric_config()
    if biometric_config["enabled"]:
        print("\nBiometric authentication available.")
        use_biometric = input("Would you like to use biometric authentication? (y/n): ")
        
        if use_biometric.lower() == 'y':
            if authenticate_with_biometrics():
                print("\nBiometric authentication successful!")
                log_action(AuditAction.LOGIN_ATTEMPT, {
                    "method": "biometric",
                    "status": "success"
                }, "success")
                return True
            else:
                print("\nBiometric authentication failed. Falling back to master password.")
    
    return check_master_password()

def secure_password_input(prompt):
    """Get password input securely and show dots while typing."""
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

def setup_master_password():
    """Set up the master password for the first time."""
    print("\nWelcome to Password Manager!")
    print("Please set up your master password.")
    
    while True:
        master_pass = secure_password_input("Enter master password: ")
        confirm_pass = secure_password_input("Confirm master password: ")
        
        if master_pass == confirm_pass:
            # Hash the password and save it
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(master_pass.encode(), salt)
            
            with open(MASTER_PASSWORD_FILE, 'wb') as f:
                f.write(hashed)
            
            print("\nMaster password set successfully!")
            return True
        else:
            print("\nPasswords don't match! Please try again.")

def check_master_password():
    """Verify the entered master password against stored hash."""
    try:
        with open(MASTER_PASSWORD_FILE, 'rb') as f:
            stored_hash = f.read()
        
        master_pass = secure_password_input("\nEnter master password: ")
        
        if bcrypt.checkpw(master_pass.encode(), stored_hash):
            print("\nAccess granted!")
            log_action(AuditAction.LOGIN_ATTEMPT, {"status": "success"}, "success")
            return True
        else:
            print("\nIncorrect master password!")
            log_action(AuditAction.LOGIN_ATTEMPT, {"status": "failed"}, "failure")
            return False
            
    except Exception as e:
        print(f"An error occurred: {e}")
        log_action(AuditAction.LOGIN_ATTEMPT, {"error": str(e)}, "failure")
        return False

def generate_key():
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

def load_or_generate_key():
    """Load the encryption key from file or generate a new one if it doesn't exist."""
    try:
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    except FileNotFoundError:
        return generate_key()

def load_passwords():
    """Load passwords from the JSON file."""
    try:
        with open(PASSWORDS_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_passwords(passwords_dict):
    """Save passwords to the JSON file."""
    with open(PASSWORDS_FILE, 'w') as file:
        json.dump(passwords_dict, file, indent=4)

def load_secure_notes():
    """Load secure notes from the JSON file."""
    try:
        with open(NOTES_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_secure_notes(notes_dict):
    """Save secure notes to the JSON file."""
    with open(NOTES_FILE, 'w') as file:
        json.dump(notes_dict, file, indent=4)

# Initialize the encryption system and load passwords
encryption_key = load_or_generate_key()
cipher_suite = Fernet(encryption_key)
passwords = load_passwords()

# Initialize secure notes
secure_notes = load_secure_notes()

def encrypt_password(password):
    """Encrypt a password string."""
    return cipher_suite.encrypt(password.encode()).decode()  # Store as string in JSON

def decrypt_password(encrypted_password):
    """Decrypt an encrypted password."""
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

def calculate_password_strength(password):
    """
    Calculate a detailed password strength score and provide specific feedback.
    Returns a tuple of (score, list of strengths, list of weaknesses)
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
    
    return score, strengths, weaknesses

def check_password_strength(password):
    """
    Check password strength and return detailed feedback with color coding.
    Returns a tuple (is_strong_enough, colored_message)
    """
    score, strengths, weaknesses = calculate_password_strength(password)
    
    # Determine strength level
    if score >= 6:
        strength = PasswordStrength.STRONG
        color = Colors.GREEN
        status = "Strong"
    elif score >= 4:
        strength = PasswordStrength.MEDIUM
        color = Colors.YELLOW
        status = "Medium"
    else:
        strength = PasswordStrength.WEAK
        color = Colors.RED
        status = "Weak"
    
    # Build detailed feedback message
    message = [f"\nPassword Strength: {color}{status}{Colors.RESET}"]
    
    if strengths:
        message.append("\nStrengths:")
        for s in strengths:
            message.append(f"✓ {s}")
    
    if weaknesses:
        message.append("\nWeaknesses:")
        for w in weaknesses:
            message.append(f"✗ {w}")
    
    # Password is considered strong enough if it's at least medium strength
    is_strong_enough = strength >= PasswordStrength.MEDIUM
    
    if not is_strong_enough:
        message.append("\nPlease improve your password by addressing the weaknesses.")
    
    return is_strong_enough, "\n".join(message)

def remove_password():
    """
    Remove a stored password for a specified account.
    """
    print("\nRemove Password")
    print("-" * 20)
    
    account_name = input("Enter account name to remove: ")
    
    if account_name in passwords:
        confirm = input(f"Are you sure you want to remove the password for '{account_name}'? (y/n): ")
        if confirm.lower() == 'y':
            try:
                del passwords[account_name]
                save_passwords(passwords)
                print(f"\nPassword for '{account_name}' has been removed successfully!")
                log_action(AuditAction.REMOVE_PASSWORD, {"account": account_name}, "success")
            except Exception as e:
                print(f"An error occurred: {e}")
                log_action(AuditAction.REMOVE_PASSWORD, {
                    "account": account_name,
                    "error": str(e)
                }, "failure")
        else:
            print("\nPassword removal cancelled.")
    else:
        print(f"\nNo password found for account: {account_name}")
        log_action(AuditAction.REMOVE_PASSWORD, {
            "account": account_name,
            "error": "Account not found"
        }, "failure")

def list_accounts():
    """
    Display all stored account names.
    """
    print("\nStored Accounts")
    print("-" * 20)
    
    if not passwords:
        print("No accounts stored yet.")
        return
    
    print("Your accounts:")
    for i, account in enumerate(sorted(passwords.keys()), 1):
        print(f"{i}. {account}")

def generate_strong_password(length=16):
    """
    Generate a strong random password.
    The password will contain uppercase, lowercase, numbers, and special characters.
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

def generate_password_menu():
    """
    Display the password generation menu and options.
    """
    print("\nGenerate Strong Password")
    print("-" * 20)
    
    try:
        length = input("Enter desired password length (minimum 8, press Enter for default 16): ")
        length = int(length) if length.strip() else 16
        
        if length < 8:
            print("Minimum length is 8 characters. Using length of 8.")
            length = 8
        
        password = generate_strong_password(length)
        print("\nGenerated Password:", password)
        
        # Option to copy and use the generated password
        use_password = input("\nWould you like to add this password to an account? (y/n): ")
        if use_password.lower() == 'y':
            add_password(generated_password=password)
            
    except ValueError:
        print("Invalid input. Using default length of 16.")
        password = generate_strong_password()
        print("\nGenerated Password:", password)

def add_password(generated_password=None):
    """
    Prompt user for account details and store them in the passwords dictionary.
    The password is encrypted before storage.
    """
    print("\nAdd New Password")
    print("-" * 20)
    
    account_name = input("Enter account name (e.g., Google): ")
    username = input("Enter username: ")
    
    if generated_password:
        password = generated_password
        print("Using generated password.")
        is_strong, message = check_password_strength(password)
        print(message)
    else:
        while True:
            password = secure_password_input("Enter password: ")
            is_strong, message = check_password_strength(password)
            print(message)
            
            if is_strong:
                break
            
            retry = input("\nWould you like to try another password? (y/n): ")
            if retry.lower() != 'y':
                print("Warning: Proceeding with a weak password is not recommended.")
                confirm = input("Are you sure you want to use this password? (y/n): ")
                if confirm.lower() == 'y':
                    break
    
    try:
        # Encrypt the password before storing
        encrypted_password = encrypt_password(password)
        
        passwords[account_name] = {
            "username": username,
            "password": encrypted_password,
            "created_date": datetime.now().isoformat()
        }
        
        # Save to file
        save_passwords(passwords)
        
        print(f"\nPassword saved successfully!")
        print(f"Account: {account_name}")
        print(f"Username: {username}")
        
        log_action(AuditAction.ADD_PASSWORD, {
            "account": account_name,
            "username": username,
            "password_strength": "strong" if is_strong else "weak"
        }, "success")
    except Exception as e:
        print(f"An error occurred: {e}")
        log_action(AuditAction.ADD_PASSWORD, {
            "account": account_name,
            "error": str(e)
        }, "failure")

def retrieve_password():
    """
    Retrieve and display password details for a specified account.
    The password is decrypted before display.
    """
    print("\nRetrieve Password")
    print("-" * 20)
    
    account_name = input("Enter account name to retrieve: ")
    
    if account_name in passwords:
        account = passwords[account_name]
        decrypted_password = decrypt_password(account['password'])
        print(f"\nAccount Details:")
        print(f"Account: {account_name}")
        print(f"Username: {account['username']}")
        print(f"Password: {decrypted_password}")
    else:
        print(f"\nNo password found for account: {account_name}")

def create_backup():
    """
    Create a backup of all password manager data.
    Returns the backup directory path.
    """
    # Create backup directory if it doesn't exist
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    # Create a timestamp for the backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"backup_{timestamp}")
    os.makedirs(backup_path)
    
    try:
        # Copy all necessary files to backup directory
        if os.path.exists(PASSWORDS_FILE):
            shutil.copy2(PASSWORDS_FILE, os.path.join(backup_path, PASSWORDS_FILE))
        if os.path.exists(KEY_FILE):
            shutil.copy2(KEY_FILE, os.path.join(backup_path, KEY_FILE))
        if os.path.exists(MASTER_PASSWORD_FILE):
            shutil.copy2(MASTER_PASSWORD_FILE, os.path.join(backup_path, MASTER_PASSWORD_FILE))
        if os.path.exists(AUDIT_LOG_FILE):
            shutil.copy2(AUDIT_LOG_FILE, os.path.join(backup_path, AUDIT_LOG_FILE))
        
        print(f"\nBackup created successfully in: {backup_path}")
        log_action(AuditAction.CREATE_BACKUP, {"backup_path": backup_path}, "success")
        return True
    except Exception as e:
        print(f"\nError creating backup: {e}")
        log_action(AuditAction.CREATE_BACKUP, {"error": str(e)}, "failure")
        return False

def list_backups():
    """
    List all available backups.
    Returns a list of backup directory paths.
    """
    if not os.path.exists(BACKUP_DIR):
        return []
    
    backups = []
    for item in os.listdir(BACKUP_DIR):
        if item.startswith("backup_"):
            backups.append(item)
    
    return sorted(backups, reverse=True)  # Most recent first

def restore_from_backup():
    """
    Restore password manager data from a backup.
    """
    print("\nRestore from Backup")
    print("-" * 20)
    
    backups = list_backups()
    if not backups:
        print("No backups found.")
        log_action(AuditAction.RESTORE_BACKUP, {"error": "No backups found"}, "failure")
        return
    
    print("\nAvailable backups:")
    for i, backup in enumerate(backups, 1):
        # Convert backup name to readable date
        date_str = backup.replace("backup_", "").replace("_", " ")
        print(f"{i}. {date_str}")
    
    try:
        choice = input("\nEnter backup number to restore (or 'c' to cancel): ")
        if choice.lower() == 'c':
            print("Restore cancelled.")
            return
        
        backup_index = int(choice) - 1
        if 0 <= backup_index < len(backups):
            backup_path = os.path.join(BACKUP_DIR, backups[backup_index])
            
            # Confirm before restoring
            confirm = input("\nWARNING: This will overwrite current data. Continue? (y/n): ")
            if confirm.lower() != 'y':
                print("Restore cancelled.")
                return
            
            # Restore files
            if os.path.exists(os.path.join(backup_path, PASSWORDS_FILE)):
                shutil.copy2(os.path.join(backup_path, PASSWORDS_FILE), PASSWORDS_FILE)
            if os.path.exists(os.path.join(backup_path, KEY_FILE)):
                shutil.copy2(os.path.join(backup_path, KEY_FILE), KEY_FILE)
            if os.path.exists(os.path.join(backup_path, MASTER_PASSWORD_FILE)):
                shutil.copy2(os.path.join(backup_path, MASTER_PASSWORD_FILE), MASTER_PASSWORD_FILE)
            if os.path.exists(os.path.join(backup_path, AUDIT_LOG_FILE)):
                shutil.copy2(os.path.join(backup_path, AUDIT_LOG_FILE), AUDIT_LOG_FILE)
            
            print("\nRestore completed successfully!")
            log_action(AuditAction.RESTORE_BACKUP, {"backup_path": backup_path}, "success")
            print("Please restart the password manager to apply the changes.")
            exit(0)
        else:
            print("Invalid backup number.")
            log_action(AuditAction.RESTORE_BACKUP, {"error": "Invalid backup number"}, "failure")
    except ValueError:
        print("Invalid input. Please enter a number.")
        log_action(AuditAction.RESTORE_BACKUP, {"error": "Invalid input"}, "failure")
    except Exception as e:
        print(f"Error during restore: {e}")
        log_action(AuditAction.RESTORE_BACKUP, {"error": str(e)}, "failure")

def backup_menu():
    """
    Display backup and restore options.
    """
    while True:
        print("\nBackup and Restore")
        print("-" * 20)
        print("1. Create Backup")
        print("2. Restore from Backup")
        print("3. Return to Main Menu")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "1":
            create_backup()
        elif choice == "2":
            restore_from_backup()
        elif choice == "3":
            return
        else:
            print("Invalid choice. Please enter a number between 1 and 3.")

def generate_backup_codes(num_codes=8):
    """Generate backup codes for MFA recovery."""
    backup_codes = []
    for _ in range(num_codes):
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        backup_codes.append(code)
    return backup_codes

def save_mfa_config(secret_key, backup_codes):
    """Save MFA configuration and backup codes."""
    mfa_config = {
        "enabled": True,
        "secret_key": secret_key,
        "enabled_date": datetime.now().isoformat()
    }
    
    with open(MFA_CONFIG_FILE, 'w') as f:
        json.dump(mfa_config, f, indent=4)
    
    with open(BACKUP_CODES_FILE, 'w') as f:
        json.dump({"backup_codes": backup_codes}, f, indent=4)

def load_mfa_config():
    """Load MFA configuration if it exists."""
    try:
        with open(MFA_CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"enabled": False}

def verify_backup_code(entered_code):
    """Verify a backup code and remove it if valid."""
    try:
        with open(BACKUP_CODES_FILE, 'r') as f:
            backup_data = json.load(f)
            backup_codes = backup_data["backup_codes"]
        
        if entered_code in backup_codes:
            # Remove used backup code
            backup_codes.remove(entered_code)
            with open(BACKUP_CODES_FILE, 'w') as f:
                json.dump({"backup_codes": backup_codes}, f, indent=4)
            return True
    except FileNotFoundError:
        pass
    return False

def enable_mfa():
    """Enable MFA for the password manager."""
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
    backup_codes = generate_backup_codes()
    
    # Verify setup
    print("\nTo verify setup, please enter the code from your authenticator app:")
    for _ in range(3):  # Give user 3 attempts
        verification_code = input("Enter verification code: ")
        if totp.verify(verification_code):
            save_mfa_config(secret_key, backup_codes)
            print("\nMFA enabled successfully!")
            print("\nBACKUP CODES (save these in a secure location):")
            for code in backup_codes:
                print(code)
            print("\nIMPORTANT: These backup codes can be used if you lose access to your authenticator app.")
            print("Each code can only be used once.")
            return True
        print("Invalid code, please try again.")
    
    print("Failed to verify MFA setup. Please try again later.")
    return False

def verify_mfa():
    """Verify MFA code during login."""
    mfa_config = load_mfa_config()
    if not mfa_config["enabled"]:
        return True
    
    print("\nMulti-Factor Authentication Required")
    print("-" * 20)
    
    for _ in range(3):  # Give user 3 attempts
        print("\nEnter your verification code from your authenticator app")
        print("Or enter a backup code (XXXXX-XXXXX)")
        code = input("Code: ").strip()
        
        # Check if it's a backup code
        if len(code) == 10 and verify_backup_code(code):
            print("Backup code accepted!")
            return True
        
        # Check if it's a valid TOTP code
        totp = pyotp.TOTP(mfa_config["secret_key"])
        if totp.verify(code):
            return True
        
        print("Invalid code, please try again.")
    
    print("Too many failed attempts.")
    return False

def mfa_menu():
    """Display MFA management options."""
    while True:
        print("\nMFA Management")
        print("-" * 20)
        mfa_config = load_mfa_config()
        
        if mfa_config["enabled"]:
            print("MFA Status: Enabled")
            print("1. Disable MFA")
            print("2. View Backup Codes")
            print("3. Generate New Backup Codes")
        else:
            print("MFA Status: Disabled")
            print("1. Enable MFA")
        
        print("4. Return to Main Menu")
        
        choice = input("\nEnter your choice: ")
        
        if choice == "1":
            if mfa_config["enabled"]:
                # Require MFA verification before disabling
                if verify_mfa():
                    os.remove(MFA_CONFIG_FILE)
                    os.remove(BACKUP_CODES_FILE)
                    print("MFA disabled successfully!")
                else:
                    print("MFA verification failed. MFA remains enabled.")
            else:
                enable_mfa()
        elif choice == "2" and mfa_config["enabled"]:
            if verify_mfa():
                with open(BACKUP_CODES_FILE, 'r') as f:
                    backup_data = json.load(f)
                    print("\nRemaining Backup Codes:")
                    for code in backup_data["backup_codes"]:
                        print(code)
        elif choice == "3" and mfa_config["enabled"]:
            if verify_mfa():
                backup_codes = generate_backup_codes()
                with open(BACKUP_CODES_FILE, 'w') as f:
                    json.dump({"backup_codes": backup_codes}, f, indent=4)
                print("\nNew Backup Codes:")
                for code in backup_codes:
                    print(code)
        elif choice == "4":
            return
        else:
            print("Invalid choice. Please try again.")

def check_haveibeenpwned(password):
    """Check if a password has been compromised using HaveIBeenPwned API."""
    import hashlib
    
    # Hash the password
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    try:
        # Query the API with the hash prefix
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code == 200:
            # Check if the hash suffix exists in the response
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return int(count)
        return 0
    except Exception as e:
        print(f"Error checking HaveIBeenPwned: {e}")
        return 0

def analyze_password_health():
    """Generate a comprehensive password health report."""
    print("\nGenerating Password Health Report...")
    print("-" * 40)
    
    if not passwords:
        print("No passwords stored yet.")
        return
    
    # Initialize statistics
    stats = {
        "total": len(passwords),
        "strength": {"weak": 0, "medium": 0, "strong": 0},
        "reused": defaultdict(list),
        "compromised": [],
        "old": [],
        "problems": defaultdict(list)
    }
    
    # Analyze each password
    for account, data in passwords.items():
        decrypted_password = decrypt_password(data['password'])
        
        # Check strength
        is_strong, _ = check_password_strength(decrypted_password)
        score, strengths, _ = calculate_password_strength(decrypted_password)
        
        if score >= 6:
            stats["strength"]["strong"] += 1
        elif score >= 4:
            stats["strength"]["medium"] += 1
            stats["problems"][account].append("Medium strength")
        else:
            stats["strength"]["weak"] += 1
            stats["problems"][account].append("Weak password")
        
        # Check for reuse
        stats["reused"][decrypted_password].append(account)
        
        # Check for compromised passwords
        if check_haveibeenpwned(decrypted_password) > 0:
            stats["compromised"].append(account)
            stats["problems"][account].append("Compromised in data breach")
        
        # Check password age if timestamp exists
        if "created_date" in data:
            created_date = datetime.fromisoformat(data["created_date"])
            if datetime.now() - created_date > timedelta(days=90):
                stats["old"].append(account)
                stats["problems"][account].append("Password older than 90 days")
    
    # Remove non-reused passwords from reused dict
    stats["reused"] = {k: v for k, v in stats["reused"].items() if len(v) > 1}
    
    # Generate report
    print("\nPassword Strength Summary:")
    print(f"Strong passwords: {stats['strength']['strong']}")
    print(f"Medium passwords: {stats['strength']['medium']}")
    print(f"Weak passwords: {stats['strength']['weak']}")
    
    if stats["reused"]:
        print("\nPassword Reuse Detected:")
        for accounts in stats["reused"].values():
            print(f"Same password used for: {', '.join(accounts)}")
    
    if stats["compromised"]:
        print("\nCompromised Passwords Detected:")
        for account in stats["compromised"]:
            print(f"- {account}")
    
    if stats["old"]:
        print("\nOld Passwords (>90 days):")
        for account in stats["old"]:
            print(f"- {account}")
    
    # Display accounts needing attention
    if stats["problems"]:
        print("\nAccounts Needing Attention:")
        for account, problems in stats["problems"].items():
            print(f"\n{account}:")
            for problem in problems:
                print(f"  - {problem}")
    
    return stats

def improve_passwords():
    """Help users improve problematic passwords."""
    stats = analyze_password_health()
    
    if not stats or not stats["problems"]:
        print("\nNo password improvements needed!")
        return
    
    while True:
        print("\nImprove Passwords")
        print("-" * 20)
        print("Select an account to improve its password:")
        
        # List accounts with problems
        accounts = list(stats["problems"].keys())
        for i, account in enumerate(accounts, 1):
            problems = stats["problems"][account]
            print(f"{i}. {account} - Issues: {', '.join(problems)}")
        
        print(f"{len(accounts) + 1}. Return to main menu")
        
        try:
            choice = input("\nEnter your choice: ")
            if choice == str(len(accounts) + 1):
                break
            
            account_index = int(choice) - 1
            if 0 <= account_index < len(accounts):
                account = accounts[account_index]
                print(f"\nImproving password for: {account}")
                
                # Offer options
                print("1. Generate new strong password")
                print("2. Enter new password manually")
                print("3. Skip")
                
                improve_choice = input("Enter your choice: ")
                
                if improve_choice == "1":
                    new_password = generate_strong_password()
                    print(f"Generated password: {new_password}")
                    if input("Use this password? (y/n): ").lower() == 'y':
                        passwords[account]["password"] = encrypt_password(new_password)
                        passwords[account]["created_date"] = datetime.now().isoformat()
                        save_passwords(passwords)
                        print("Password updated successfully!")
                
                elif improve_choice == "2":
                    while True:
                        new_password = secure_password_input("Enter new password: ")
                        is_strong, message = check_password_strength(new_password)
                        print(message)
                        
                        if is_strong or input("\nUse this password anyway? (y/n): ").lower() == 'y':
                            passwords[account]["password"] = encrypt_password(new_password)
                            passwords[account]["created_date"] = datetime.now().isoformat()
                            save_passwords(passwords)
                            print("Password updated successfully!")
                            break
            else:
                print("Invalid choice!")
                
        except (ValueError, IndexError):
            print("Invalid input! Please enter a number.")
        except Exception as e:
            print(f"An error occurred: {e}")

def add_secure_note():
    """Add a new secure note with encrypted content."""
    print("\nAdd Secure Note")
    print("-" * 20)
    
    title = input("Enter note title: ")
    print("\nEnter note content (press Ctrl+D or Ctrl+Z on a new line to finish):")
    content_lines = []
    
    try:
        while True:
            line = input()
            content_lines.append(line)
    except (EOFError, KeyboardInterrupt):
        content = "\n".join(content_lines)
    
    if not content_lines:
        print("Note creation cancelled.")
        return
    
    try:
        # Encrypt the content
        encrypted_content = encrypt_password(content)  # Reusing password encryption
        
        secure_notes[title] = {
            "content": encrypted_content,
            "created_date": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat()
        }
        
        save_secure_notes(secure_notes)
        print(f"\nSecure note '{title}' saved successfully!")
        
        log_action(AuditAction.ADD_NOTE, {
            "title": title,
            "content_length": len(content)
        }, "success")
    except Exception as e:
        print(f"Error saving note: {e}")
        log_action(AuditAction.ADD_NOTE, {
            "title": title,
            "error": str(e)
        }, "failure")

def retrieve_secure_note():
    """Retrieve and display a secure note."""
    print("\nRetrieve Secure Note")
    print("-" * 20)
    
    if not secure_notes:
        print("No secure notes found.")
        return
    
    title = input("Enter note title: ")
    
    if title in secure_notes:
        try:
            note = secure_notes[title]
            decrypted_content = decrypt_password(note['content'])  # Reusing password decryption
            
            print(f"\nTitle: {title}")
            print("-" * (len(title) + 7))
            print(f"Created: {datetime.fromisoformat(note['created_date']).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Last Modified: {datetime.fromisoformat(note['last_modified']).strftime('%Y-%m-%d %H:%M:%S')}")
            print("\nContent:")
            print("-" * 7)
            print(decrypted_content)
            
            log_action(AuditAction.VIEW_NOTE, {"title": title}, "success")
        except Exception as e:
            print(f"Error retrieving note: {e}")
            log_action(AuditAction.VIEW_NOTE, {
                "title": title,
                "error": str(e)
            }, "failure")
    else:
        print(f"\nNo note found with title: {title}")
        log_action(AuditAction.VIEW_NOTE, {
            "title": title,
            "error": "Note not found"
        }, "failure")

def remove_secure_note():
    """Remove a secure note."""
    print("\nRemove Secure Note")
    print("-" * 20)
    
    if not secure_notes:
        print("No secure notes found.")
        return
    
    title = input("Enter note title to remove: ")
    
    if title in secure_notes:
        confirm = input(f"Are you sure you want to remove the note '{title}'? (y/n): ")
        if confirm.lower() == 'y':
            try:
                del secure_notes[title]
                save_secure_notes(secure_notes)
                print(f"\nNote '{title}' has been removed successfully!")
                log_action(AuditAction.REMOVE_NOTE, {"title": title}, "success")
            except Exception as e:
                print(f"Error removing note: {e}")
                log_action(AuditAction.REMOVE_NOTE, {
                    "title": title,
                    "error": str(e)
                }, "failure")
        else:
            print("\nNote removal cancelled.")
    else:
        print(f"\nNo note found with title: {title}")
        log_action(AuditAction.REMOVE_NOTE, {
            "title": title,
            "error": "Note not found"
        }, "failure")

def secure_notes_menu():
    """Display secure notes management menu."""
    while True:
        print("\nSecure Notes Management")
        print("-" * 20)
        print("1. Add Note")
        print("2. Retrieve Note")
        print("3. List Notes")
        print("4. Remove Note")
        print("5. Return to Main Menu")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == "1":
            add_secure_note()
        elif choice == "2":
            retrieve_secure_note()
        elif choice == "3":
            list_secure_notes()
        elif choice == "4":
            remove_secure_note()
        elif choice == "5":
            return
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

def load_audit_logs():
    """Load audit logs from the encrypted file."""
    try:
        with open(AUDIT_LOG_FILE, 'r') as f:
            encrypted_data = f.read()
            if encrypted_data:
                decrypted_data = decrypt_password(encrypted_data)
                return json.loads(decrypted_data)
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Error loading audit logs: {e}")
        return []

def save_audit_logs(logs):
    """Save audit logs to the encrypted file."""
    try:
        encrypted_data = encrypt_password(json.dumps(logs, indent=4))
        with open(AUDIT_LOG_FILE, 'w') as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"Error saving audit logs: {e}")

def log_action(action, details, status="success"):
    """
    Log an action in the audit log.
    
    Args:
        action (str): The type of action performed
        details (dict): Additional details about the action
        status (str): Status of the action (success/failure)
    """
    try:
        logs = load_audit_logs()
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details,
            "status": status
        }
        
        logs.append(log_entry)
        save_audit_logs(logs)
    except Exception as e:
        print(f"Error logging action: {e}")

def filter_logs(logs, start_date=None, end_date=None, action_type=None, status=None):
    """Filter logs based on criteria."""
    filtered_logs = logs
    
    if start_date:
        filtered_logs = [log for log in filtered_logs 
                        if datetime.fromisoformat(log["timestamp"]) >= start_date]
    
    if end_date:
        filtered_logs = [log for log in filtered_logs 
                        if datetime.fromisoformat(log["timestamp"]) <= end_date]
    
    if action_type:
        filtered_logs = [log for log in filtered_logs 
                        if log["action"] == action_type]
    
    if status:
        filtered_logs = [log for log in filtered_logs 
                        if log["status"] == status]
    
    return filtered_logs

def parse_date(date_str):
    """Parse date string in YYYY-MM-DD format."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None

def view_audit_logs():
    """Display audit logs with filtering and analysis options."""
    while True:
        print("\nAudit Log Management")
        print("-" * 20)
        print("1. View All Logs")
        print("2. Filter Logs")
        print("3. View Audit Summary")
        print("4. Check Suspicious Activity")
        print("5. Return to Main Menu")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == "1":
            display_all_logs()
        elif choice == "2":
            filter_and_display_logs()
        elif choice == "3":
            display_audit_summary()
        elif choice == "4":
            suspicious = detect_suspicious_activity()
            if suspicious:
                print("\nSuspicious Activities Detected:")
                for activity in suspicious:
                    print(f"\nType: {activity['type']}")
                    for key, value in activity.items():
                        if key != 'type':
                            print(f"{key.capitalize()}: {value}")
            else:
                print("\nNo suspicious activities detected in the last 24 hours.")
            input("\nPress Enter to continue...")
        elif choice == "5":
            return
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

def display_all_logs():
    """Display all audit logs with pagination."""
    logs = load_audit_logs()
    if not logs:
        print("No audit logs found.")
        return
    
    page_size = 10
    current_page = 0
    total_pages = (len(logs) + page_size - 1) // page_size
    
    while True:
        start_idx = current_page * page_size
        end_idx = min(start_idx + page_size, len(logs))
        
        print(f"\nAudit Logs (Page {current_page + 1} of {total_pages})")
        print("-" * 80)
        
        for log in logs[start_idx:end_idx]:
            timestamp = datetime.fromisoformat(log["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            print(f"Time: {timestamp}")
            print(f"Action: {log['action']}")
            print(f"Status: {log['status']}")
            print("Details:")
            for key, value in log["details"].items():
                print(f"  {key}: {value}")
            print("-" * 80)
        
        print("\nNavigation:")
        print("n - Next page")
        print("p - Previous page")
        print("q - Return to menu")
        
        cmd = input("\nEnter command: ").lower()
        if cmd == 'n' and current_page < total_pages - 1:
            current_page += 1
        elif cmd == 'p' and current_page > 0:
            current_page -= 1
        elif cmd == 'q':
            break

def filter_and_display_logs():
    """Filter and display audit logs based on various criteria."""
    print("\nFilter Logs")
    print("-" * 20)
    
    # Get filter criteria
    print("\nEnter filter criteria (press Enter to skip):")
    
    start_date_str = input("Start date (YYYY-MM-DD): ")
    end_date_str = input("End date (YYYY-MM-DD): ")
    
    start_date = parse_date(start_date_str) if start_date_str else None
    end_date = parse_date(end_date_str) if end_date_str else None
    
    if start_date and end_date and start_date > end_date:
        print("Invalid date range: Start date must be before end date.")
        return
    
    # Get action type filter
    print("\nAvailable action types:")
    logs = load_audit_logs()
    action_types = sorted(set(log["action"] for log in logs))
    for i, action in enumerate(action_types, 1):
        print(f"{i}. {action}")
    print("0. All actions")
    
    try:
        action_choice = input("\nEnter action number: ")
        action_type = action_types[int(action_choice) - 1] if action_choice != "0" else None
    except (ValueError, IndexError):
        action_type = None
    
    # Get status filter
    status = input("\nEnter status to filter (success/failure/all): ").lower()
    if status not in ["success", "failure"]:
        status = None
    
    # Apply filters
    filtered_logs = filter_logs(logs, start_date, end_date, action_type, status)
    
    if not filtered_logs:
        print("\nNo logs found matching the filter criteria.")
        return
    
    # Display filtered logs with pagination
    page_size = 10
    current_page = 0
    total_pages = (len(filtered_logs) + page_size - 1) // page_size
    
    while True:
        start_idx = current_page * page_size
        end_idx = min(start_idx + page_size, len(filtered_logs))
        
        print(f"\nFiltered Logs (Page {current_page + 1} of {total_pages})")
        print("-" * 80)
        
        for log in filtered_logs[start_idx:end_idx]:
            timestamp = datetime.fromisoformat(log["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            print(f"Time: {timestamp}")
            print(f"Action: {log['action']}")
            print(f"Status: {log['status']}")
            print("Details:")
            for key, value in log["details"].items():
                print(f"  {key}: {value}")
            print("-" * 80)
        
        print("\nNavigation:")
        print("n - Next page")
        print("p - Previous page")
        print("q - Return to menu")
        
        cmd = input("\nEnter command: ").lower()
        if cmd == 'n' and current_page < total_pages - 1:
            current_page += 1
        elif cmd == 'p' and current_page > 0:
            current_page -= 1
        elif cmd == 'q':
            break

def display_audit_summary():
    """Display a comprehensive audit summary with graphs and alerts."""
    print("\nAudit Summary")
    print("-" * 20)
    
    # Check for suspicious activities
    suspicious = detect_suspicious_activity()
    if suspicious:
        print("\nSUSPICIOUS ACTIVITY ALERTS:")
        print("-" * 25)
        for activity in suspicious:
            print(f"\nType: {activity['type']}")
            for key, value in activity.items():
                if key != 'type':
                    print(f"{key.capitalize()}: {value}")
    else:
        print("\nNo suspicious activities detected in the last 24 hours.")
    
    # Generate and display graphs
    print("\nGenerating activity graphs...")
    
    # Login frequency graph
    login_graph = generate_login_frequency_graph()
    if login_graph:
        print("\nLogin frequency graph has been generated.")
        # In a GUI environment, you would display this graph
        # For now, we'll just indicate it's available
    
    # Activity distribution
    activity_graph = generate_activity_summary()
    if activity_graph:
        print("Activity distribution graph has been generated.")
        # In a GUI environment, you would display this graph
    
    print("\nPress Enter to continue...")
    input()

def detect_suspicious_activity():
    """Detect suspicious activities in the audit logs."""
    logs = load_audit_logs()
    suspicious = []
    
    # Check for suspicious activities
    for log in logs:
        if log["action"] == "Login Attempt" and log["status"] == "failure":
            suspicious.append({
                "type": "Login Attempt",
                "account": log["details"]["account"],
                "timestamp": log["timestamp"]
            })
    
    return suspicious

def generate_login_frequency_graph():
    """Generate a login frequency graph."""
    # This is a placeholder implementation
    # You would implement this function based on your specific requirements
    return True

def generate_activity_summary():
    """Generate an activity summary graph."""
    # This is a placeholder implementation
    # You would implement this function based on your specific requirements
    return True

def list_secure_notes():
    """List all secure notes titles."""
    print("\nSecure Notes")
    print("-" * 20)
    
    if not secure_notes:
        print("No secure notes found.")
        log_action(AuditAction.VIEW_NOTE, {"error": "No notes found"}, "failure")
        return
    
    print("Your secure notes:")
    for i, title in enumerate(sorted(secure_notes.keys()), 1):
        created_date = datetime.fromisoformat(secure_notes[title]['created_date']).strftime('%Y-%m-%d')
        print(f"{i}. {title} (Created: {created_date})")
    
    print("\nEnter note number to view its content (or press Enter to return):")
    choice = input("> ")
    
    if choice.strip():
        try:
            index = int(choice) - 1
            if 0 <= index < len(secure_notes):
                title = sorted(secure_notes.keys())[index]
                note = secure_notes[title]
                decrypted_content = decrypt_password(note['content'])
                
                print(f"\nTitle: {title}")
                print("-" * (len(title) + 7))
                print(f"Created: {datetime.fromisoformat(note['created_date']).strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Last Modified: {datetime.fromisoformat(note['last_modified']).strftime('%Y-%m-%d %H:%M:%S')}")
                print("\nContent:")
                print("-" * 7)
                print(decrypted_content)
                
                log_action(AuditAction.VIEW_NOTE, {"title": title}, "success")
            else:
                print("Invalid note number.")
                log_action(AuditAction.VIEW_NOTE, {"error": "Invalid note number"}, "failure")
        except ValueError:
            print("Invalid input. Please enter a number.")
            log_action(AuditAction.VIEW_NOTE, {"error": "Invalid input"}, "failure")

def load_trusted_contacts():
    """Load trusted contacts from the JSON file."""
    try:
        with open(TRUSTED_CONTACTS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"contacts": []}

def save_trusted_contacts(contacts_data):
    """Save trusted contacts to the JSON file."""
    with open(TRUSTED_CONTACTS_FILE, 'w') as f:
        json.dump(contacts_data, f, indent=4)

def generate_emergency_token():
    """Generate a unique emergency access token."""
    return str(uuid.uuid4())

def send_emergency_email(email, token, action="request"):
    """Send emergency access email to trusted contact."""
    # Note: Replace with your email configuration
    sender_email = "your_email@example.com"
    sender_password = "your_app_password"
    
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = email
    
    if action == "request":
        msg["Subject"] = "Emergency Access Request - Password Manager"
        body = f"""
        You have been granted emergency access to the password manager.
        Your emergency access token is: {token}
        
        Please keep this token secure and use it only in case of emergency.
        """
    elif action == "notification":
        msg["Subject"] = "Emergency Access Notification - Password Manager"
        body = "Someone has requested emergency access using your trusted contact status."
    
    msg.attach(MIMEText(body, "plain"))
    
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def add_trusted_contact():
    """Add a new trusted contact."""
    print("\nAdd Trusted Contact")
    print("-" * 20)
    
    name = input("Enter contact name: ")
    email = input("Enter contact email: ")
    
    contacts_data = load_trusted_contacts()
    
    # Check if contact already exists
    if any(c["email"] == email for c in contacts_data["contacts"]):
        print("This email is already registered as a trusted contact.")
        return
    
    # Generate and encrypt emergency access token
    token = generate_emergency_token()
    encrypted_token = encrypt_password(token)
    
    new_contact = {
        "name": name,
        "email": email,
        "token": encrypted_token,
        "added_date": datetime.now().isoformat(),
        "status": "active"
    }
    
    try:
        # Send email to trusted contact
        if send_emergency_email(email, token):
            contacts_data["contacts"].append(new_contact)
            save_trusted_contacts(contacts_data)
            print(f"\nTrusted contact {name} added successfully!")
            log_action(AuditAction.ADD_TRUSTED_CONTACT, {
                "name": name,
                "email": email
            }, "success")
        else:
            print("Failed to send emergency access email. Contact not added.")
            log_action(AuditAction.ADD_TRUSTED_CONTACT, {
                "name": name,
                "email": email,
                "error": "Email sending failed"
            }, "failure")
    except Exception as e:
        print(f"Error adding trusted contact: {e}")
        log_action(AuditAction.ADD_TRUSTED_CONTACT, {
            "name": name,
            "email": email,
            "error": str(e)
        }, "failure")

def remove_trusted_contact():
    """Remove a trusted contact."""
    print("\nRemove Trusted Contact")
    print("-" * 20)
    
    contacts_data = load_trusted_contacts()
    if not contacts_data["contacts"]:
        print("No trusted contacts found.")
        return
    
    print("\nCurrent trusted contacts:")
    for i, contact in enumerate(contacts_data["contacts"], 1):
        print(f"{i}. {contact['name']} ({contact['email']})")
    
    try:
        choice = int(input("\nEnter the number of the contact to remove: ")) - 1
        if 0 <= choice < len(contacts_data["contacts"]):
            contact = contacts_data["contacts"][choice]
            confirm = input(f"Are you sure you want to remove {contact['name']}? (y/n): ")
            
            if confirm.lower() == 'y':
                removed_contact = contacts_data["contacts"].pop(choice)
                save_trusted_contacts(contacts_data)
                print(f"\nTrusted contact {removed_contact['name']} removed successfully!")
                log_action(AuditAction.REMOVE_TRUSTED_CONTACT, {
                    "name": removed_contact['name'],
                    "email": removed_contact['email']
                }, "success")
        else:
            print("Invalid contact number.")
    except (ValueError, IndexError):
        print("Invalid input. Please enter a valid number.")
    except Exception as e:
        print(f"Error removing trusted contact: {e}")

def verify_emergency_access():
    """Verify emergency access request."""
    print("\nEmergency Access Verification")
    print("-" * 20)
    
    email = input("Enter your email: ")
    token = input("Enter your emergency access token: ")
    
    contacts_data = load_trusted_contacts()
    contact = next((c for c in contacts_data["contacts"] if c["email"] == email), None)
    
    if not contact:
        print("Email not found in trusted contacts.")
        log_action(AuditAction.EMERGENCY_ACCESS_DENIED, {
            "email": email,
            "reason": "Contact not found"
        }, "failure")
        return False
    
    try:
        stored_token = decrypt_password(contact["token"])
        if token == stored_token:
            # Send notification to primary user (implement your notification method)
            print("\nEmergency access granted!")
            log_action(AuditAction.EMERGENCY_ACCESS_GRANTED, {
                "email": email
            }, "success")
            return True
        else:
            print("Invalid emergency access token.")
            log_action(AuditAction.EMERGENCY_ACCESS_DENIED, {
                "email": email,
                "reason": "Invalid token"
            }, "failure")
            return False
    except Exception as e:
        print(f"Error verifying emergency access: {e}")
        log_action(AuditAction.EMERGENCY_ACCESS_DENIED, {
            "email": email,
            "error": str(e)
        }, "failure")
        return False

def emergency_access_menu():
    """Display emergency access management menu."""
    while True:
        print("\nEmergency Access Management")
        print("-" * 20)
        print("1. Add Trusted Contact")
        print("2. Remove Trusted Contact")
        print("3. List Trusted Contacts")
        print("4. Request Emergency Access")
        print("5. Return to Main Menu")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == "1":
            add_trusted_contact()
        elif choice == "2":
            remove_trusted_contact()
        elif choice == "3":
            list_trusted_contacts()
        elif choice == "4":
            if verify_emergency_access():
                # Provide limited access to vault
                emergency_access_vault()
        elif choice == "5":
            return
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

def list_trusted_contacts():
    """List all trusted contacts."""
    print("\nTrusted Contacts")
    print("-" * 20)
    
    contacts_data = load_trusted_contacts()
    if not contacts_data["contacts"]:
        print("No trusted contacts found.")
        return
    
    print("\nCurrent trusted contacts:")
    for i, contact in enumerate(contacts_data["contacts"], 1):
        added_date = datetime.fromisoformat(contact["added_date"]).strftime("%Y-%m-%d")
        print(f"{i}. Name: {contact['name']}")
        print(f"   Email: {contact['email']}")
        print(f"   Added: {added_date}")
        print(f"   Status: {contact['status']}")
        print()

def emergency_access_vault():
    """Provide limited access to vault for emergency access."""
    print("\nEmergency Access Mode")
    print("-" * 20)
    print("You have been granted emergency access to the vault.")
    
    while True:
        print("\n1. View Passwords")
        print("2. View Secure Notes")
        print("3. Exit Emergency Access")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "1":
            list_accounts()
        elif choice == "2":
            list_secure_notes()
        elif choice == "3":
            print("\nExiting emergency access mode.")
            return
        else:
            print("Invalid choice. Please enter a number between 1 and 3.")

def is_biometric_available():
    """Check if biometric authentication is available on the system."""
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

def authenticate_with_biometrics():
    """Authenticate user using biometric authentication."""
    system = platform.system().lower()
    
    try:
        if system == "darwin":  # macOS
            import subprocess
            result = subprocess.run(["bioutil", "-c"], capture_output=True, text=True)
            success = result.returncode == 0
        elif system == "windows":
            # For Windows, you would typically use the Windows Hello API
            # This is a simplified example
            import ctypes
            success = ctypes.windll.user32.MessageBoxW(0, 
                "Please authenticate with Windows Hello", 
                "Biometric Authentication", 
                1) == 1
        elif system == "linux":
            import subprocess
            result = subprocess.run(["fprintd-verify"], capture_output=True, text=True)
            success = result.returncode == 0
        else:
            success = False
        
        log_action(AuditAction.BIOMETRIC_AUTH_ATTEMPT, 
                  {"method": "biometric", "platform": system},
                  "success" if success else "failure")
        
        return success
    except Exception as e:
        log_action(AuditAction.BIOMETRIC_AUTH_ATTEMPT, {
            "method": "biometric",
            "platform": system,
            "error": str(e)
        }, "failure")
        return False

def load_biometric_config():
    """Load biometric authentication configuration."""
    try:
        with open(BIOMETRIC_CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"enabled": False}

def save_biometric_config(config):
    """Save biometric authentication configuration."""
    with open(BIOMETRIC_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def setup_biometric_auth():
    """Set up biometric authentication."""
    print("\nBiometric Authentication Setup")
    print("-" * 20)
    
    if not is_biometric_available():
        print("Biometric authentication is not available on your system.")
        return False
    
    print("This will enable biometric authentication for logging in.")
    print("You will still need your master password as a backup.")
    
    confirm = input("\nDo you want to proceed? (y/n): ")
    if confirm.lower() != 'y':
        return False
    
    # Verify current master password before enabling biometric auth
    if not check_master_password():
        print("Master password verification failed. Cannot enable biometric authentication.")
        return False
    
    # Test biometric authentication
    print("\nPlease authenticate with your biometric sensor to confirm setup.")
    if authenticate_with_biometrics():
        config = {"enabled": True, "setup_date": datetime.now().isoformat()}
        save_biometric_config(config)
        print("\nBiometric authentication enabled successfully!")
        return True
    else:
        print("\nBiometric authentication setup failed.")
        return False

def disable_biometric_auth():
    """Disable biometric authentication."""
    print("\nDisable Biometric Authentication")
    print("-" * 20)
    
    # Verify master password before disabling
    if not check_master_password():
        print("Master password verification failed. Cannot disable biometric authentication.")
        return False
    
    config = {"enabled": False}
    save_biometric_config(config)
    print("\nBiometric authentication disabled successfully!")
    return True

def passwordless_auth_menu():
    """Display passwordless authentication management menu."""
    while True:
        print("\nPasswordless Authentication Management")
        print("-" * 20)
        
        biometric_config = load_biometric_config()
        if biometric_config["enabled"]:
            print("Biometric Status: Enabled")
            print("1. Disable Biometric Authentication")
        else:
            print("Biometric Status: Disabled")
            print("1. Enable Biometric Authentication")
        
        print("2. Return to Main Menu")
        
        choice = input("\nEnter your choice (1-2): ")
        
        if choice == "1":
            if biometric_config["enabled"]:
                disable_biometric_auth()
            else:
                setup_biometric_auth()
        elif choice == "2":
            return
        else:
            print("Invalid choice. Please enter 1 or 2.")

def main_menu():
    """
    Display the main menu options to the user.
    """
    while True:
        print("\nPassword Manager")
        print("-" * 20)
        print("1. Add Password")
        print("2. Retrieve Password")
        print("3. List Accounts")
        print("4. Remove Password")
        print("5. Generate Strong Password")
        print("6. Backup and Restore")
        print("7. MFA Settings")
        print("8. Password Health Report")
        print("9. Improve Passwords")
        print("10. Secure Notes")
        print("11. View Audit Logs")
        print("12. Emergency Access")
        print("13. Passwordless Authentication")
        print("14. Exit")
        
        try:
            choice = input("\nEnter your choice (1-14): ")
            
            if choice == "1":
                add_password()
            elif choice == "2":
                retrieve_password()
            elif choice == "3":
                list_accounts()
            elif choice == "4":
                remove_password()
            elif choice == "5":
                generate_password_menu()
            elif choice == "6":
                backup_menu()
            elif choice == "7":
                mfa_menu()
            elif choice == "8":
                analyze_password_health()
            elif choice == "9":
                improve_passwords()
            elif choice == "10":
                secure_notes_menu()
            elif choice == "11":
                view_audit_logs()
            elif choice == "12":
                emergency_access_menu()
            elif choice == "13":
                passwordless_auth_menu()
            elif choice == "14":
                print("Goodbye!")
                exit()
            else:
                print("Invalid choice. Please enter a number between 1 and 14.")
        except KeyboardInterrupt:
            print("\nGoodbye!")
            exit()
        except Exception as e:
            print(f"An error occurred: {e}")

def main():
    """
    Main entry point of the password manager application.
    """
    # Verify master password before proceeding
    if not verify_master_password():
        print("Access denied. Exiting...")
        exit(1)
    
    # Verify MFA if enabled
    if not verify_mfa():
        print("MFA verification failed. Exiting...")
        exit(1)
    
    main_menu()

if __name__ == "__main__":
    main()

