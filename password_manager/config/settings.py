"""
Configuration settings for the password manager.
Contains file paths, audit action types, and other constants.
"""

import os

# File paths for storing data
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

# Create data directory if it doesn't exist
os.makedirs(DATA_DIR, exist_ok=True)

PASSWORDS_FILE = os.path.join(DATA_DIR, "passwords.json")
KEY_FILE = os.path.join(DATA_DIR, "key.key")
MASTER_PASSWORD_FILE = os.path.join(DATA_DIR, "master.key")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
MFA_CONFIG_FILE = os.path.join(DATA_DIR, "mfa_config.json")
BACKUP_CODES_FILE = os.path.join(DATA_DIR, "backup_codes.json")
NOTES_FILE = os.path.join(DATA_DIR, "secure_notes.json")
AUDIT_LOG_FILE = os.path.join(DATA_DIR, "audit_logs.json")
TRUSTED_CONTACTS_FILE = os.path.join(DATA_DIR, "trusted_contacts.json")
EMERGENCY_ACCESS_CONFIG_FILE = os.path.join(DATA_DIR, "emergency_access_config.json")
BIOMETRIC_CONFIG_FILE = os.path.join(DATA_DIR, "biometric_config.json")

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

# Email settings (to be configured by user)
EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 465,
    "sender_email": None,  # To be configured by user
    "sender_password": None,  # To be configured by user
} 