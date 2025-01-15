"""Configuration settings for the password manager."""

import os
from pathlib import Path

# Get user's home directory
HOME_DIR = str(Path.home())

# Base directory for all password manager data
DATA_DIR = os.path.join(HOME_DIR, '.password_manager', 'data')

# File paths
PASSWORDS_FILE = os.path.join(DATA_DIR, 'passwords.json')
KEY_FILE = os.path.join(DATA_DIR, 'key.key')
MASTER_PASSWORD_FILE = os.path.join(DATA_DIR, 'master.key')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')
MFA_CONFIG_FILE = os.path.join(DATA_DIR, 'mfa_config.json')
BACKUP_CODES_FILE = os.path.join(DATA_DIR, 'backup_codes.json')
NOTES_FILE = os.path.join(DATA_DIR, 'secure_notes.json')
AUDIT_LOG_FILE = os.path.join(DATA_DIR, 'audit_logs.json')
TRUSTED_CONTACTS_FILE = os.path.join(DATA_DIR, 'trusted_contacts.json')
EMERGENCY_ACCESS_CONFIG_FILE = os.path.join(DATA_DIR, 'emergency_access_config.json')
BIOMETRIC_CONFIG_FILE = os.path.join(DATA_DIR, 'biometric_config.json')

# Create necessary directories
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

# Security settings
MIN_PASSWORD_LENGTH = 12
MAX_FAILED_ATTEMPTS = 3
SESSION_TIMEOUT_MINUTES = 15
PASSWORD_HISTORY_SIZE = 5

# Audit settings
MAX_AUDIT_LOG_SIZE = 1000  # number of entries
AUDIT_RETENTION_DAYS = 90

# Backup settings
MAX_BACKUPS = 10
BACKUP_RETENTION_DAYS = 30

# Email configuration
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',  # For Gmail
    'smtp_port': 587,                 # For TLS
    'sender_email': '',               # Your Gmail address
    'sender_password': ''             # Your Gmail App Password
}

# Audit log action types
class AuditAction:
    # Authentication actions
    LOGIN_ATTEMPT = "Login Attempt"
    LOGOUT = "Logout"
    MFA_SETUP = "MFA Setup"
    MFA_DISABLE = "MFA Disable"
    BIOMETRIC_SETUP = "Biometric Setup"
    BIOMETRIC_DISABLE = "Biometric Disable"
    
    # Password actions
    ADD_PASSWORD = "Add Password"
    VIEW_PASSWORD = "View Password"
    UPDATE_PASSWORD = "Update Password"
    REMOVE_PASSWORD = "Remove Password"
    GENERATE_PASSWORD = "Generate Password"
    IMPORT_PASSWORDS = "Import Passwords"
    EXPORT_PASSWORDS = "Export Passwords"
    
    # Note actions
    ADD_NOTE = "Add Note"
    VIEW_NOTE = "View Note"
    UPDATE_NOTE = "Update Note"
    DELETE_NOTE = "Delete Note"
    
    # Backup actions
    CREATE_BACKUP = "Create Backup"
    RESTORE_BACKUP = "Restore Backup"
    
    # Emergency access actions
    EMERGENCY_ACCESS_REQUEST = "Emergency Access Request"
    EMERGENCY_ACCESS_GRANTED = "Emergency Access Granted"
    EMERGENCY_ACCESS_DENIED = "Emergency Access Denied"
    
    # Contact management
    ADD_TRUSTED_CONTACT = "Add Trusted Contact"
    REMOVE_TRUSTED_CONTACT = "Remove Trusted Contact"
    
    # Settings actions
    UPDATE_SETTINGS = "Update Settings"
    RESET_SETTINGS = "Reset Settings"
    
    # Security actions
    PASSWORD_HEALTH_CHECK = "Password Health Check"
    BREACH_CHECK = "Breach Check"
    TOGGLE_FAVORITE = "Toggle Favorite"

# Password strength categories
class PasswordStrength:
    WEAK = 'weak'
    MEDIUM = 'medium'
    STRONG = 'strong'

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    HEADER = '\033[95m'
    FAIL = '\033[91m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m' 