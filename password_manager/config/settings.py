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

# Define audit action types
class AuditAction:
    """Enum class for audit action types."""
    ADD_PASSWORD = "add_password"
    REMOVE_PASSWORD = "remove_password"
    VIEW_PASSWORD = "view_password"
    GENERATE_PASSWORD = "generate_password"
    MODIFY_PASSWORD = "modify_password"
    ADD_NOTE = "add_note"
    VIEW_NOTE = "view_note"
    REMOVE_NOTE = "remove_note"
    MODIFY_NOTE = "modify_note"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    SETTINGS_CHANGED = "settings_changed"
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    EMERGENCY_ACCESS_REQUEST = "emergency_access_request"
    EMERGENCY_ACCESS_GRANTED = "emergency_access_granted"
    EMERGENCY_ACCESS_DENIED = "emergency_access_denied"
    TRUSTED_CONTACT_ADDED = "trusted_contact_added"
    TRUSTED_CONTACT_REMOVED = "trusted_contact_removed"

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