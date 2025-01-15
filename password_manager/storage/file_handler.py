"""
File handling operations for the password manager.
"""

import json
import os
import shutil
from datetime import datetime
from ..config.settings import (
    PASSWORDS_FILE,
    NOTES_FILE,
    AUDIT_LOG_FILE,
    BACKUP_DIR,
    MFA_CONFIG_FILE,
    BACKUP_CODES_FILE,
    TRUSTED_CONTACTS_FILE,
    BIOMETRIC_CONFIG_FILE
)

class FileHandler:
    def __init__(self):
        """Initialize the file handler."""
        self.PASSWORDS_FILE = PASSWORDS_FILE
        self.BACKUP_DIR = BACKUP_DIR
        self.NOTES_FILE = NOTES_FILE
        self.MFA_CONFIG_FILE = MFA_CONFIG_FILE
        self.BACKUP_CODES_FILE = BACKUP_CODES_FILE
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(PASSWORDS_FILE), exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        
        # Initialize files if they don't exist
        self._initialize_files()

    def _initialize_files(self):
        """Initialize necessary files with default structure if they don't exist."""
        # Initialize passwords file
        if not os.path.exists(self.PASSWORDS_FILE):
            self.save_passwords({})
        
        # Initialize notes file
        if not os.path.exists(self.NOTES_FILE):
            self.save_json_file(self.NOTES_FILE, {})
        
        # Initialize MFA config
        if not os.path.exists(self.MFA_CONFIG_FILE):
            self.save_json_file(self.MFA_CONFIG_FILE, {"enabled": False})
        
        # Initialize backup codes
        if not os.path.exists(self.BACKUP_CODES_FILE):
            self.save_json_file(self.BACKUP_CODES_FILE, {"backup_codes": []})

    def load_passwords(self):
        """Load passwords from file."""
        try:
            if not os.path.exists(self.PASSWORDS_FILE):
                return {}
            with open(self.PASSWORDS_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            # If file is corrupted, backup and create new
            if os.path.exists(self.PASSWORDS_FILE):
                backup_name = f"passwords_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                os.rename(self.PASSWORDS_FILE, os.path.join(self.BACKUP_DIR, backup_name))
            return {}
        except Exception as e:
            print(f"Error loading passwords: {str(e)}")
            return {}

    def save_passwords(self, passwords):
        """Save passwords to file."""
        try:
            os.makedirs(os.path.dirname(self.PASSWORDS_FILE), exist_ok=True)
            with open(self.PASSWORDS_FILE, 'w') as f:
                json.dump(passwords, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving passwords: {str(e)}")
            return False

    def load_json_file(self, filepath, default=None):
        """Load JSON data from file."""
        try:
            if not os.path.exists(filepath):
                return default if default is not None else {}
            with open(filepath, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            # If file is corrupted, backup and return default
            if os.path.exists(filepath):
                backup_name = f"{os.path.basename(filepath)}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                os.rename(filepath, os.path.join(self.BACKUP_DIR, backup_name))
            return default if default is not None else {}
        except Exception as e:
            print(f"Error loading file {filepath}: {str(e)}")
            return default if default is not None else {}

    def save_json_file(self, filepath, data):
        """Save JSON data to file."""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving file {filepath}: {str(e)}")
            return False

    def save_secure_notes(self, notes):
        """Save secure notes to file."""
        return self.save_json_file(self.NOTES_FILE, notes)

    def create_backup(self):
        """Create a backup of all important files."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir = os.path.join(self.BACKUP_DIR, f"backup_{timestamp}")
            os.makedirs(backup_dir, exist_ok=True)
            
            # Files to backup
            files_to_backup = [
                self.PASSWORDS_FILE,
                self.NOTES_FILE,
                self.MFA_CONFIG_FILE,
                self.BACKUP_CODES_FILE
            ]
            
            for file in files_to_backup:
                if os.path.exists(file):
                    backup_path = os.path.join(backup_dir, os.path.basename(file))
                    with open(file, 'r') as src, open(backup_path, 'w') as dst:
                        dst.write(src.read())
            
            return backup_dir
        except Exception as e:
            print(f"Error creating backup: {str(e)}")
            return None

    def restore_from_backup(self, backup_path):
        """Restore files from a backup."""
        try:
            for file in os.listdir(backup_path):
                src_path = os.path.join(backup_path, file)
                dst_path = os.path.join(os.path.dirname(self.PASSWORDS_FILE), file)
                with open(src_path, 'r') as src, open(dst_path, 'w') as dst:
                    dst.write(src.read())
            return True
        except Exception as e:
            print(f"Error restoring from backup: {str(e)}")
            return False

    def list_backups(self):
        """List available backups."""
        try:
            return [d for d in os.listdir(self.BACKUP_DIR) if d.startswith('backup_')]
        except Exception as e:
            print(f"Error listing backups: {str(e)}")
            return [] 