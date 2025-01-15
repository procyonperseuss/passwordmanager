"""File handling operations for the password manager."""

import os
import json
import shutil
from datetime import datetime
from ..config.settings import (
    PASSWORDS_FILE,
    BACKUP_DIR,
    NOTES_FILE,
    MFA_CONFIG_FILE,
    BACKUP_CODES_FILE
)

class FileHandler:
    def __init__(self):
        """Initialize the FileHandler."""
        self.BACKUP_DIR = BACKUP_DIR
        self.MFA_CONFIG_FILE = MFA_CONFIG_FILE
        self.BACKUP_CODES_FILE = BACKUP_CODES_FILE
        
        # Create necessary directories
        os.makedirs(os.path.dirname(PASSWORDS_FILE), exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)

    def load_json_file(self, file_path, default_value=None):
        """Load data from a JSON file."""
        try:
            if not os.path.exists(file_path):
                return default_value
            with open(file_path, 'r') as file:
                return json.load(file)
        except Exception as e:
            print(f"Error loading {file_path}: {str(e)}")
            return default_value

    def save_json_file(self, file_path, data):
        """Save data to a JSON file."""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
        except Exception as e:
            print(f"Error saving {file_path}: {str(e)}")
            raise

    def load_passwords(self):
        """Load passwords from the JSON file."""
        return self.load_json_file(PASSWORDS_FILE, {})

    def save_passwords(self, passwords_dict):
        """Save passwords to the JSON file."""
        self.save_json_file(PASSWORDS_FILE, passwords_dict)

    def load_secure_notes(self):
        """Load secure notes from the JSON file."""
        return self.load_json_file(NOTES_FILE, {})

    def save_secure_notes(self, notes_dict):
        """Save secure notes to the JSON file."""
        self.save_json_file(NOTES_FILE, notes_dict)

    def create_backup(self):
        """Create a backup of all password manager data."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = os.path.join(self.BACKUP_DIR, f'backup_{timestamp}')
            os.makedirs(backup_path, exist_ok=True)

            # List of files to backup
            files_to_backup = [
                PASSWORDS_FILE,
                NOTES_FILE,
                MFA_CONFIG_FILE,
                BACKUP_CODES_FILE
            ]

            # Copy each file if it exists
            for file_path in files_to_backup:
                if os.path.exists(file_path):
                    shutil.copy2(file_path, backup_path)

            return backup_path
        except Exception as e:
            print(f"Error creating backup: {str(e)}")
            raise

    def restore_from_backup(self, backup_path):
        """Restore data from a backup."""
        try:
            if not os.path.exists(backup_path):
                raise FileNotFoundError(f"Backup not found: {backup_path}")

            # List of files to restore
            files_to_restore = [
                PASSWORDS_FILE,
                NOTES_FILE,
                MFA_CONFIG_FILE,
                BACKUP_CODES_FILE
            ]

            # Restore each file if it exists in the backup
            for file_path in files_to_restore:
                backup_file = os.path.join(backup_path, os.path.basename(file_path))
                if os.path.exists(backup_file):
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    shutil.copy2(backup_file, file_path)

        except Exception as e:
            print(f"Error restoring from backup: {str(e)}")
            raise

    def list_backups(self):
        """List all available backups."""
        try:
            if not os.path.exists(self.BACKUP_DIR):
                return []

            backups = []
            for item in os.listdir(self.BACKUP_DIR):
                backup_path = os.path.join(self.BACKUP_DIR, item)
                if os.path.isdir(backup_path) and item.startswith('backup_'):
                    backup_time = datetime.strptime(item.replace('backup_', ''), '%Y%m%d_%H%M%S')
                    backups.append({
                        'path': backup_path,
                        'timestamp': backup_time,
                        'size': self._get_dir_size(backup_path)
                    })

            return sorted(backups, key=lambda x: x['timestamp'], reverse=True)
        except Exception as e:
            print(f"Error listing backups: {str(e)}")
            return []

    def _get_dir_size(self, path):
        """Get the total size of a directory in bytes."""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                total_size += os.path.getsize(file_path)
        return total_size 