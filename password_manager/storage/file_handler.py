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
    @staticmethod
    def load_json_file(file_path, default_value=None):
        """Load data from a JSON file."""
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return default_value if default_value is not None else {}

    @staticmethod
    def save_json_file(file_path, data):
        """Save data to a JSON file."""
        with open(file_path, 'w') as file:
            json.dump(data, file, indent=4)

    @staticmethod
    def save_binary_file(file_path, data):
        """Save binary data to a file."""
        with open(file_path, 'wb') as file:
            file.write(data)

    @staticmethod
    def load_binary_file(file_path):
        """Load binary data from a file."""
        with open(file_path, 'rb') as file:
            return file.read()

    def load_passwords(self):
        """Load passwords from the JSON file."""
        return self.load_json_file(PASSWORDS_FILE)

    def save_passwords(self, passwords_dict):
        """Save passwords to the JSON file."""
        self.save_json_file(PASSWORDS_FILE, passwords_dict)

    def load_secure_notes(self):
        """Load secure notes from the JSON file."""
        return self.load_json_file(NOTES_FILE)

    def save_secure_notes(self, notes_dict):
        """Save secure notes to the JSON file."""
        self.save_json_file(NOTES_FILE, notes_dict)

    def create_backup(self):
        """Create a backup of all password manager data."""
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"backup_{timestamp}")
        os.makedirs(backup_path)

        try:
            # Copy all necessary files to backup directory
            files_to_backup = [
                PASSWORDS_FILE,
                NOTES_FILE,
                AUDIT_LOG_FILE,
                MFA_CONFIG_FILE,
                BACKUP_CODES_FILE,
                TRUSTED_CONTACTS_FILE,
                BIOMETRIC_CONFIG_FILE
            ]

            for file_path in files_to_backup:
                if os.path.exists(file_path):
                    shutil.copy2(file_path, backup_path)

            return backup_path
        except Exception as e:
            raise Exception(f"Backup failed: {str(e)}")

    def restore_from_backup(self, backup_path):
        """Restore password manager data from a backup."""
        if not os.path.exists(backup_path):
            raise Exception("Backup directory not found")

        try:
            files_to_restore = [
                PASSWORDS_FILE,
                NOTES_FILE,
                AUDIT_LOG_FILE,
                MFA_CONFIG_FILE,
                BACKUP_CODES_FILE,
                TRUSTED_CONTACTS_FILE,
                BIOMETRIC_CONFIG_FILE
            ]

            for file_path in files_to_restore:
                backup_file = os.path.join(backup_path, os.path.basename(file_path))
                if os.path.exists(backup_file):
                    shutil.copy2(backup_file, file_path)

        except Exception as e:
            raise Exception(f"Restore failed: {str(e)}")

    def list_backups(self):
        """List all available backups."""
        if not os.path.exists(BACKUP_DIR):
            return []

        backups = []
        for item in os.listdir(BACKUP_DIR):
            if item.startswith("backup_"):
                backups.append(item)

        return sorted(backups, reverse=True)  # Most recent first 