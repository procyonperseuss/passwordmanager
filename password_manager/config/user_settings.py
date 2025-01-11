"""
User settings management for the password manager.
"""

import os
import json
from pathlib import Path

class UserSettings:
    def __init__(self):
        """Initialize user settings."""
        self.settings_file = os.path.join(str(Path.home()), '.password_manager', 'settings.json')
        self.settings = self.load_settings()

    def load_settings(self):
        """Load settings from file or create with defaults."""
        defaults = {
            'user_email': '',
            'email_settings': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': '',
                'sender_password': ''  # Should be an app-specific password for Gmail
            },
            'default_password_length': 16,
            'password_preview_enabled': True,
            'preview_chars': 3,
            'password_age_warning': 90,  # days
            'theme': 'default',
            'auto_backup': True,
            'backup_frequency': 7,  # days
            'max_failed_attempts': 3,
            'session_timeout': 30  # minutes
        }

        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    saved_settings = json.load(f)
                    # Merge with defaults to ensure all settings exist
                    return {**defaults, **saved_settings}
            else:
                os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
                self.save_settings(defaults)
                return defaults
        except Exception as e:
            print(f"Error loading settings: {str(e)}")
            return defaults

    def save_settings(self, settings=None):
        """Save settings to file."""
        if settings is not None:
            self.settings = settings
        try:
            os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            print(f"Error saving settings: {str(e)}")

    def get(self, key, default=None):
        """Get a setting value."""
        return self.settings.get(key, default)

    def set(self, key, value):
        """Set a setting value and save."""
        self.settings[key] = value
        self.save_settings()

    def reset_to_defaults(self):
        """Reset settings to defaults."""
        self.settings = self.load_settings()
        self.save_settings()

    def update_email_settings(self, smtp_server=None, smtp_port=None, sender_email=None, sender_password=None):
        """Update email settings."""
        if smtp_server:
            self.settings['email_settings']['smtp_server'] = smtp_server
        if smtp_port:
            self.settings['email_settings']['smtp_port'] = smtp_port
        if sender_email:
            self.settings['email_settings']['sender_email'] = sender_email
        if sender_password:
            self.settings['email_settings']['sender_password'] = sender_password
        self.save_settings()

    def get_email_settings(self):
        """Get email settings."""
        return self.settings.get('email_settings', {}) 