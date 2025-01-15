"""User settings management module."""

import os
import json
from ..config.settings import DATA_DIR

class UserSettings:
    def __init__(self):
        """Initialize user settings."""
        self.settings_file = os.path.join(DATA_DIR, 'user_settings.json')
        self.settings = self._load_settings()

    def _load_settings(self):
        """Load settings from file."""
        default_settings = {
            'theme': {
                'style': 'default',
                'color_scheme': 'dark',
                'menu_style': 'compact'
            },
            'email': {
                'smtp_server': '',
                'smtp_port': 587,
                'sender_email': '',
                'sender_password': ''
            },
            'security': {
                'session_timeout': 15,
                'max_login_attempts': 3,
                'password_expiry_days': 90,
                'require_mfa': False
            },
            'backup': {
                'auto_backup': True,
                'backup_interval_days': 7,
                'keep_backups': 5
            }
        }

        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    saved_settings = json.load(f)
                    # Merge with defaults to ensure all settings exist
                    return self._merge_settings(default_settings, saved_settings)
            return default_settings
        except Exception:
            return default_settings

    def _merge_settings(self, default, saved):
        """Recursively merge saved settings with defaults."""
        merged = default.copy()
        for key, value in saved.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_settings(merged[key], value)
            else:
                merged[key] = value
        return merged

    def get(self, key, default=None):
        """Get a setting value."""
        return self.settings.get(key, default)

    def get_email_settings(self):
        """Get email settings."""
        return self.settings.get('email', {})

    def update_email_settings(self, **kwargs):
        """Update email settings."""
        if 'email' not in self.settings:
            self.settings['email'] = {}
        self.settings['email'].update(kwargs)
        self.save()

    def update(self, settings):
        """Update settings with new values."""
        for key, value in settings.items():
            if isinstance(value, dict) and key in self.settings and isinstance(self.settings[key], dict):
                self.settings[key].update(value)
            else:
                self.settings[key] = value
        self.save()

    def save(self):
        """Save settings to file."""
        try:
            os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            raise Exception(f"Failed to save settings: {str(e)}")

    def reset_to_defaults(self):
        """Reset all settings to default values."""
        self.settings = self._load_settings()
        self.save() 