"""
User settings management for the password manager.
"""

import os
import json
from pathlib import Path

DEFAULT_SETTINGS = {
    "data_directory": "~/.password_manager/data",
    "backup_directory": "~/.password_manager/backups",
    "show_password_preview": True,
    "password_preview_chars": 3,
    "default_password_length": 16,
    "password_age_warning": 90,  # days
    "max_failed_attempts": 3,
    "session_timeout": 300,  # seconds
    "theme": {
        "header": "bold blue",
        "success": "bold green",
        "error": "bold red",
        "warning": "bold yellow",
        "info": "bold cyan"
    }
}

class UserSettings:
    def __init__(self):
        self.settings_file = os.path.expanduser("~/.password_manager/settings.json")
        self.settings = self.load_settings()
        self.ensure_directories()

    def load_settings(self):
        """Load user settings from file or create with defaults."""
        try:
            with open(self.settings_file, 'r') as f:
                settings = json.load(f)
                # Merge with defaults to ensure all settings exist
                return {**DEFAULT_SETTINGS, **settings}
        except FileNotFoundError:
            self.save_settings(DEFAULT_SETTINGS)
            return DEFAULT_SETTINGS

    def save_settings(self, settings):
        """Save settings to file."""
        os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
        with open(self.settings_file, 'w') as f:
            json.dump(settings, f, indent=4)

    def ensure_directories(self):
        """Ensure all required directories exist."""
        directories = [
            os.path.expanduser(self.settings["data_directory"]),
            os.path.expanduser(self.settings["backup_directory"])
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def get_setting(self, key):
        """Get a setting value."""
        return self.settings.get(key, DEFAULT_SETTINGS.get(key))

    def set_setting(self, key, value):
        """Set a setting value."""
        self.settings[key] = value
        self.save_settings(self.settings)

    def get_data_path(self, filename):
        """Get the full path for a data file."""
        data_dir = os.path.expanduser(self.settings["data_directory"])
        return os.path.join(data_dir, filename)

    def get_backup_path(self, filename):
        """Get the full path for a backup file."""
        backup_dir = os.path.expanduser(self.settings["backup_directory"])
        return os.path.join(backup_dir, filename)

    def reset_to_defaults(self):
        """Reset all settings to defaults."""
        self.settings = DEFAULT_SETTINGS.copy()
        self.save_settings(self.settings)

    def update_theme(self, theme_settings):
        """Update theme settings."""
        self.settings["theme"].update(theme_settings)
        self.save_settings(self.settings)

    def get_theme(self):
        """Get current theme settings."""
        return self.settings.get("theme", DEFAULT_SETTINGS["theme"]) 