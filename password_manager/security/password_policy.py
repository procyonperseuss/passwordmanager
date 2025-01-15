"""Password policy management module."""

import json
import os
from datetime import datetime, timedelta
from ..config.settings import DATA_DIR

class PasswordPolicy:
    def __init__(self):
        """Initialize password policy manager."""
        self.policy_file = os.path.join(DATA_DIR, 'password_policy.json')
        self.history_file = os.path.join(DATA_DIR, 'password_history.json')
        self.policy = self._load_policy()
        self.history = self._load_history()

    def _load_policy(self):
        """Load password policy settings."""
        default_policy = {
            'max_age_days': 90,  # Passwords expire after 90 days
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special': True,
            'history_size': 5,  # Remember last 5 passwords
            'min_unique_chars': 8,
            'prohibited_patterns': [
                r'password',
                r'123456',
                r'qwerty'
            ]
        }

        try:
            if os.path.exists(self.policy_file):
                with open(self.policy_file, 'r') as f:
                    return {**default_policy, **json.load(f)}
            return default_policy
        except Exception:
            return default_policy

    def _save_policy(self):
        """Save password policy settings."""
        with open(self.policy_file, 'w') as f:
            json.dump(self.policy, f, indent=4)

    def _load_history(self):
        """Load password history."""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception:
            return {}

    def _save_history(self):
        """Save password history."""
        with open(self.history_file, 'w') as f:
            json.dump(self.history, f, indent=4)

    def update_policy(self, new_policy):
        """Update password policy settings."""
        self.policy.update(new_policy)
        self._save_policy()

    def add_to_history(self, username, password_hash):
        """Add a password to the history."""
        if username not in self.history:
            self.history[username] = []
        
        self.history[username].append({
            'hash': password_hash,
            'date': datetime.now().isoformat()
        })

        # Keep only the most recent passwords according to history_size
        if len(self.history[username]) > self.policy['history_size']:
            self.history[username] = self.history[username][-self.policy['history_size']:]
        
        self._save_history()

    def check_password_age(self, username, password_date):
        """Check if a password has expired."""
        if not password_date:
            return True  # Consider passwords without dates as expired
        
        password_datetime = datetime.fromisoformat(password_date)
        age = datetime.now() - password_datetime
        return age.days > self.policy['max_age_days']

    def is_password_reused(self, username, password_hash):
        """Check if a password has been used before."""
        if username not in self.history:
            return False
        
        return any(entry['hash'] == password_hash for entry in self.history[username])

    def get_expiring_passwords(self, days_warning=14):
        """Get list of passwords that will expire soon."""
        expiring = []
        warning_date = datetime.now() + timedelta(days=days_warning)
        
        for username, history in self.history.items():
            if not history:
                continue
                
            last_password = history[-1]
            password_date = datetime.fromisoformat(last_password['date'])
            expiry_date = password_date + timedelta(days=self.policy['max_age_days'])
            
            if datetime.now() < expiry_date <= warning_date:
                days_until_expiry = (expiry_date - datetime.now()).days
                expiring.append({
                    'username': username,
                    'days_until_expiry': days_until_expiry,
                    'expiry_date': expiry_date.isoformat()
                })
        
        return expiring

    def get_policy_summary(self):
        """Get a human-readable summary of the password policy."""
        return {
            'Maximum password age': f"{self.policy['max_age_days']} days",
            'Minimum length': self.policy['min_length'],
            'Required characters': [
                'Uppercase letters' if self.policy['require_uppercase'] else None,
                'Lowercase letters' if self.policy['require_lowercase'] else None,
                'Numbers' if self.policy['require_numbers'] else None,
                'Special characters' if self.policy['require_special'] else None
            ],
            'Password history': f"Last {self.policy['history_size']} passwords remembered",
            'Minimum unique characters': self.policy['min_unique_chars']
        } 