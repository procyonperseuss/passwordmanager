"""Secure password sharing module."""

import json
import os
import secrets
from datetime import datetime, timedelta
from ..config.settings import DATA_DIR
from ..encryption.encryption_manager import EncryptionManager

class PasswordSharing:
    def __init__(self):
        """Initialize password sharing manager."""
        self.shares_file = os.path.join(DATA_DIR, 'shared_passwords.json')
        self.shares = self._load_shares()
        self.encryption = EncryptionManager()

    def _load_shares(self):
        """Load shared password data."""
        try:
            if os.path.exists(self.shares_file):
                with open(self.shares_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception:
            return {}

    def _save_shares(self):
        """Save shared password data."""
        with open(self.shares_file, 'w') as f:
            json.dump(self.shares, f, indent=4)

    def create_share(self, password, expiry_hours=24, max_accesses=1):
        """Create a new password share."""
        # Generate a secure sharing key
        share_id = secrets.token_urlsafe(32)
        access_key = secrets.token_urlsafe(16)

        # Encrypt the password with the access key
        encrypted_password = self.encryption.encrypt_data(password)

        self.shares[share_id] = {
            'encrypted_password': encrypted_password,
            'access_key': access_key,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(hours=expiry_hours)).isoformat(),
            'max_accesses': max_accesses,
            'access_count': 0,
            'access_log': []
        }

        self._save_shares()
        return {
            'share_id': share_id,
            'access_key': access_key,
            'expires_at': self.shares[share_id]['expires_at']
        }

    def access_shared_password(self, share_id, access_key):
        """Access a shared password."""
        if share_id not in self.shares:
            return None, "Share not found"

        share = self.shares[share_id]

        # Check expiration
        if datetime.now() > datetime.fromisoformat(share['expires_at']):
            self._cleanup_expired_share(share_id)
            return None, "Share has expired"

        # Verify access key
        if share['access_key'] != access_key:
            return None, "Invalid access key"

        # Check access count
        if share['access_count'] >= share['max_accesses']:
            return None, "Maximum access count reached"

        # Log access
        share['access_count'] += 1
        share['access_log'].append({
            'timestamp': datetime.now().isoformat(),
            'successful': True
        })

        # Get the password
        try:
            password = self.encryption.decrypt_data(share['encrypted_password'])
        except Exception:
            return None, "Error decrypting password"

        # Remove share if max accesses reached
        if share['access_count'] >= share['max_accesses']:
            self._cleanup_expired_share(share_id)
        else:
            self._save_shares()

        return password, "Success"

    def revoke_share(self, share_id):
        """Revoke a password share."""
        if share_id in self.shares:
            del self.shares[share_id]
            self._save_shares()
            return True
        return False

    def _cleanup_expired_share(self, share_id):
        """Remove an expired or fully used share."""
        if share_id in self.shares:
            del self.shares[share_id]
            self._save_shares()

    def cleanup_expired_shares(self):
        """Clean up all expired shares."""
        current_time = datetime.now()
        expired_shares = [
            share_id for share_id, share in self.shares.items()
            if current_time > datetime.fromisoformat(share['expires_at'])
        ]
        
        for share_id in expired_shares:
            self._cleanup_expired_share(share_id)

    def get_share_status(self, share_id):
        """Get the status of a password share."""
        if share_id not in self.shares:
            return None

        share = self.shares[share_id]
        expires_at = datetime.fromisoformat(share['expires_at'])
        time_remaining = expires_at - datetime.now()

        return {
            'created_at': share['created_at'],
            'expires_at': share['expires_at'],
            'time_remaining': str(time_remaining) if time_remaining.total_seconds() > 0 else "Expired",
            'access_count': share['access_count'],
            'max_accesses': share['max_accesses'],
            'is_expired': datetime.now() > expires_at,
            'access_log': share['access_log']
        } 