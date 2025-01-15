"""Login attempt tracking and brute force protection module."""

import os
import json
from datetime import datetime, timedelta
from ..config.settings import DATA_DIR

class LoginAttempt:
    """Class representing a single login attempt."""
    def __init__(self, ip_address, user_id, success):
        self.timestamp = datetime.now()
        self.ip_address = ip_address
        self.user_id = user_id
        self.success = success

    def to_dict(self):
        """Convert login attempt to dictionary for storage."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'ip_address': self.ip_address,
            'user_id': self.user_id,
            'success': self.success
        }

    @classmethod
    def from_dict(cls, data):
        """Create login attempt from dictionary data."""
        attempt = cls(data['ip_address'], data['user_id'], data['success'])
        attempt.timestamp = datetime.fromisoformat(data['timestamp'])
        return attempt

class LoginTracker:
    """Class for tracking login attempts and preventing brute force attacks."""
    def __init__(self, max_attempts=3, block_duration_minutes=30, attempt_window_minutes=10):
        self.attempts_file = os.path.join(DATA_DIR, 'login_attempts.json')
        self.max_attempts = max_attempts
        self.block_duration = timedelta(minutes=block_duration_minutes)
        self.attempt_window = timedelta(minutes=attempt_window_minutes)
        self.attempts = self._load_attempts()
        self.blocked_ips = self._load_blocked_ips()

    def _load_attempts(self):
        """Load login attempts from file."""
        try:
            if os.path.exists(self.attempts_file):
                with open(self.attempts_file, 'r') as f:
                    data = json.load(f)
                    return [LoginAttempt.from_dict(attempt) for attempt in data]
            return []
        except Exception as e:
            print(f"Error loading login attempts: {e}")
            return []

    def _save_attempts(self):
        """Save login attempts to file."""
        try:
            os.makedirs(os.path.dirname(self.attempts_file), exist_ok=True)
            with open(self.attempts_file, 'w') as f:
                json.dump([attempt.to_dict() for attempt in self.attempts], f, indent=4)
        except Exception as e:
            print(f"Error saving login attempts: {e}")

    def _load_blocked_ips(self):
        """Load blocked IPs and their block expiry times."""
        blocked_file = os.path.join(DATA_DIR, 'blocked_ips.json')
        try:
            if os.path.exists(blocked_file):
                with open(blocked_file, 'r') as f:
                    data = json.load(f)
                    return {
                        ip: datetime.fromisoformat(expiry)
                        for ip, expiry in data.items()
                    }
            return {}
        except Exception:
            return {}

    def _save_blocked_ips(self):
        """Save blocked IPs to file."""
        blocked_file = os.path.join(DATA_DIR, 'blocked_ips.json')
        try:
            os.makedirs(os.path.dirname(blocked_file), exist_ok=True)
            with open(blocked_file, 'w') as f:
                json.dump(
                    {ip: expiry.isoformat() for ip, expiry in self.blocked_ips.items()},
                    f,
                    indent=4
                )
        except Exception as e:
            print(f"Error saving blocked IPs: {e}")

    def record_attempt(self, ip_address, user_id, success):
        """Record a login attempt."""
        # Add new attempt
        attempt = LoginAttempt(ip_address, user_id, success)
        self.attempts.append(attempt)
        
        # If failed attempt, check if IP should be blocked
        if not success:
            recent_failures = self.get_recent_failures(ip_address)
            if len(recent_failures) >= self.max_attempts:
                self.block_ip(ip_address)
        
        # Clean up old attempts
        self.cleanup_old_attempts()
        self._save_attempts()

    def is_ip_blocked(self, ip_address):
        """Check if an IP is currently blocked."""
        if ip_address in self.blocked_ips:
            expiry = self.blocked_ips[ip_address]
            if datetime.now() > expiry:
                # Block has expired
                del self.blocked_ips[ip_address]
                self._save_blocked_ips()
                return False
            return True
        return False

    def block_ip(self, ip_address):
        """Block an IP address."""
        self.blocked_ips[ip_address] = datetime.now() + self.block_duration
        self._save_blocked_ips()

    def unblock_ip(self, ip_address):
        """Manually unblock an IP address."""
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
            self._save_blocked_ips()

    def get_recent_failures(self, ip_address):
        """Get recent failed login attempts for an IP address."""
        cutoff_time = datetime.now() - self.attempt_window
        return [
            attempt for attempt in self.attempts
            if (attempt.ip_address == ip_address and
                not attempt.success and
                attempt.timestamp > cutoff_time)
        ]

    def get_attempts_for_user(self, user_id):
        """Get all login attempts for a specific user."""
        return [
            attempt for attempt in self.attempts
            if attempt.user_id == user_id
        ]

    def get_attempts_for_ip(self, ip_address):
        """Get all login attempts from a specific IP address."""
        return [
            attempt for attempt in self.attempts
            if attempt.ip_address == ip_address
        ]

    def cleanup_old_attempts(self):
        """Remove login attempts older than the attempt window."""
        cutoff_time = datetime.now() - self.attempt_window
        self.attempts = [
            attempt for attempt in self.attempts
            if attempt.timestamp > cutoff_time
        ]
        self._save_attempts()

    def get_blocked_ips(self):
        """Get all currently blocked IPs and their expiry times."""
        # Clean up expired blocks first
        for ip in list(self.blocked_ips.keys()):
            if datetime.now() > self.blocked_ips[ip]:
                del self.blocked_ips[ip]
        self._save_blocked_ips()
        return self.blocked_ips.copy() 