"""Session management and security tracking module."""

import time
import json
import os
from datetime import datetime, timedelta
from ..config.settings import DATA_DIR, SESSION_TIMEOUT_MINUTES, MAX_FAILED_ATTEMPTS
import socket
import requests

class SessionManager:
    def __init__(self):
        """Initialize session manager."""
        self.sessions_file = os.path.join(DATA_DIR, 'sessions.json')
        self.ip_tracking_file = os.path.join(DATA_DIR, 'ip_tracking.json')
        self.sessions = self._load_sessions()
        self.ip_tracking = self._load_ip_tracking()

    def _load_sessions(self):
        """Load active sessions from file."""
        try:
            if os.path.exists(self.sessions_file):
                with open(self.sessions_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception:
            return {}

    def _save_sessions(self):
        """Save active sessions to file."""
        with open(self.sessions_file, 'w') as f:
            json.dump(self.sessions, f, indent=4)

    def _load_ip_tracking(self):
        """Load IP tracking data from file."""
        try:
            if os.path.exists(self.ip_tracking_file):
                with open(self.ip_tracking_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception:
            return {}

    def _save_ip_tracking(self):
        """Save IP tracking data to file."""
        with open(self.ip_tracking_file, 'w') as f:
            json.dump(self.ip_tracking, f, indent=4)

    def create_session(self, username):
        """Create a new session for a user."""
        session_id = os.urandom(16).hex()
        ip_address = self._get_ip_address()
        
        self.sessions[session_id] = {
            'username': username,
            'created_at': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'ip_address': ip_address
        }
        
        self._save_sessions()
        return session_id

    def validate_session(self, session_id):
        """Validate a session and check for timeout."""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]
        last_activity = datetime.fromisoformat(session['last_activity'])
        
        # Check for session timeout
        if datetime.now() - last_activity > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            self.end_session(session_id)
            return False

        # Update last activity
        session['last_activity'] = datetime.now().isoformat()
        self._save_sessions()
        return True

    def end_session(self, session_id):
        """End a user session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
            self._save_sessions()

    def track_login_attempt(self, username, success=True):
        """Track login attempts by IP address."""
        ip_address = self._get_ip_address()
        current_time = datetime.now().isoformat()

        if ip_address not in self.ip_tracking:
            self.ip_tracking[ip_address] = {
                'attempts': [],
                'blocked_until': None
            }

        # Clean up old attempts
        self.ip_tracking[ip_address]['attempts'] = [
            attempt for attempt in self.ip_tracking[ip_address]['attempts']
            if datetime.fromisoformat(attempt['timestamp']) > datetime.now() - timedelta(hours=1)
        ]

        # Add new attempt
        self.ip_tracking[ip_address]['attempts'].append({
            'timestamp': current_time,
            'username': username,
            'success': success
        })

        # Check for too many failed attempts
        failed_attempts = sum(
            1 for attempt in self.ip_tracking[ip_address]['attempts']
            if not attempt['success']
        )

        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            # Block IP for 1 hour
            self.ip_tracking[ip_address]['blocked_until'] = (
                datetime.now() + timedelta(hours=1)
            ).isoformat()

        self._save_ip_tracking()

    def is_ip_blocked(self):
        """Check if current IP is blocked."""
        ip_address = self._get_ip_address()
        if ip_address not in self.ip_tracking:
            return False

        blocked_until = self.ip_tracking[ip_address].get('blocked_until')
        if not blocked_until:
            return False

        if datetime.now() > datetime.fromisoformat(blocked_until):
            # Remove block if time has expired
            self.ip_tracking[ip_address]['blocked_until'] = None
            self._save_ip_tracking()
            return False

        return True

    def _get_ip_address(self):
        """Get the current IP address."""
        try:
            # Try to get external IP
            response = requests.get('https://api.ipify.org')
            return response.text
        except Exception:
            # Fallback to local IP
            return socket.gethostbyname(socket.gethostname()) 