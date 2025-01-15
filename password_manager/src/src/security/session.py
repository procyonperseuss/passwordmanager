"""Session management module for handling user sessions."""

import os
import json
import time
from datetime import datetime, timedelta
from ..config.settings import DATA_DIR

class Session:
    """Class representing a single user session."""
    def __init__(self, user_id, ip_address):
        self.session_id = os.urandom(16).hex()
        self.user_id = user_id
        self.ip_address = ip_address
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.is_active = True

    def to_dict(self):
        """Convert session to dictionary for storage."""
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'is_active': self.is_active
        }

    @classmethod
    def from_dict(cls, data):
        """Create session from dictionary data."""
        session = cls(data['user_id'], data['ip_address'])
        session.session_id = data['session_id']
        session.created_at = datetime.fromisoformat(data['created_at'])
        session.last_activity = datetime.fromisoformat(data['last_activity'])
        session.is_active = data['is_active']
        return session

class SessionManager:
    """Class for managing user sessions."""
    def __init__(self, timeout_minutes=15):
        self.sessions_file = os.path.join(DATA_DIR, 'sessions.json')
        self.timeout_minutes = timeout_minutes
        self.sessions = self._load_sessions()

    def _load_sessions(self):
        """Load sessions from file."""
        try:
            if os.path.exists(self.sessions_file):
                with open(self.sessions_file, 'r') as f:
                    data = json.load(f)
                    return {
                        sid: Session.from_dict(sdata)
                        for sid, sdata in data.items()
                    }
            return {}
        except Exception as e:
            print(f"Error loading sessions: {e}")
            return {}

    def _save_sessions(self):
        """Save sessions to file."""
        try:
            os.makedirs(os.path.dirname(self.sessions_file), exist_ok=True)
            with open(self.sessions_file, 'w') as f:
                json.dump(
                    {sid: session.to_dict() for sid, session in self.sessions.items()},
                    f,
                    indent=4
                )
        except Exception as e:
            print(f"Error saving sessions: {e}")

    def create_session(self, user_id, ip_address):
        """Create a new session for a user."""
        # Clean up expired sessions first
        self.cleanup_expired_sessions()
        
        # Create new session
        session = Session(user_id, ip_address)
        self.sessions[session.session_id] = session
        self._save_sessions()
        
        return session.session_id

    def validate_session(self, session_id):
        """Validate a session and update last activity."""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]
        
        # Check if session is active
        if not session.is_active:
            return False

        # Check for timeout
        if self._is_session_expired(session):
            self.end_session(session_id)
            return False

        # Update last activity
        session.last_activity = datetime.now()
        self._save_sessions()
        return True

    def end_session(self, session_id):
        """End a specific session."""
        if session_id in self.sessions:
            self.sessions[session_id].is_active = False
            self._save_sessions()

    def end_all_sessions(self, user_id):
        """End all sessions for a specific user."""
        for session in self.sessions.values():
            if session.user_id == user_id:
                session.is_active = False
        self._save_sessions()

    def get_active_sessions(self, user_id=None):
        """Get all active sessions, optionally filtered by user."""
        active_sessions = {}
        for sid, session in self.sessions.items():
            if session.is_active and not self._is_session_expired(session):
                if user_id is None or session.user_id == user_id:
                    active_sessions[sid] = session
        return active_sessions

    def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        for session in list(self.sessions.values()):
            if self._is_session_expired(session):
                session.is_active = False
        self._save_sessions()

    def _is_session_expired(self, session):
        """Check if a session has expired."""
        if not session.is_active:
            return True
            
        expiry_time = session.last_activity + timedelta(minutes=self.timeout_minutes)
        return datetime.now() > expiry_time 