"""Main password manager class."""

from .security.hardware_auth import HardwareAuthManager
from .security.session_manager import SessionManager
from .security.password_policy import PasswordPolicy
from .security.password_sharing import PasswordSharing
from .config.settings import HARDWARE_KEY_ENABLED

class PasswordManager:
    def __init__(self):
        """Initialize password manager."""
        self.hardware_auth = HardwareAuthManager()
        self.session_manager = SessionManager()
        self.password_policy = PasswordPolicy()
        self.password_sharing = PasswordSharing()

    def authenticate(self, username, password):
        """Authenticate user with password and optional hardware key."""
        # Check if IP is blocked
        if self.session_manager.is_ip_blocked():
            return False, "Too many failed attempts. Please try again later."

        # Verify password
        if not self._verify_password(username, password):
            self.session_manager.track_login_attempt(username, success=False)
            return False, "Invalid username or password"

        # Verify hardware key if enabled
        if HARDWARE_KEY_ENABLED and not self.hardware_auth.verify_key(username):
            self.session_manager.track_login_attempt(username, success=False)
            return False, "Hardware key verification failed"

        # Create session
        session_id = self.session_manager.create_session(username)
        self.session_manager.track_login_attempt(username, success=True)
        
        return True, session_id

    def add_password(self, account, username, password, session_id):
        """Add a new password."""
        # Validate session
        if not self.session_manager.validate_session(session_id):
            return False, "Session expired. Please log in again."

        # Check password against policy
        if self.password_policy.is_password_reused(username, self._hash_password(password)):
            return False, "Password has been used recently"

        # Add to password history
        self.password_policy.add_to_history(username, self._hash_password(password))
        
        return True, "Password added successfully"

    def get_password(self, account, session_id):
        """Retrieve a password."""
        # Validate session
        if not self.session_manager.validate_session(session_id):
            return None, "Session expired. Please log in again."

    def share_password(self, account, expiry_hours, max_accesses, session_id):
        """Share a password securely."""
        # Validate session
        if not self.session_manager.validate_session(session_id):
            return None, "Session expired. Please log in again."

        password_data = self.passwords.get(account)
        if not password_data:
            return None, "Account not found"

        share_info = self.password_sharing.create_share(
            password_data['password'],
            expiry_hours=expiry_hours,
            max_accesses=max_accesses
        )
        
        return share_info, "Password shared successfully"

    def access_shared_password(self, share_id, access_key):
        """Access a shared password."""
        return self.password_sharing.access_shared_password(share_id, access_key)

    def get_security_status(self, session_id):
        """Get overall security status."""
        # Validate session
        if not self.session_manager.validate_session(session_id):
            return None, "Session expired. Please log in again."

        return {
            'hardware_keys': len(self.hardware_auth.credentials),
            'active_sessions': len(self.session_manager.sessions),
            'expiring_passwords': len(self.password_policy.get_expiring_passwords()),
            'active_shares': len(self.password_sharing.shares)
        }

    def cleanup(self):
        """Cleanup resources before exit."""
        # End all sessions
        for session_id in list(self.session_manager.sessions.keys()):
            self.session_manager.end_session(session_id)
        
        # Cleanup expired shares
        self.password_sharing.cleanup_expired_shares() 