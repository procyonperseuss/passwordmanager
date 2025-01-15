"""Hardware security key authentication module."""

import time
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from ..config.settings import DATA_DIR
import os
import json

class HardwareAuthManager:
    def __init__(self):
        """Initialize hardware authentication manager."""
        self.credentials_file = os.path.join(DATA_DIR, 'hardware_credentials.json')
        self.rp = PublicKeyCredentialRpEntity("password-manager", "Secure Password Manager")
        self.server = Fido2Server(self.rp)
        self.credentials = self._load_credentials()

    def _load_credentials(self):
        """Load saved credentials from file."""
        try:
            if os.path.exists(self.credentials_file):
                with open(self.credentials_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Error loading credentials: {e}")
            return {}

    def _save_credentials(self):
        """Save credentials to file."""
        try:
            with open(self.credentials_file, 'w') as f:
                json.dump(self.credentials, f, indent=4)
        except Exception as e:
            print(f"Error saving credentials: {e}")

    def register_key(self, username):
        """Register a new hardware security key."""
        try:
            user = PublicKeyCredentialUserEntity(
                id=os.urandom(32),
                name=username,
                display_name=username
            )

            # Generate registration options
            options, state = self.server.register_begin(
                user,
                credentials=[],
                user_verification="preferred"
            )

            print("\nPlease insert your security key and touch it when it starts blinking...")
            time.sleep(1)  # Give user time to prepare

            # Here you would normally send these options to the authenticator
            # For CLI, we'll simulate the key touch
            attestation = self._simulate_key_touch()

            # Complete registration
            auth_data = self.server.register_complete(state, attestation)
            
            # Store the credential
            self.credentials[username] = {
                'credential_id': auth_data.credential_data.credential_id.hex(),
                'public_key': auth_data.credential_data.public_key.hex(),
                'sign_count': auth_data.sign_count,
                'registered_on': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self._save_credentials()
            return True

        except Exception as e:
            print(f"Error registering security key: {e}")
            return False

    def verify_key(self, username):
        """Verify a hardware security key."""
        try:
            if username not in self.credentials:
                print("No security key registered for this user")
                return False

            # Generate authentication options
            options, state = self.server.authenticate_begin(
                credentials=[self.credentials[username]],
                user_verification="preferred"
            )

            print("\nPlease insert your security key and touch it when it starts blinking...")
            time.sleep(1)  # Give user time to prepare

            # Here you would normally send these options to the authenticator
            # For CLI, we'll simulate the key touch
            assertion = self._simulate_key_touch()

            # Verify the assertion
            self.server.authenticate_complete(
                state,
                credentials=[self.credentials[username]],
                assertion=assertion
            )

            # Update sign count
            self.credentials[username]['sign_count'] += 1
            self._save_credentials()
            
            return True

        except Exception as e:
            print(f"Error verifying security key: {e}")
            return False

    def _simulate_key_touch(self):
        """Simulate security key touch (for demonstration)."""
        print("Waiting for key touch...")
        time.sleep(2)  # Simulate user touching the key
        print("Key touch detected!")
        # In a real implementation, this would return actual key data
        return {'type': 'public-key', 'id': b'simulated_id', 'response': {}}

    def remove_key(self, username):
        """Remove a registered security key."""
        try:
            if username in self.credentials:
                del self.credentials[username]
                self._save_credentials()
                return True
            return False
        except Exception as e:
            print(f"Error removing security key: {e}")
            return False 