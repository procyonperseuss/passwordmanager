"""Security menu interface for the password manager."""

from rich.table import Table
from ..security.hardware_auth import HardwareAuthManager
from ..security.session_manager import SessionManager
from ..security.password_policy import PasswordPolicy
from ..security.password_sharing import PasswordSharing
from ..utils.terminal_formatter import TerminalFormatter

class SecurityMenu:
    def __init__(self):
        """Initialize security menu."""
        self.hardware_auth = HardwareAuthManager()
        self.session_manager = SessionManager()
        self.password_policy = PasswordPolicy()
        self.password_sharing = PasswordSharing()
        self.formatter = TerminalFormatter()

    def show_menu(self):
        """Display the security menu."""
        while True:
            self.formatter.print_header("Security Settings")
            
            options = {
                "1": "Hardware Security Key Management",
                "2": "Session Management",
                "3": "Password Policy Settings",
                "4": "Password Sharing",
                "5": "View Security Status",
                "6": "Return to Main Menu"
            }
            
            self.formatter.create_menu_table("Security Options", options)
            choice = self.formatter.get_input("\nEnter your choice")
            
            if choice == "1":
                self._hardware_key_menu()
            elif choice == "2":
                self._session_menu()
            elif choice == "3":
                self._policy_menu()
            elif choice == "4":
                self._sharing_menu()
            elif choice == "5":
                self._show_security_status()
            elif choice == "6":
                break
            else:
                self.formatter.print_error("Invalid choice")

    def _hardware_key_menu(self):
        """Handle hardware security key operations."""
        while True:
            self.formatter.print_header("Hardware Security Key Management")
            
            options = {
                "1": "Register New Key",
                "2": "Remove Existing Key",
                "3": "Test Key Authentication",
                "4": "Return to Security Menu"
            }
            
            self.formatter.create_menu_table("Hardware Key Options", options)
            choice = self.formatter.get_input("\nEnter your choice")
            
            if choice == "1":
                username = self.formatter.get_input("Enter username for key registration")
                if self.hardware_auth.register_key(username):
                    self.formatter.print_success("Security key registered successfully!")
                else:
                    self.formatter.print_error("Failed to register security key")
                    
            elif choice == "2":
                username = self.formatter.get_input("Enter username to remove key")
                if self.hardware_auth.remove_key(username):
                    self.formatter.print_success("Security key removed successfully!")
                else:
                    self.formatter.print_error("Failed to remove security key")
                    
            elif choice == "3":
                username = self.formatter.get_input("Enter username to test key")
                if self.hardware_auth.verify_key(username):
                    self.formatter.print_success("Security key verification successful!")
                else:
                    self.formatter.print_error("Security key verification failed")
                    
            elif choice == "4":
                break

    def _session_menu(self):
        """Handle session management operations."""
        while True:
            self.formatter.print_header("Session Management")
            
            options = {
                "1": "View Active Sessions",
                "2": "End Session",
                "3": "View Login Attempts",
                "4": "Return to Security Menu"
            }
            
            self.formatter.create_menu_table("Session Options", options)
            choice = self.formatter.get_input("\nEnter your choice")
            
            if choice == "1":
                self._show_active_sessions()
            elif choice == "2":
                session_id = self.formatter.get_input("Enter session ID to end")
                self.session_manager.end_session(session_id)
                self.formatter.print_success("Session ended successfully!")
            elif choice == "3":
                self._show_login_attempts()
            elif choice == "4":
                break

    def _policy_menu(self):
        """Handle password policy operations."""
        while True:
            self.formatter.print_header("Password Policy Settings")
            
            # Show current policy
            policy_summary = self.password_policy.get_policy_summary()
            self.formatter.print_info("\nCurrent Policy:")
            for key, value in policy_summary.items():
                self.formatter.print_info(f"{key}: {value}")
            
            options = {
                "1": "Update Password Age Policy",
                "2": "Update Password Requirements",
                "3": "View Expiring Passwords",
                "4": "Return to Security Menu"
            }
            
            self.formatter.create_menu_table("\nPolicy Options", options)
            choice = self.formatter.get_input("\nEnter your choice")
            
            if choice == "1":
                max_age = self.formatter.get_input("Enter maximum password age in days [90]") or "90"
                if max_age.isdigit():
                    self.password_policy.update_policy({'max_age_days': int(max_age)})
                    self.formatter.print_success("Password age policy updated!")
                    
            elif choice == "2":
                self._update_password_requirements()
                
            elif choice == "3":
                expiring = self.password_policy.get_expiring_passwords()
                if expiring:
                    self.formatter.print_info("\nExpiring Passwords:")
                    for entry in expiring:
                        self.formatter.print_warning(
                            f"Username: {entry['username']}, "
                            f"Days until expiry: {entry['days_until_expiry']}"
                        )
                else:
                    self.formatter.print_info("No passwords are expiring soon")
                    
            elif choice == "4":
                break

    def _sharing_menu(self):
        """Handle password sharing operations."""
        while True:
            self.formatter.print_header("Password Sharing")
            
            options = {
                "1": "Share Password",
                "2": "Access Shared Password",
                "3": "Revoke Share",
                "4": "View Share Status",
                "5": "Return to Security Menu"
            }
            
            self.formatter.create_menu_table("Sharing Options", options)
            choice = self.formatter.get_input("\nEnter your choice")
            
            if choice == "1":
                password = self.formatter.get_input("Enter password to share", password=True)
                expiry = self.formatter.get_input("Enter share expiry hours [24]") or "24"
                max_accesses = self.formatter.get_input("Enter maximum access count [1]") or "1"
                
                if expiry.isdigit() and max_accesses.isdigit():
                    share_info = self.password_sharing.create_share(
                        password,
                        expiry_hours=int(expiry),
                        max_accesses=int(max_accesses)
                    )
                    self.formatter.print_success("\nPassword shared successfully!")
                    self.formatter.print_info(f"Share ID: {share_info['share_id']}")
                    self.formatter.print_info(f"Access Key: {share_info['access_key']}")
                    self.formatter.print_info(f"Expires at: {share_info['expires_at']}")
                    
            elif choice == "2":
                share_id = self.formatter.get_input("Enter share ID")
                access_key = self.formatter.get_input("Enter access key")
                password, message = self.password_sharing.access_shared_password(share_id, access_key)
                
                if password:
                    self.formatter.print_success("Password retrieved successfully!")
                    self.formatter.print_info(f"Password: {password}")
                else:
                    self.formatter.print_error(f"Failed to access password: {message}")
                    
            elif choice == "3":
                share_id = self.formatter.get_input("Enter share ID to revoke")
                if self.password_sharing.revoke_share(share_id):
                    self.formatter.print_success("Share revoked successfully!")
                else:
                    self.formatter.print_error("Failed to revoke share")
                    
            elif choice == "4":
                share_id = self.formatter.get_input("Enter share ID")
                status = self.password_sharing.get_share_status(share_id)
                if status:
                    self.formatter.print_info("\nShare Status:")
                    for key, value in status.items():
                        self.formatter.print_info(f"{key}: {value}")
                else:
                    self.formatter.print_error("Share not found")
                    
            elif choice == "5":
                break

    def _show_security_status(self):
        """Display overall security status."""
        self.formatter.print_header("Security Status")
        
        # Create status table
        table = Table(title="Security Overview")
        table.add_column("Feature", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="yellow")
        
        # Hardware key status
        table.add_row(
            "Hardware Security Keys",
            "Active" if self.hardware_auth.credentials else "Not configured",
            f"{len(self.hardware_auth.credentials)} key(s) registered"
        )
        
        # Session status
        active_sessions = len(self.session_manager.sessions)
        table.add_row(
            "Active Sessions",
            "Active" if active_sessions > 0 else "None",
            f"{active_sessions} session(s)"
        )
        
        # Password policy
        expiring = len(self.password_policy.get_expiring_passwords())
        table.add_row(
            "Password Policy",
            "Active",
            f"{expiring} password(s) expiring soon"
        )
        
        # Password shares
        active_shares = len(self.password_sharing.shares)
        table.add_row(
            "Password Shares",
            "Active" if active_shares > 0 else "None",
            f"{active_shares} active share(s)"
        )
        
        self.formatter.console.print(table)
        input("\nPress Enter to continue...")

    def _show_active_sessions(self):
        """Display active sessions."""
        table = Table(title="Active Sessions")
        table.add_column("Session ID", style="cyan")
        table.add_column("Username", style="green")
        table.add_column("Created At", style="yellow")
        table.add_column("Last Activity", style="magenta")
        
        for session_id, session in self.session_manager.sessions.items():
            table.add_row(
                session_id,
                session['username'],
                session['created_at'],
                session['last_activity']
            )
        
        self.formatter.console.print(table)
        input("\nPress Enter to continue...")

    def _show_login_attempts(self):
        """Display recent login attempts."""
        table = Table(title="Recent Login Attempts")
        table.add_column("Timestamp", style="cyan")
        table.add_column("Username", style="green")
        table.add_column("IP Address", style="yellow")
        table.add_column("Status", style="magenta")
        
        for ip, data in self.session_manager.ip_tracking.items():
            for attempt in data['attempts']:
                table.add_row(
                    attempt['timestamp'],
                    attempt['username'],
                    ip,
                    "Success" if attempt['success'] else "Failed"
                )
        
        self.formatter.console.print(table)
        input("\nPress Enter to continue...")

    def _update_password_requirements(self):
        """Update password requirement settings."""
        self.formatter.print_header("Update Password Requirements")
        
        min_length = self.formatter.get_input("Minimum password length [12]") or "12"
        require_upper = self.formatter.get_input("Require uppercase letters? (y/n) [y]").lower() != 'n'
        require_lower = self.formatter.get_input("Require lowercase letters? (y/n) [y]").lower() != 'n'
        require_numbers = self.formatter.get_input("Require numbers? (y/n) [y]").lower() != 'n'
        require_special = self.formatter.get_input("Require special characters? (y/n) [y]").lower() != 'n'
        min_unique = self.formatter.get_input("Minimum unique characters [8]") or "8"
        
        if min_length.isdigit() and min_unique.isdigit():
            self.password_policy.update_policy({
                'min_length': int(min_length),
                'require_uppercase': require_upper,
                'require_lowercase': require_lower,
                'require_numbers': require_numbers,
                'require_special': require_special,
                'min_unique_chars': int(min_unique)
            })
            self.formatter.print_success("Password requirements updated successfully!") 