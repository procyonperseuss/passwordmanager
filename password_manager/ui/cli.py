"""
Command-line interface for the password manager.
"""

import os
from datetime import datetime, timedelta
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ..config.settings import (
    PASSWORDS_FILE,
    BACKUP_DIR,
    NOTES_FILE,
    MFA_CONFIG_FILE,
    BACKUP_CODES_FILE,
    TRUSTED_CONTACTS_FILE,
    EMERGENCY_ACCESS_CONFIG_FILE,
    AuditAction
)

from ..utils.email_sender import EmailSender
from ..config.user_settings import UserSettings
from ..utils.terminal_formatter import TerminalFormatter
from ..encryption.encryption_manager import EncryptionManager
from ..storage.file_handler import FileHandler
from ..authentication.auth_manager import AuthenticationManager
from ..audit.audit import AuditLogger
from ..utils.password_utils import PasswordUtils

class PasswordManagerCLI:
    def __init__(self):
        """Initialize the Password Manager CLI."""
        # Initialize core components
        self.formatter = TerminalFormatter()
        self.encryption_manager = EncryptionManager()
        self.file_handler = FileHandler()
        self.password_utils = PasswordUtils()
        self.auth_manager = AuthenticationManager()
        self.audit_logger = AuditLogger()
        self.settings = UserSettings()
        
        # Initialize data storage
        self._health_report_cache = None
        self.passwords = {}
        self.secure_notes = {}
        self.favorites = set()
        
        # Create necessary directories
        os.makedirs(os.path.dirname(PASSWORDS_FILE), exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        
        # Load initial data
        self.load_data()
        self.load_favorites()

    def load_data(self):
        """Load passwords and secure notes from storage."""
        try:
            self.passwords = self.file_handler.load_passwords() or {}
            self.secure_notes = self.file_handler.load_json_file(NOTES_FILE) or {}
        except Exception as e:
            self.formatter.print_error(f"Error loading data: {str(e)}")
            self.passwords = {}
            self.secure_notes = {}

    def save_data(self):
        """Save passwords and secure notes to storage."""
        self.file_handler.save_passwords(self.passwords)
        self.file_handler.save_secure_notes(self.secure_notes)

    def load_favorites(self):
        """Load favorite accounts from storage."""
        try:
            favorites_file = os.path.join(os.path.dirname(PASSWORDS_FILE), 'favorites.json')
            favorites_data = self.file_handler.load_json_file(favorites_file) or {'favorites': []}
            self.favorites = set(favorites_data.get('favorites', []))
        except Exception as e:
            self.formatter.print_error(f"Error loading favorites: {str(e)}")
            self.favorites = set()

    def save_favorites(self):
        """Save favorite accounts to storage."""
        try:
            favorites_file = os.path.join(os.path.dirname(PASSWORDS_FILE), 'favorites.json')
            self.file_handler.save_json_file(favorites_file, {'favorites': list(self.favorites)})
        except Exception as e:
            self.formatter.print_error(f"Error saving favorites: {str(e)}")

    def toggle_favorite(self, account):
        """Toggle favorite status of an account."""
        if account in self.favorites:
            self.favorites.remove(account)
            self.formatter.print_info(f"Removed {account} from favorites")
        else:
            self.favorites.add(account)
            self.formatter.print_success(f"Added {account} to favorites")
        self.save_favorites()

    def add_password(self, generated_password=None):
        """Add a new password entry."""
        try:
            self.formatter.print_header("Add New Password")
            
            # Get account details
            account = self.formatter.get_input("Enter account name (e.g., Google): ")
            if not account:
                self.formatter.print_error("Account name cannot be empty")
                return
            
            if account in self.passwords:
                if not self.formatter.confirm("Account already exists. Update it?"):
                    return
            
            username = self.formatter.get_input("Enter username: ")
            
            # Handle password input
            if generated_password:
                password = generated_password
                self.formatter.print_info(f"Using generated password: {password}")
            else:
                password = self.formatter.get_input("Enter password: ", password=True)
                
                # Check password strength
                strength_info = self.password_utils.check_password_strength(password)
                
                if strength_info['strength'] == "Weak":
                    self.formatter.print_warning("Warning: This password is weak")
                    for weakness in strength_info['weaknesses']:
                        self.formatter.print_warning(f"- {weakness}")
                    
                    if self.formatter.confirm("Would you like to generate a strong password instead?"):
                        password = self.password_utils.generate_strong_password()
                        self.formatter.print_info(f"Generated password: {password}")
            
            # Encrypt and save the password
            encrypted_password = self.encryption_manager.encrypt_data(password)
            
            # Create or update password entry
            self.passwords[account] = {
                'username': username,
                'password': encrypted_password,
                'created_date': datetime.now().strftime('%Y-%m-%d'),
                'last_modified': datetime.now().strftime('%Y-%m-%d')
            }
            
            # Save to file
            self.file_handler.save_passwords(self.passwords)
            
            # Log the action
            self.audit_logger.log_action(
                AuditAction.ADD_PASSWORD if account not in self.passwords else AuditAction.UPDATE_PASSWORD,
                f"Account: {account}"
            )
            
            self.formatter.print_success(f"Password {'updated' if account in self.passwords else 'saved'} successfully!")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def retrieve_password(self):
        """Retrieve and display a password."""
        try:
            self.formatter.print_header("Retrieve Password")
            
            search_term = self.formatter.get_input("Enter account name or search term: ")
            if not search_term:
                self.formatter.print_error("Search term cannot be empty")
                return
            
            # If exact match exists, use it
            if search_term in self.passwords:
                accounts = {search_term: self.passwords[search_term]}
            else:
                # Search for partial matches
                accounts = {
                    name: data for name, data in self.passwords.items()
                    if search_term.lower() in name.lower() or
                    search_term.lower() in data.get('username', '').lower()
                }
            
            if not accounts:
                self.formatter.print_error("No matching accounts found")
                return
            
            if len(accounts) > 1:
                # Display matching accounts
                self.formatter.print_info("\nMatching accounts:")
                for name in accounts:
                    self.formatter.print_info(f"- {name}")
                
                # Ask user to specify
                account = self.formatter.get_input("\nEnter exact account name: ")
                if account not in accounts:
                    self.formatter.print_error("Invalid account name")
                    return
            else:
                account = list(accounts.keys())[0]
            
            # Display account details
            data = accounts[account]
            decrypted_password = self.encryption_manager.decrypt_data(data['password'])
            
            self.formatter.print_info("\nAccount Details:")
            self.formatter.print_info(f"Account: {account}")
            self.formatter.print_info(f"Username: {data['username']}")
            
            # Show password preview first
            preview = self.formatter.print_password_preview(decrypted_password)
            self.formatter.print_info(f"Password: {preview}")
            
            # Ask if user wants to see full password
            if self.formatter.confirm("Show full password?"):
                self.formatter.print_info(f"Full password: {decrypted_password}")
                
                # Log the action
                self.audit_logger.log_action(
                    AuditAction.VIEW_PASSWORD,
                    f"Account: {account}"
                )
            
            # Offer to toggle favorite status
            if self.formatter.confirm(f"Toggle favorite status for {account}?"):
                if account in self.favorites:
                    self.favorites.remove(account)
                    self.formatter.print_success(f"Removed {account} from favorites")
                else:
                    self.favorites.add(account)
                    self.formatter.print_success(f"Added {account} to favorites")
                self.save_favorites()
                
                # Log the action
                self.audit_logger.log_action(
                    AuditAction.TOGGLE_FAVORITE,
                    f"Account: {account}"
                )
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def list_accounts(self):
        """Display all stored accounts."""
        self.formatter.print_header("Stored Accounts")
        
        if not self.passwords:
            self.formatter.print_warning("No accounts stored yet.")
            return
        
        # Show favorites first
        if self.favorites:
            favorite_accounts = {k: self.passwords[k] for k in self.favorites if k in self.passwords}
            if favorite_accounts:
                self.formatter.print_info("\nFavorite Accounts:")
                self.formatter.print_account_list(favorite_accounts)
        
        # Show all accounts
        self.formatter.print_info("\nAll Accounts:")
        self.formatter.print_account_list(self.passwords)
        
        # Search option
        if self.formatter.confirm("\nWould you like to search accounts?"):
            search_term = self.formatter.get_input("Enter search term")
            matches = self.formatter.search_accounts(self.passwords, search_term)
            if matches:
                self.formatter.print_info("\nSearch Results:")
                self.formatter.print_account_list(matches)
            else:
                self.formatter.print_warning("No matches found.")

    def remove_password(self):
        """Remove a stored password."""
        self.formatter.print_header("Remove Password")
        
        account_name = self.formatter.get_input("Enter account name to remove")
        
        if account_name in self.passwords:
            if self.formatter.confirm(f"Are you sure you want to remove the password for '{account_name}'?"):
                try:
                    del self.passwords[account_name]
                    if account_name in self.favorites:
                        self.favorites.remove(account_name)
                        self.save_favorites()
                    self.save_data()
                    self.formatter.print_success(f"Password for '{account_name}' has been removed successfully!")
                    self.audit_logger.log_action(AuditAction.REMOVE_PASSWORD, {
                        "account": account_name
                    })
                except Exception as e:
                    self.formatter.print_error(f"An error occurred: {e}")
                    self.audit_logger.log_action(AuditAction.REMOVE_PASSWORD, {
                        "account": account_name,
                        "error": str(e)
                    }, "failure")
            else:
                self.formatter.print_info("Password removal cancelled.")
        else:
            self.formatter.print_error(f"No password found for account: {account_name}")
            self.audit_logger.log_action(AuditAction.REMOVE_PASSWORD, {
                "account": account_name,
                "error": "Account not found"
            }, "failure")

    def generate_password_menu(self):
        """Display password generation menu."""
        self.formatter.print_header("Generate Strong Password")
        
        try:
            length = self.formatter.get_input("Enter desired password length (minimum 8, press Enter for default 16)")
            length = int(length) if length.strip() else 16
            
            if length < 8:
                self.formatter.print_warning("Minimum length is 8 characters. Using length of 8.")
                length = 8
            
            password = PasswordUtils.generate_strong_password(length)
            self.formatter.print_success("\nGenerated Password:")
            self.formatter.print_info(password)
            
            self.audit_logger.log_action(AuditAction.GENERATE_PASSWORD, {
                "length": length
            })
            
            if self.formatter.confirm("\nWould you like to add this password to an account?"):
                self.add_password(generated_password=password)
                
        except ValueError:
            self.formatter.print_error("Invalid input. Using default length of 16.")
            password = PasswordUtils.generate_strong_password()
            self.formatter.print_success("\nGenerated Password:")
            self.formatter.print_info(password)

    def main_menu(self):
        """Display the main menu."""
        menu_options = {
            "1": "Add Password",
            "2": "Retrieve Password",
            "3": "List Accounts",
            "4": "Remove Password",
            "5": "Generate Strong Password",
            "6": "Backup and Restore",
            "7": "MFA Settings",
            "8": "Password Health Report",
            "9": "Improve Passwords",
            "10": "Secure Notes",
            "11": "View Audit Logs",
            "12": "Emergency Access",
            "13": "Passwordless Authentication",
            "14": "Settings",
            "15": "Help",
            "16": "Exit"
        }
        
        while True:
            self.formatter.print_header("Password Manager")
            self.formatter.create_menu_table("Main Menu", menu_options)
            
            try:
                choice = self.formatter.get_input("\nEnter your choice")
                
                if choice == "1":
                    self.add_password()
                elif choice == "2":
                    self.retrieve_password()
                elif choice == "3":
                    self.list_accounts()
                elif choice == "4":
                    self.remove_password()
                elif choice == "5":
                    self.generate_password_menu()
                elif choice == "6":
                    self.backup_menu()
                elif choice == "7":
                    self.mfa_menu()
                elif choice == "8":
                    self.password_health_report()
                elif choice == "9":
                    self.improve_passwords()
                elif choice == "10":
                    self.secure_notes_menu()
                elif choice == "11":
                    self.view_audit_logs()
                elif choice == "12":
                    self.emergency_access_menu()
                elif choice == "13":
                    self.passwordless_auth_menu()
                elif choice == "14":
                    self.settings_menu()
                elif choice == "15":
                    self.formatter.print_help_menu()
                    input("\nPress Enter to continue...")
                elif choice == "16":
                    self.formatter.print_info("Goodbye!")
                    exit()
                else:
                    self.formatter.print_error("Invalid choice. Please enter a number between 1 and 16.")
            except KeyboardInterrupt:
                self.formatter.print_info("\nGoodbye!")
                exit()
            except Exception as e:
                self.formatter.print_error(f"An error occurred: {e}")

    def run(self):
        """Start the password manager."""
        try:
            # Verify master password before proceeding
            if not self.auth_manager.verify_master_password():
                self.formatter.print_error("Access denied. Exiting...")
                exit(1)
            
            # Verify MFA if enabled
            if not self.auth_manager.verify_mfa():
                self.formatter.print_error("MFA verification failed. Exiting...")
                exit(1)
            
            self.main_menu()
        except KeyboardInterrupt:
            self.formatter.print_info("\nGoodbye!")
            exit(0)
        except Exception as e:
            self.formatter.print_error(f"Fatal error: {e}")
            exit(1)

    def backup_menu(self):
        """Display backup and restore menu."""
        while True:
            self.formatter.print_header("Backup and Restore")
            
            menu_options = {
                "1": "Create Backup",
                "2": "Restore from Backup",
                "3": "List Backups",
                "4": "Return to Main Menu"
            }
            
            self.formatter.create_menu_table("Backup Options", menu_options)
            
            choice = self.formatter.get_input("\nEnter your choice")
            
            if choice == "1":
                self.create_backup()
            elif choice == "2":
                self.restore_backup()
            elif choice == "3":
                self.list_backups()
            elif choice == "4":
                break
            else:
                self.formatter.print_error("Invalid choice")

    def create_backup(self):
        """Create a new backup."""
        try:
            backup_path = self.file_handler.create_backup()
            self.formatter.print_success(f"Backup created successfully in: {backup_path}")
            self.audit_logger.log_action(AuditAction.CREATE_BACKUP, {
                "backup_path": backup_path
            })
        except Exception as e:
            self.formatter.print_error(f"Error creating backup: {e}")
            self.audit_logger.log_action(AuditAction.CREATE_BACKUP, {
                "error": str(e)
            }, "failure")

    def restore_backup(self):
        """Restore from a backup."""
        backups = self.file_handler.list_backups()
        if not backups:
            self.formatter.print_warning("No backups found.")
            return
        
        self.formatter.print_info("\nAvailable backups:")
        for i, backup in enumerate(backups, 1):
            date_str = backup.replace("backup_", "").replace("_", " ")
            print(f"{i}. {date_str}")
        
        try:
            choice = self.formatter.get_input("\nEnter backup number to restore (or 0 to cancel)")
            choice_idx = int(choice) - 1
            
            if choice_idx < 0:
                self.formatter.print_info("Restore cancelled.")
                return
            
            if 0 <= choice_idx < len(backups):
                backup_path = os.path.join(self.file_handler.BACKUP_DIR, backups[choice_idx])
                
                if self.formatter.confirm("\nWARNING: This will overwrite current data. Continue?"):
                    self.file_handler.restore_from_backup(backup_path)
                    self.formatter.print_success("Restore completed successfully!")
                    self.audit_logger.log_action(AuditAction.RESTORE_BACKUP, {
                        "backup_path": backup_path
                    })
                    self.formatter.print_warning("Please restart the password manager to apply the changes.")
                    exit(0)
                else:
                    self.formatter.print_info("Restore cancelled.")
            else:
                self.formatter.print_error("Invalid backup number.")
        except ValueError:
            self.formatter.print_error("Invalid input. Please enter a number.")
        except Exception as e:
            self.formatter.print_error(f"Error during restore: {e}")
            self.audit_logger.log_action(AuditAction.RESTORE_BACKUP, {
                "error": str(e)
            }, "failure")

    def list_backups(self):
        """Display list of available backups."""
        backups = self.file_handler.list_backups()
        if not backups:
            self.formatter.print_warning("No backups found.")
            return
        
        self.formatter.print_info("\nAvailable backups:")
        for i, backup in enumerate(backups, 1):
            date_str = backup.replace("backup_", "").replace("_", " ")
            print(f"{i}. {date_str}")
        
        input("\nPress Enter to continue...") 

    def mfa_menu(self):
        """Display MFA management menu."""
        while True:
            self.formatter.print_header("MFA Management")
            
            # Get current MFA status
            mfa_config = self.file_handler.load_json_file(self.file_handler.MFA_CONFIG_FILE, {"enabled": False})
            status = "Enabled" if mfa_config.get("enabled", False) else "Disabled"
            
            menu_options = {
                "1": f"{'Disable' if mfa_config.get('enabled', False) else 'Enable'} MFA",
                "2": "View Backup Codes",
                "3": "Generate New Backup Codes",
                "4": "Return to Main Menu"
            }
            
            self.formatter.print_info(f"Current MFA Status: {status}")
            self.formatter.create_menu_table("MFA Options", menu_options)
            
            choice = self.formatter.get_input("\nEnter your choice")
            
            if choice == "1":
                if mfa_config.get("enabled", False):
                    self.disable_mfa()
                else:
                    self.setup_mfa()
            elif choice == "2":
                self.view_backup_codes()
            elif choice == "3":
                self.generate_new_backup_codes()
            elif choice == "4":
                break
            else:
                self.formatter.print_error("Invalid choice")

    def setup_mfa(self):
        """Enable MFA for the password manager."""
        self.formatter.print_header("Enable Multi-Factor Authentication")
        
        # Generate a random secret key for TOTP
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        
        # Generate QR code for authenticator apps
        provisioning_uri = totp.provisioning_uri("Password Manager", issuer_name="Secure Password Manager")
        
        self.formatter.print_info("\nPlease follow these steps to enable MFA:")
        self.formatter.print_info("1. Open your authenticator app (Google Authenticator, Authy, etc.)")
        self.formatter.print_info("2. Scan the QR code or manually enter the secret key")
        self.formatter.print_info(f"\nSecret Key: {secret_key}")
        
        # Generate QR code
        qr = qrcode.QRCode()
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        qr.print_ascii()
        
        # Generate and save backup codes
        backup_codes = self.auth_manager.generate_backup_codes()
        
        # Verify setup
        self.formatter.print_info("\nTo verify setup, please enter the code from your authenticator app:")
        for _ in range(3):  # Give user 3 attempts
            verification_code = self.formatter.get_input("Enter verification code")
            if totp.verify(verification_code):
                self.auth_manager.save_mfa_config(secret_key, backup_codes)
                self.formatter.print_success("\nMFA enabled successfully!")
                self.formatter.print_info("\nBACKUP CODES (save these in a secure location):")
                for code in backup_codes:
                    self.formatter.print_info(code)
                return True
            self.formatter.print_error("Invalid code, please try again.")
        
        self.formatter.print_error("Failed to verify MFA setup. Please try again later.")
        return False

    def disable_mfa(self):
        """Disable MFA."""
        self.formatter.print_header("Disable MFA")
        
        if not self.auth_manager.verify_mfa():
            self.formatter.print_error("MFA verification failed. Cannot disable MFA.")
            return
        
        if self.formatter.confirm("Are you sure you want to disable MFA?"):
            try:
                os.remove(self.file_handler.MFA_CONFIG_FILE)
                os.remove(self.file_handler.BACKUP_CODES_FILE)
                self.formatter.print_success("MFA disabled successfully!")
            except Exception as e:
                self.formatter.print_error(f"Error disabling MFA: {e}")

    def view_backup_codes(self):
        """View existing backup codes."""
        if not self.auth_manager.verify_mfa():
            self.formatter.print_error("MFA verification required to view backup codes.")
            return
        
        backup_data = self.file_handler.load_json_file(self.file_handler.BACKUP_CODES_FILE, {"backup_codes": []})
        backup_codes = backup_data.get("backup_codes", [])
        
        if not backup_codes:
            self.formatter.print_warning("No backup codes found.")
            return
        
        self.formatter.print_info("\nBackup Codes:")
        for code in backup_codes:
            self.formatter.print_info(code)
        
        input("\nPress Enter to continue...")

    def generate_new_backup_codes(self):
        """Generate new backup codes."""
        if not self.auth_manager.verify_mfa():
            self.formatter.print_error("MFA verification required to generate new backup codes.")
            return
        
        if self.formatter.confirm("This will invalidate all existing backup codes. Continue?"):
            backup_codes = self.auth_manager.generate_backup_codes()
            mfa_config = self.file_handler.load_json_file(self.file_handler.MFA_CONFIG_FILE, {})
            self.auth_manager.save_mfa_config(mfa_config.get("secret_key"), backup_codes)
            
            self.formatter.print_success("\nNew backup codes generated successfully!")
            self.formatter.print_info("\nBACKUP CODES (save these in a secure location):")
            for code in backup_codes:
                self.formatter.print_info(code)
            
            input("\nPress Enter to continue...") 

    def password_health_report(self):
        """Generate a comprehensive report on password health."""
        try:
            with self.formatter.create_progress() as progress:
                task = progress.add_task("Analyzing passwords...", total=100)
                
                passwords = self.file_handler.load_passwords()
                if not passwords:
                    self.formatter.print_warning("No passwords stored yet.")
                    self._health_report_cache = {}
                    return
                
                progress.update(task, advance=30)
                
                # Analyze password strength
                strength_stats = defaultdict(int)
                reused_passwords = defaultdict(list)
                old_passwords = []
                compromised_passwords = []
                total_score = 100
                
                for account, data in passwords.items():
                    decrypted_password = self.encryption_manager.decrypt_data(data['password'])
                    strength = self.password_utils.calculate_password_strength(decrypted_password)
                    
                    # Count password strengths
                    if strength >= 80:
                        strength_stats['strong'] += 1
                    elif strength >= 60:
                        strength_stats['medium'] += 1
                        total_score -= 5
                    else:
                        strength_stats['weak'] += 1
                        total_score -= 10
                    
                    # Check for reused passwords
                    for other_account, other_data in passwords.items():
                        if account != other_account and data['password'] == other_data['password']:
                            reused_passwords[decrypted_password].append(account)
                            total_score -= 15
                            break
                    
                    # Check password age
                    created_date = datetime.strptime(data.get('created_date', datetime.now().strftime('%Y-%m-%d')), '%Y-%m-%d')
                    if (datetime.now() - created_date).days > 90:
                        old_passwords.append(account)
                        total_score -= 5
                    
                    progress.update(task, advance=10)
                
                # Create summary table
                table = Table(title="Password Health Summary", show_header=True)
                table.add_column("Category", style="cyan")
                table.add_column("Count", style="magenta")
                table.add_column("Impact", style="yellow")
                
                table.add_row(
                    "Strong Passwords",
                    str(strength_stats['strong']),
                    "Good"
                )
                table.add_row(
                    "Medium Passwords",
                    str(strength_stats['medium']),
                    "-5 points each"
                )
                table.add_row(
                    "Weak Passwords",
                    str(strength_stats['weak']),
                    "-10 points each"
                )
                table.add_row(
                    "Reused Passwords",
                    str(len(reused_passwords)),
                    "-15 points each"
                )
                table.add_row(
                    "Old Passwords (>90 days)",
                    str(len(old_passwords)),
                    "-5 points each"
                )
                
                progress.update(task, advance=30)
                
                # Display results
                self.formatter.print_header("Password Health Report")
                self.formatter.console.print(table)
                
                # Display overall score
                total_score = max(0, min(100, total_score))
                score_color = "green" if total_score >= 80 else "yellow" if total_score >= 60 else "red"
                self.formatter.console.print(f"\nOverall Security Score: ", end="")
                self.formatter.console.print(f"{total_score}/100", style=f"bold {score_color}")
                
                progress.update(task, completed=100)
                
                # Store results for improve_passwords method
                self._health_report_cache = {
                    'weak_passwords': [acc for acc, data in passwords.items() 
                                     if self.password_utils.calculate_password_strength(
                                         self.encryption_manager.decrypt_data(data['password'])) < 60],
                    'reused_passwords': reused_passwords,
                    'old_passwords': old_passwords
                }
                
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")
            self._health_report_cache = {}

    def improve_passwords(self):
        """Provide suggestions for improving password security."""
        try:
            # Check if we have a recent health report
            if self._health_report_cache is None:
                self.formatter.print_info("Running password health analysis first...")
                self.password_health_report()
            
            if not self._health_report_cache:
                self.formatter.print_success("All passwords meet security standards!")
                return
            
            if not (self._health_report_cache.get('weak_passwords') or 
                   self._health_report_cache.get('reused_passwords') or 
                   self._health_report_cache.get('old_passwords')):
                self.formatter.print_success("All passwords meet security standards!")
                return
            
            self.formatter.print_header("Password Improvement Suggestions")
            
            # Create a table for suggestions
            table = Table(show_header=True)
            table.add_column("Account", style="cyan")
            table.add_column("Issue", style="yellow")
            table.add_column("Recommendation", style="green")
            
            # Add weak passwords to the table
            for account in self._health_report_cache.get('weak_passwords', []):
                table.add_row(
                    account,
                    "Weak Password",
                    "Generate a new strong password using option 5"
                )
            
            # Add reused passwords to the table
            for password, accounts in self._health_report_cache.get('reused_passwords', {}).items():
                for account in accounts:
                    table.add_row(
                        account,
                        "Reused Password",
                        "Create unique passwords for each account"
                    )
            
            # Add old passwords to the table
            for account in self._health_report_cache.get('old_passwords', []):
                table.add_row(
                    account,
                    "Password > 90 days old",
                    "Update password for better security"
                )
            
            self.formatter.console.print(table)
            
            # Offer to generate new passwords
            if self.formatter.confirm("Would you like to generate new strong passwords for these accounts?"):
                self._improve_selected_passwords()
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")
    
    def _improve_selected_passwords(self):
        """Helper method to improve selected passwords."""
        try:
            passwords = self.file_handler.load_passwords()
            accounts_to_improve = set(self._health_report_cache['weak_passwords'])
            accounts_to_improve.update(
                account for accounts in self._health_report_cache['reused_passwords'].values()
                for account in accounts
            )
            accounts_to_improve.update(self._health_report_cache['old_passwords'])
            
            for account in sorted(accounts_to_improve):
                if self.formatter.confirm(f"Generate new password for {account}?"):
                    new_password = self.password_utils.generate_strong_password()
                    passwords[account]['password'] = self.encryption_manager.encrypt_data(new_password)
                    passwords[account]['created_date'] = datetime.now().strftime('%Y-%m-%d')
                    
                    self.formatter.print_success(f"Generated new password for {account}")
                    self.formatter.print_info(f"New password: {new_password}")
                    self.formatter.print_warning("Please update this password on the respective website/service")
            
            self.file_handler.save_passwords(passwords)
            self.formatter.print_success("Password improvements completed!")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred while improving passwords: {str(e)}") 

    def secure_notes_menu(self):
        """Display and handle the secure notes menu."""
        try:
            while True:
                self.formatter.print_header("Secure Notes")
                
                # Create menu options
                options = {
                    "1": "Add Note",
                    "2": "View Note",
                    "3": "List Notes",
                    "4": "Edit Note",
                    "5": "Delete Note",
                    "6": "Return to Main Menu"
                }
                
                self.formatter.create_menu_table("Secure Notes Menu", options)
                choice = self.formatter.get_input("Enter your choice: ")
                
                if choice == "1":
                    self.add_secure_note()
                elif choice == "2":
                    self.view_secure_note()
                elif choice == "3":
                    self.list_secure_notes()
                elif choice == "4":
                    self.edit_secure_note()
                elif choice == "5":
                    self.delete_secure_note()
                elif choice == "6":
                    break
                else:
                    self.formatter.print_error("Invalid choice")
                
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def add_secure_note(self):
        """Add a new secure note."""
        try:
            self.formatter.print_header("Add New Note")
            
            # Get note details
            title = self.formatter.get_input("Enter note title: ")
            if not title:
                self.formatter.print_error("Title cannot be empty")
                return
            
            if title in self.secure_notes:
                if not self.formatter.confirm("Note already exists. Update it?"):
                    return
            
            # Get note content
            self.formatter.print_info("Enter note content (press Enter twice to finish):")
            lines = []
            while True:
                line = input()
                if not line and (not lines or not lines[-1]):
                    break
                lines.append(line)
            
            content = "\n".join(lines)
            if not content:
                self.formatter.print_error("Note content cannot be empty")
                return
            
            # Encrypt and save the note
            encrypted_content = self.encryption_manager.encrypt_data(content)
            
            # Create or update note entry
            self.secure_notes[title] = {
                'content': encrypted_content,
                'created_date': datetime.now().strftime('%Y-%m-%d'),
                'last_modified': datetime.now().strftime('%Y-%m-%d')
            }
            
            # Save to file
            self.file_handler.save_secure_notes(self.secure_notes)
            
            # Log the action
            self.audit_logger.log_action(
                AuditAction.ADD_NOTE if title not in self.secure_notes else AuditAction.UPDATE_NOTE,
                f"Note: {title}"
            )
            
            self.formatter.print_success(f"Note {'updated' if title in self.secure_notes else 'saved'} successfully!")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def view_secure_note(self):
        """View a secure note."""
        try:
            self.formatter.print_header("View Note")
            
            if not self.secure_notes:
                self.formatter.print_warning("No notes stored yet")
                return
            
            # List available notes
            self.list_secure_notes()
            
            # Get note title
            title = self.formatter.get_input("Enter note title: ")
            if title not in self.secure_notes:
                self.formatter.print_error("Note not found")
                return
            
            # Decrypt and display note
            note = self.secure_notes[title]
            decrypted_content = self.encryption_manager.decrypt_data(note['content'])
            
            self.formatter.print_info(f"\nTitle: {title}")
            self.formatter.print_info(f"Created: {note['created_date']}")
            self.formatter.print_info(f"Last Modified: {note.get('last_modified', 'N/A')}")
            self.formatter.print_info("\nContent:")
            print(decrypted_content)
            
            # Log the action
            self.audit_logger.log_action(
                AuditAction.VIEW_NOTE,
                f"Note: {title}"
            )
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def list_secure_notes(self):
        """List all secure notes."""
        try:
            if not self.secure_notes:
                self.formatter.print_warning("No notes stored yet")
                return
            
            # Create table for notes
            table = Table(title="Stored Notes", show_header=True)
            table.add_column("#", style="cyan", justify="right")
            table.add_column("Title", style="green")
            table.add_column("Created Date", style="magenta")
            table.add_column("Last Modified", style="yellow")
            
            for i, (title, note) in enumerate(sorted(self.secure_notes.items()), 1):
                table.add_row(
                    str(i),
                    title,
                    note['created_date'],
                    note.get('last_modified', 'N/A')
                )
            
            self.formatter.console.print(table)
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def edit_secure_note(self):
        """Edit an existing secure note."""
        try:
            self.formatter.print_header("Edit Note")
            
            if not self.secure_notes:
                self.formatter.print_warning("No notes stored yet")
                return
            
            # List available notes
            self.list_secure_notes()
            
            # Get note title
            title = self.formatter.get_input("Enter note title: ")
            if title not in self.secure_notes:
                self.formatter.print_error("Note not found")
                return
            
            # Show current content
            note = self.secure_notes[title]
            current_content = self.encryption_manager.decrypt_data(note['content'])
            self.formatter.print_info("\nCurrent content:")
            print(current_content)
            
            # Get new content
            self.formatter.print_info("\nEnter new content (press Enter twice to finish):")
            lines = []
            while True:
                line = input()
                if not line and (not lines or not lines[-1]):
                    break
                lines.append(line)
            
            content = "\n".join(lines)
            if not content:
                self.formatter.print_error("Note content cannot be empty")
                return
            
            # Confirm update
            if not self.formatter.confirm("Save changes?"):
                return
            
            # Encrypt and save the note
            encrypted_content = self.encryption_manager.encrypt_data(content)
            self.secure_notes[title]['content'] = encrypted_content
            self.secure_notes[title]['last_modified'] = datetime.now().strftime('%Y-%m-%d')
            
            # Save to file
            self.file_handler.save_secure_notes(self.secure_notes)
            
            # Log the action
            self.audit_logger.log_action(
                AuditAction.UPDATE_NOTE,
                f"Note: {title}"
            )
            
            self.formatter.print_success("Note updated successfully!")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def delete_secure_note(self):
        """Delete a secure note."""
        try:
            self.formatter.print_header("Delete Note")
            
            if not self.secure_notes:
                self.formatter.print_warning("No notes stored yet")
                return
            
            # List available notes
            self.list_secure_notes()
            
            # Get note title
            title = self.formatter.get_input("Enter note title: ")
            if title not in self.secure_notes:
                self.formatter.print_error("Note not found")
                return
            
            # Confirm deletion
            if not self.formatter.confirm(f"Are you sure you want to delete '{title}'?"):
                return
            
            # Delete the note
            del self.secure_notes[title]
            
            # Save to file
            self.file_handler.save_secure_notes(self.secure_notes)
            
            # Log the action
            self.audit_logger.log_action(
                AuditAction.DELETE_NOTE,
                f"Note: {title}"
            )
            
            self.formatter.print_success("Note deleted successfully!")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}") 

    def view_audit_logs(self):
        """View and filter audit logs."""
        try:
            while True:
                self.formatter.print_header("Audit Logs")
                
                # Create menu options
                options = {
                    "1": "View Recent Activity",
                    "2": "View All Logs",
                    "3": "Filter Logs",
                    "4": "Export Logs",
                    "5": "Clear Old Logs",
                    "6": "Return to Main Menu"
                }
                
                self.formatter.create_menu_table("Audit Logs Menu", options)
                choice = self.formatter.get_input("Enter your choice: ")
                
                if choice == "1":
                    self._view_recent_activity()
                elif choice == "2":
                    self._view_all_logs()
                elif choice == "3":
                    self._filter_logs()
                elif choice == "4":
                    self._export_logs()
                elif choice == "5":
                    self._clear_old_logs()
                elif choice == "6":
                    break
                else:
                    self.formatter.print_error("Invalid choice")
                
                if choice in ["1", "2", "3", "4", "5"]:
                    input("\nPress Enter to continue...")
                
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _view_recent_activity(self):
        """View the most recent audit log entries."""
        try:
            logs = self.audit_logger.get_recent_activity(limit=10)
            if not logs:
                self.formatter.print_warning("No recent activity found")
                return
            
            self._display_logs(logs, "Recent Activity")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _view_all_logs(self):
        """View all audit logs."""
        try:
            logs = self.audit_logger.get_logs()
            if not logs:
                self.formatter.print_warning("No logs found")
                return
            
            self._display_logs(logs, "All Audit Logs")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _filter_logs(self):
        """Filter audit logs based on criteria."""
        try:
            self.formatter.print_header("Filter Logs")
            
            # Get filter criteria
            self.formatter.print_info("Leave fields empty to skip filtering")
            
            # Date range
            start_date = self.formatter.get_input("Start date (YYYY-MM-DD): ")
            end_date = self.formatter.get_input("End date (YYYY-MM-DD): ")
            
            # Action type
            self.formatter.print_info("\nAvailable action types:")
            action_types = [attr for attr in dir(AuditAction) if not attr.startswith('_')]
            for i, action in enumerate(action_types, 1):
                self.formatter.print_info(f"{i}. {action}")
            
            action_choice = self.formatter.get_input("\nEnter action type number (or leave empty): ")
            action_type = None
            if action_choice.isdigit() and 1 <= int(action_choice) <= len(action_types):
                action_type = getattr(AuditAction, action_types[int(action_choice) - 1])
            
            # Status
            status = self.formatter.get_input("Status (success/failure, or leave empty): ")
            if status and status not in ['success', 'failure']:
                self.formatter.print_error("Invalid status. Using no status filter.")
                status = None
            
            # Convert dates if provided
            try:
                if start_date:
                    start_date = datetime.strptime(start_date, '%Y-%m-%d')
                if end_date:
                    end_date = datetime.strptime(end_date, '%Y-%m-%d')
            except ValueError:
                self.formatter.print_error("Invalid date format. Using no date filter.")
                start_date = end_date = None
            
            # Get filtered logs
            logs = self.audit_logger.get_logs(
                start_date=start_date,
                end_date=end_date,
                action_type=action_type,
                status=status
            )
            
            if not logs:
                self.formatter.print_warning("No logs found matching the criteria")
                return
            
            self._display_logs(logs, "Filtered Audit Logs")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _export_logs(self):
        """Export audit logs to a file."""
        try:
            self.formatter.print_header("Export Logs")
            
            # Get export format
            format_choice = self.formatter.get_input("Export format (json/csv) [json]: ").lower() or 'json'
            if format_choice not in ['json', 'csv']:
                self.formatter.print_error("Invalid format. Using JSON.")
                format_choice = 'json'
            
            # Get export path
            default_filename = f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            filename = self.formatter.get_input(f"Export filename [{default_filename}]: ") or default_filename
            
            # Add extension if not provided
            if not filename.endswith(f'.{format_choice}'):
                filename = f"{filename}.{format_choice}"
            
            # Get logs
            logs = self.audit_logger.get_logs()
            if not logs:
                self.formatter.print_warning("No logs to export")
                return
            
            # Export based on format
            if format_choice == 'json':
                with open(filename, 'w') as f:
                    json.dump({'logs': logs}, f, indent=4, default=str)
            else:  # csv
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(['Timestamp', 'Action', 'Details', 'Status'])
                    # Write data
                    for log in logs:
                        writer.writerow([
                            log['timestamp'],
                            log['action'],
                            log['details'],
                            log['status']
                        ])
            
            self.formatter.print_success(f"Logs exported to {filename}")
            
            # Log the export
            self.audit_logger.log_action(
                AuditAction.EXPORT_DATA,
                f"Exported audit logs to {filename}"
            )
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _clear_old_logs(self):
        """Clear logs older than specified days."""
        try:
            self.formatter.print_header("Clear Old Logs")
            
            days = self.formatter.get_input("Clear logs older than how many days? [90]: ")
            days = int(days) if days.isdigit() else 90
            
            if not self.formatter.confirm(f"Are you sure you want to clear logs older than {days} days?"):
                return
            
            self.audit_logger.clear_old_logs(days)
            self.formatter.print_success(f"Cleared logs older than {days} days")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _display_logs(self, logs, title):
        """Display logs in a formatted table."""
        try:
            table = Table(title=title, show_header=True)
            table.add_column("Timestamp", style="cyan")
            table.add_column("Action", style="green")
            table.add_column("Details", style="white")
            table.add_column("Status", style="yellow")
            
            for log in logs:
                # Convert timestamp to local time
                timestamp = datetime.fromisoformat(log['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                
                # Set status color
                status_style = "green" if log['status'] == "success" else "red"
                
                table.add_row(
                    timestamp,
                    log['action'],
                    log['details'],
                    Text(log['status'], style=status_style)
                )
            
            self.formatter.console.print(table)
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def emergency_access_menu(self):
        """Display and handle the emergency access menu."""
        try:
            while True:
                self.formatter.print_header("Emergency Access")
                
                # Create menu options
                options = {
                    "1": "Configure Trusted Contacts",
                    "2": "View Trusted Contacts",
                    "3": "Request Emergency Access",
                    "4": "Approve/Deny Access Requests",
                    "5": "Emergency Access Settings",
                    "6": "Return to Main Menu"
                }
                
                self.formatter.create_menu_table("Emergency Access Menu", options)
                choice = self.formatter.get_input("Enter your choice: ")
                
                if choice == "1":
                    self._configure_trusted_contacts()
                elif choice == "2":
                    self._view_trusted_contacts()
                elif choice == "3":
                    self._request_emergency_access()
                elif choice == "4":
                    self._manage_access_requests()
                elif choice == "5":
                    self._emergency_access_settings()
                elif choice == "6":
                    break
                else:
                    self.formatter.print_error("Invalid choice")
                
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _configure_trusted_contacts(self):
        """Configure trusted contacts for emergency access."""
        try:
            self.formatter.print_header("Configure Trusted Contacts")
            
            # Load existing trusted contacts
            trusted_contacts = self.file_handler.load_json_file(TRUSTED_CONTACTS_FILE) or {'contacts': []}
            
            while True:
                # Show current contacts
                if trusted_contacts['contacts']:
                    self.formatter.print_info("\nCurrent Trusted Contacts:")
                    for i, contact in enumerate(trusted_contacts['contacts'], 1):
                        self.formatter.print_info(f"{i}. {contact['name']} ({contact['email']})")
                else:
                    self.formatter.print_info("\nNo trusted contacts configured.")
                
                # Show options
                options = {
                    "1": "Add Contact",
                    "2": "Remove Contact",
                    "3": "Return to Emergency Access Menu"
                }
                
                self.formatter.create_menu_table("Options", options)
                choice = self.formatter.get_input("Enter your choice: ")
                
                if choice == "1":
                    name = self.formatter.get_input("Enter contact name: ")
                    email = self.formatter.get_input("Enter contact email: ")
                    waiting_period = self.formatter.get_input("Enter waiting period (hours) [72]: ") or "72"
                    
                    if not name or not email or not waiting_period.isdigit():
                        self.formatter.print_error("Invalid input")
                        continue
                    
                    trusted_contacts['contacts'].append({
                        'name': name,
                        'email': email,
                        'waiting_period': int(waiting_period),
                        'added_date': datetime.now().strftime('%Y-%m-%d')
                    })
                    
                    self.file_handler.save_json_file(TRUSTED_CONTACTS_FILE, trusted_contacts)
                    self.formatter.print_success("Contact added successfully!")
                    
                elif choice == "2":
                    if not trusted_contacts['contacts']:
                        self.formatter.print_warning("No contacts to remove")
                        continue
                    
                    index = self.formatter.get_input("Enter contact number to remove: ")
                    if not index.isdigit() or int(index) < 1 or int(index) > len(trusted_contacts['contacts']):
                        self.formatter.print_error("Invalid contact number")
                        continue
                    
                    removed = trusted_contacts['contacts'].pop(int(index) - 1)
                    self.file_handler.save_json_file(TRUSTED_CONTACTS_FILE, trusted_contacts)
                    self.formatter.print_success(f"Removed {removed['name']} from trusted contacts")
                    
                elif choice == "3":
                    break
                else:
                    self.formatter.print_error("Invalid choice")
                
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _view_trusted_contacts(self):
        """View list of trusted contacts and their details."""
        try:
            self.formatter.print_header("Trusted Contacts")
            
            # Load trusted contacts
            trusted_contacts = self.file_handler.load_json_file(TRUSTED_CONTACTS_FILE) or {'contacts': []}
            
            if not trusted_contacts['contacts']:
                self.formatter.print_warning("No trusted contacts configured")
                return
            
            # Create table for contacts
            table = Table(title="Trusted Contacts", show_header=True)
            table.add_column("Name", style="cyan")
            table.add_column("Email", style="green")
            table.add_column("Waiting Period", style="yellow")
            table.add_column("Added Date", style="magenta")
            
            for contact in trusted_contacts['contacts']:
                table.add_row(
                    contact['name'],
                    contact['email'],
                    f"{contact['waiting_period']} hours",
                    contact['added_date']
                )
            
            self.formatter.console.print(table)
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _request_emergency_access(self):
        """Request emergency access to another user's vault."""
        try:
            self.formatter.print_header("Request Emergency Access")
            
            email = self.formatter.get_input("Enter the vault owner's email: ")
            if not email:
                self.formatter.print_error("Email cannot be empty")
                return
            
            reason = self.formatter.get_input("Enter reason for access request: ")
            if not reason:
                self.formatter.print_error("Reason cannot be empty")
                return
            
            # Save the request
            requests = self.file_handler.load_json_file(EMERGENCY_ACCESS_CONFIG_FILE) or {'requests': []}
            
            new_request = {
                'requester_email': self.settings.get('user_email', 'unknown'),
                'owner_email': email,
                'reason': reason,
                'request_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'pending'
            }
            
            requests['requests'].append(new_request)
            self.file_handler.save_json_file(EMERGENCY_ACCESS_CONFIG_FILE, requests)
            
            # Send email notification
            email_sender = EmailSender()
            success, message = email_sender.send_emergency_access_request(
                owner_email=email,
                requester_email=new_request['requester_email'],
                reason=reason
            )
            
            if success:
                self.formatter.print_success("Emergency access request sent!")
                self.formatter.print_info("The vault owner will be notified and must approve your request.")
            else:
                self.formatter.print_warning(f"Request saved but email notification failed: {message}")
                self.formatter.print_info("The vault owner will see your request when they next log in.")
            
            # Log the request
            self.audit_logger.log_action(
                AuditAction.EMERGENCY_ACCESS_REQUEST,
                f"Requested access to {email}'s vault"
            )
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _manage_access_requests(self):
        """Manage incoming emergency access requests."""
        try:
            self.formatter.print_header("Access Requests")
            
            # Load access requests
            requests = self.file_handler.load_json_file(EMERGENCY_ACCESS_CONFIG_FILE) or {'requests': []}
            
            if not requests['requests']:
                self.formatter.print_warning("No pending access requests")
                return
            
            # Show pending requests
            for i, request in enumerate(requests['requests'], 1):
                self.formatter.print_info(f"\nRequest #{i}")
                self.formatter.print_info(f"From: {request['requester_email']}")
                self.formatter.print_info(f"Reason: {request['reason']}")
                self.formatter.print_info(f"Requested: {request['request_date']}")
                
                if self.formatter.confirm("Approve this request?"):
                    # In a real implementation, this would grant access and notify the requester
                    self.formatter.print_success("Access granted!")
                    self.audit_logger.log_action(
                        AuditAction.EMERGENCY_ACCESS_GRANTED,
                        f"Granted access to {request['requester_email']}"
                    )
                else:
                    self.formatter.print_info("Request denied")
                    self.audit_logger.log_action(
                        AuditAction.EMERGENCY_ACCESS_DENIED,
                        f"Denied access to {request['requester_email']}"
                    )
                
                # Remove processed request
                requests['requests'].pop(i - 1)
            
            self.file_handler.save_json_file(EMERGENCY_ACCESS_CONFIG_FILE, requests)
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _emergency_access_settings(self):
        """Configure emergency access settings."""
        try:
            self.formatter.print_header("Emergency Access Settings")
            
            # Load current settings
            settings = self.file_handler.load_json_file(EMERGENCY_ACCESS_CONFIG_FILE) or {
                'settings': {
                    'auto_approve_trusted': False,
                    'notification_method': 'email',
                    'require_2fa': True,
                    'access_duration': 24  # hours
                }
            }
            
            while True:
                self.formatter.print_info("\nCurrent Settings:")
                for key, value in settings['settings'].items():
                    self.formatter.print_info(f"{key}: {value}")
                
                options = {
                    "1": "Toggle Auto-Approve for Trusted Contacts",
                    "2": "Change Notification Method",
                    "3": "Toggle 2FA Requirement",
                    "4": "Change Access Duration",
                    "5": "Return to Emergency Access Menu"
                }
                
                self.formatter.create_menu_table("Options", options)
                choice = self.formatter.get_input("Enter your choice: ")
                
                if choice == "1":
                    settings['settings']['auto_approve_trusted'] = not settings['settings']['auto_approve_trusted']
                    self.formatter.print_success("Setting updated!")
                    
                elif choice == "2":
                    method = self.formatter.get_input("Enter notification method (email/sms): ")
                    if method in ['email', 'sms']:
                        settings['settings']['notification_method'] = method
                        self.formatter.print_success("Setting updated!")
                    else:
                        self.formatter.print_error("Invalid notification method")
                        
                elif choice == "3":
                    settings['settings']['require_2fa'] = not settings['settings']['require_2fa']
                    self.formatter.print_success("Setting updated!")
                    
                elif choice == "4":
                    duration = self.formatter.get_input("Enter access duration in hours: ")
                    if duration.isdigit() and int(duration) > 0:
                        settings['settings']['access_duration'] = int(duration)
                        self.formatter.print_success("Setting updated!")
                    else:
                        self.formatter.print_error("Invalid duration")
                        
                elif choice == "5":
                    break
                else:
                    self.formatter.print_error("Invalid choice")
                
                # Save settings after each change
                self.file_handler.save_json_file(EMERGENCY_ACCESS_CONFIG_FILE, settings)
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}") 

    def settings_menu(self):
        """Display and handle the settings menu."""
        try:
            while True:
                self.formatter.print_header("Settings")
                
                options = {
                    "1": "Configure Email Settings",
                    "2": "Password Settings",
                    "3": "Security Settings",
                    "4": "Theme Settings",
                    "5": "Backup Settings",
                    "6": "Reset to Defaults",
                    "7": "Return to Main Menu"
                }
                
                self.formatter.create_menu_table("Settings Menu", options)
                choice = self.formatter.get_input("Enter your choice: ")
                
                if choice == "1":
                    self._configure_email_settings()
                elif choice == "2":
                    self._configure_password_settings()
                elif choice == "3":
                    self._configure_security_settings()
                elif choice == "4":
                    self._configure_theme_settings()
                elif choice == "5":
                    self._configure_backup_settings()
                elif choice == "6":
                    if self.formatter.confirm("Are you sure you want to reset all settings to defaults?"):
                        self.settings.reset_to_defaults()
                        self.formatter.print_success("Settings reset to defaults")
                elif choice == "7":
                    break
                else:
                    self.formatter.print_error("Invalid choice")
                    
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}")

    def _configure_email_settings(self):
        """Configure email settings for notifications."""
        try:
            self.formatter.print_header("Email Settings")
            
            # Show current settings
            email_settings = self.settings.get_email_settings()
            self.formatter.print_info("\nCurrent Settings:")
            self.formatter.print_info(f"SMTP Server: {email_settings.get('smtp_server', 'Not set')}")
            self.formatter.print_info(f"SMTP Port: {email_settings.get('smtp_port', 'Not set')}")
            self.formatter.print_info(f"Sender Email: {email_settings.get('sender_email', 'Not set')}")
            self.formatter.print_info("Sender Password: ********" if email_settings.get('sender_password') else "Sender Password: Not set")
            
            self.formatter.print_info("\nFor Gmail users:")
            self.formatter.print_info("1. Use smtp.gmail.com as SMTP server")
            self.formatter.print_info("2. Use 587 as SMTP port")
            self.formatter.print_info("3. Use your Gmail address as sender email")
            self.formatter.print_info("4. Use an App Password (not your regular Gmail password)")
            self.formatter.print_info("   To get an App Password:")
            self.formatter.print_info("   - Go to Google Account settings")
            self.formatter.print_info("   - Security > 2-Step Verification > App Passwords")
            self.formatter.print_info("   - Generate new App Password for 'Mail'")
            
            if self.formatter.confirm("\nWould you like to update email settings?"):
                # Get user email first
                user_email = self.formatter.get_input("\nEnter your email address: ")
                if user_email:
                    self.settings.set('user_email', user_email)
                
                # Get SMTP settings
                self.formatter.print_info("\nSMTP Settings:")
                smtp_server = self.formatter.get_input("Enter SMTP server (default: smtp.gmail.com): ") or "smtp.gmail.com"
                smtp_port = self.formatter.get_input("Enter SMTP port (default: 587): ") or "587"
                sender_email = self.formatter.get_input("Enter sender email (your Gmail address): ")
                sender_password = self.formatter.get_input("Enter App Password (16-character password from Google): ", password=True)
                
                if sender_email and sender_password:
                    self.settings.update_email_settings(
                        smtp_server=smtp_server,
                        smtp_port=int(smtp_port),
                        sender_email=sender_email,
                        sender_password=sender_password
                    )
                    self.formatter.print_success("Email settings updated successfully!")
                    
                    # Test the settings if user wants
                    if self.formatter.confirm("\nWould you like to test the email settings?"):
                        self.formatter.print_info("Sending test email...")
                        email_sender = EmailSender()
                        success, message = email_sender.send_email(
                            sender_email,
                            "Password Manager - Test Email",
                            "This is a test email from your password manager."
                        )
                        if success:
                            self.formatter.print_success("Test email sent successfully! Please check your inbox.")
                        else:
                            self.formatter.print_error(f"Failed to send test email: {message}")
                            self.formatter.print_info("Please verify your email settings and try again.")
                else:
                    self.formatter.print_error("Email settings update cancelled - required fields were empty")
            
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {str(e)}") 