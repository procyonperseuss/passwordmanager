"""
Command-line interface for the password manager.
"""

from datetime import datetime
import json
import os
from ..authentication.auth_manager import AuthenticationManager
from ..encryption.crypto import EncryptionManager
from ..storage.file_handler import FileHandler
from ..utils.password_utils import PasswordUtils
from ..utils.audit_logger import AuditLogger
from ..utils.terminal_formatter import TerminalFormatter
from ..config.settings import AuditAction
from .settings_menu import SettingsMenu

class PasswordManagerCLI:
    def __init__(self):
        self.auth_manager = AuthenticationManager()
        self.encryption_manager = EncryptionManager()
        self.file_handler = FileHandler()
        self.audit_logger = AuditLogger()
        self.formatter = TerminalFormatter()
        self.settings_menu = SettingsMenu()
        self.passwords = {}
        self.secure_notes = {}
        self.favorites = set()
        self.load_data()
        self.load_favorites()

    def load_data(self):
        """Load passwords and secure notes from storage."""
        self.passwords = self.file_handler.load_passwords()
        self.secure_notes = self.file_handler.load_secure_notes()

    def save_data(self):
        """Save passwords and secure notes to storage."""
        self.file_handler.save_passwords(self.passwords)
        self.file_handler.save_secure_notes(self.secure_notes)

    def load_favorites(self):
        """Load favorite accounts from file."""
        try:
            with open("favorites.json", "r") as f:
                self.favorites = set(json.load(f))
        except FileNotFoundError:
            self.favorites = set()

    def save_favorites(self):
        """Save favorite accounts to file."""
        with open("favorites.json", "w") as f:
            json.dump(list(self.favorites), f)

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
        self.formatter.print_header("Add New Password")
        
        account_name = self.formatter.get_input("Enter account name (e.g., Google)")
        username = self.formatter.get_input("Enter username")
        
        if generated_password:
            password = generated_password
            self.formatter.print_info("Using generated password.")
            is_strong, message = PasswordUtils.check_password_strength(password)
            print(message)
        else:
            while True:
                password = self.formatter.get_input("Enter password", password=True)
                is_strong, message = PasswordUtils.check_password_strength(password)
                print(message)
                
                if is_strong:
                    break
                
                if not self.formatter.confirm("Would you like to try another password?"):
                    self.formatter.print_warning("Proceeding with a weak password is not recommended.")
                    if self.formatter.confirm("Are you sure you want to use this password?"):
                        break
        
        try:
            # Encrypt the password before storing
            encrypted_password = self.encryption_manager.encrypt_data(password)
            
            self.passwords[account_name] = {
                "username": username,
                "password": encrypted_password,
                "created_date": datetime.now().isoformat()
            }
            
            self.save_data()
            
            self.formatter.print_success("Password saved successfully!")
            self.formatter.print_info(f"Account: {account_name}")
            self.formatter.print_info(f"Username: {username}")
            
            if self.formatter.confirm("Add this account to favorites?"):
                self.favorites.add(account_name)
                self.save_favorites()
                self.formatter.print_success("Added to favorites!")
            
            self.audit_logger.log_action(AuditAction.ADD_PASSWORD, {
                "account": account_name,
                "username": username,
                "password_strength": "strong" if is_strong else "weak"
            })
        except Exception as e:
            self.formatter.print_error(f"An error occurred: {e}")
            self.audit_logger.log_action(AuditAction.ADD_PASSWORD, {
                "account": account_name,
                "error": str(e)
            }, "failure")

    def retrieve_password(self):
        """Retrieve and display password details."""
        self.formatter.print_header("Retrieve Password")
        
        # Show favorites first if any exist
        if self.favorites:
            self.formatter.print_info("Favorite Accounts:")
            for i, account in enumerate(sorted(self.favorites), 1):
                if account in self.passwords:
                    print(f"{i}. ⭐ {account}")
            print()
        
        account_name = self.formatter.get_input("Enter account name or search term")
        
        # Search functionality
        matches = self.formatter.search_accounts(self.passwords, account_name)
        
        if len(matches) > 1:
            self.formatter.print_info("Multiple matches found:")
            for i, acc in enumerate(sorted(matches.keys()), 1):
                star = "⭐ " if acc in self.favorites else ""
                print(f"{i}. {star}{acc}")
            
            choice = self.formatter.get_input("Enter the number of the account to view (or 0 to cancel)")
            try:
                choice_idx = int(choice) - 1
                if choice_idx < 0:
                    return
                account_name = sorted(matches.keys())[choice_idx]
            except (ValueError, IndexError):
                self.formatter.print_error("Invalid choice")
                return
        elif len(matches) == 1:
            account_name = next(iter(matches.keys()))
        else:
            self.formatter.print_error("No matching accounts found")
            return
        
        if account_name in self.passwords:
            account = self.passwords[account_name]
            decrypted_password = self.encryption_manager.decrypt_data(account['password'])
            
            # Show password preview first
            self.formatter.print_info(f"\nAccount Details:")
            self.formatter.print_info(f"Account: {account_name}")
            self.formatter.print_info(f"Username: {account['username']}")
            preview = self.formatter.print_password_preview(decrypted_password)
            self.formatter.print_info(f"Password: {preview}")
            
            # Ask if user wants to see full password
            if self.formatter.confirm("Show full password?"):
                self.formatter.print_info(f"Full password: {decrypted_password}")
            
            # Option to toggle favorite status
            star = "⭐ " if account_name in self.favorites else ""
            if self.formatter.confirm(f"Toggle favorite status for {star}{account_name}?"):
                self.toggle_favorite(account_name)
            
            self.audit_logger.log_action(AuditAction.VIEW_PASSWORD, {
                "account": account_name
            })
        else:
            self.formatter.print_error(f"No password found for account: {account_name}")
            self.audit_logger.log_action(AuditAction.VIEW_PASSWORD, {
                "account": account_name,
                "error": "Account not found"
            }, "failure")

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
                    self.settings_menu.show_menu()
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