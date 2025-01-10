"""
Main entry point for the password manager application.
Handles user interface and command routing.
"""

import sys
from typing import Optional

from .encryption import EncryptionManager
from .auth import AuthenticationManager
from .password_manager import PasswordManager
from .secure_notes import SecureNotesManager
from .audit_logs import AuditLogger, AuditAction
from .utils import Colors, format_password_strength, format_timestamp

class PasswordManagerCLI:
    """Command-line interface for the password manager."""
    
    def __init__(self):
        """Initialize the password manager CLI."""
        self.encryption_manager = EncryptionManager()
        self.auth_manager = AuthenticationManager()
        self.password_manager = PasswordManager(self.encryption_manager)
        self.secure_notes_manager = SecureNotesManager(self.encryption_manager)
        self.audit_logger = AuditLogger(self.encryption_manager)
    
    def authenticate(self) -> bool:
        """
        Authenticate the user.
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        if not self.auth_manager.verify_master_password():
            self.audit_logger.log_action(
                AuditAction.LOGIN_ATTEMPT,
                {"status": "Master password verification failed"},
                "failure"
            )
            print("Access denied.")
            return False
        
        if not self.auth_manager.verify_mfa():
            self.audit_logger.log_action(
                AuditAction.LOGIN_ATTEMPT,
                {"status": "MFA verification failed"},
                "failure"
            )
            print("MFA verification failed.")
            return False
        
        self.audit_logger.log_action(
            AuditAction.LOGIN_ATTEMPT,
            {"status": "Success"},
            "success"
        )
        return True
    
    def display_menu(self) -> None:
        """Display the main menu options."""
        print("\nPassword Manager")
        print("-" * 20)
        print("1. Add Password")
        print("2. Retrieve Password")
        print("3. List Accounts")
        print("4. Remove Password")
        print("5. Generate Strong Password")
        print("6. Secure Notes")
        print("7. View Audit Logs")
        print("8. MFA Settings")
        print("9. Exit")
    
    def add_password(self) -> None:
        """Handle adding a new password."""
        print("\nAdd New Password")
        print("-" * 20)
        
        account_name = input("Enter account name: ")
        username = input("Enter username: ")
        
        # Option to generate password
        gen_pass = input("Would you like to generate a strong password? (y/n): ")
        if gen_pass.lower() == 'y':
            length = input("Enter desired password length (minimum 8, press Enter for default 16): ")
            length = int(length) if length.strip() else 16
            password = self.password_manager.generate_password(length)
            print(f"\nGenerated password: {password}")
        else:
            password = input("Enter password: ")
        
        # Check password strength
        is_strong, strength, strengths, weaknesses = self.password_manager.check_password_strength(password)
        print(f"\nPassword Strength: {format_password_strength(strength)}")
        
        if strengths:
            print("\nStrengths:")
            for s in strengths:
                print(f"✓ {s}")
        
        if weaknesses:
            print("\nWeaknesses:")
            for w in weaknesses:
                print(f"✗ {w}")
        
        if not is_strong:
            confirm = input("\nPassword is not strong. Use anyway? (y/n): ")
            if confirm.lower() != 'y':
                return
        
        if self.password_manager.add_password(account_name, username, password):
            print("\nPassword saved successfully!")
            self.audit_logger.log_action(
                AuditAction.ADD_PASSWORD,
                {"account": account_name, "username": username},
                "success"
            )
        else:
            print("\nFailed to save password.")
            self.audit_logger.log_action(
                AuditAction.ADD_PASSWORD,
                {"account": account_name, "error": "Failed to save"},
                "failure"
            )
    
    def retrieve_password(self) -> None:
        """Handle retrieving a password."""
        print("\nRetrieve Password")
        print("-" * 20)
        
        account_name = input("Enter account name: ")
        account = self.password_manager.retrieve_password(account_name)
        
        if account:
            print("\nAccount Details:")
            print(f"Account: {account['account']}")
            print(f"Username: {account['username']}")
            print(f"Password: {account['password']}")
            print(f"Created: {format_timestamp(account['created_date'])}")
            
            self.audit_logger.log_action(
                AuditAction.VIEW_PASSWORD,
                {"account": account_name},
                "success"
            )
        else:
            print(f"\nNo password found for account: {account_name}")
            self.audit_logger.log_action(
                AuditAction.VIEW_PASSWORD,
                {"account": account_name, "error": "Account not found"},
                "failure"
            )
    
    def list_accounts(self) -> None:
        """Handle listing all accounts."""
        print("\nStored Accounts")
        print("-" * 20)
        
        accounts = self.password_manager.list_accounts()
        if not accounts:
            print("No accounts stored yet.")
            return
        
        print("\nYour accounts:")
        for i, account in enumerate(accounts, 1):
            print(f"{i}. Account: {account['account']}")
            print(f"   Username: {account['username']}")
            print(f"   Created: {format_timestamp(account['created_date'])}")
            print()
    
    def remove_password(self) -> None:
        """Handle removing a password."""
        print("\nRemove Password")
        print("-" * 20)
        
        account_name = input("Enter account name to remove: ")
        
        if self.password_manager.remove_password(account_name):
            print(f"\nPassword for '{account_name}' has been removed successfully!")
            self.audit_logger.log_action(
                AuditAction.REMOVE_PASSWORD,
                {"account": account_name},
                "success"
            )
        else:
            print(f"\nNo password found for account: {account_name}")
            self.audit_logger.log_action(
                AuditAction.REMOVE_PASSWORD,
                {"account": account_name, "error": "Account not found"},
                "failure"
            )
    
    def secure_notes_menu(self) -> None:
        """Handle secure notes operations."""
        while True:
            print("\nSecure Notes")
            print("-" * 20)
            print("1. Add Note")
            print("2. View Note")
            print("3. List Notes")
            print("4. Remove Note")
            print("5. Return to Main Menu")
            
            choice = input("\nEnter your choice (1-5): ")
            
            if choice == "1":
                self.add_note()
            elif choice == "2":
                self.view_note()
            elif choice == "3":
                self.list_notes()
            elif choice == "4":
                self.remove_note()
            elif choice == "5":
                break
            else:
                print("Invalid choice. Please try again.")
    
    def add_note(self) -> None:
        """Handle adding a new secure note."""
        print("\nAdd Secure Note")
        print("-" * 20)
        
        title = input("Enter note title: ")
        print("\nEnter note content (press Ctrl+D or Ctrl+Z on a new line to finish):")
        
        content_lines = []
        try:
            while True:
                line = input()
                content_lines.append(line)
        except (EOFError, KeyboardInterrupt):
            content = "\n".join(content_lines)
        
        if not content_lines:
            print("Note creation cancelled.")
            return
        
        if self.secure_notes_manager.add_note(title, content):
            print(f"\nSecure note '{title}' saved successfully!")
            self.audit_logger.log_action(
                AuditAction.ADD_NOTE,
                {"title": title},
                "success"
            )
        else:
            print("\nFailed to save note.")
            self.audit_logger.log_action(
                AuditAction.ADD_NOTE,
                {"title": title, "error": "Failed to save"},
                "failure"
            )
    
    def view_note(self) -> None:
        """Handle viewing a secure note."""
        print("\nView Secure Note")
        print("-" * 20)
        
        title = input("Enter note title: ")
        note = self.secure_notes_manager.retrieve_note(title)
        
        if note:
            print(f"\nTitle: {note['title']}")
            print("-" * (len(note['title']) + 7))
            print(f"Created: {format_timestamp(note['created_date'])}")
            print(f"Last Modified: {format_timestamp(note['last_modified'])}")
            print("\nContent:")
            print("-" * 7)
            print(note['content'])
            
            self.audit_logger.log_action(
                AuditAction.VIEW_NOTE,
                {"title": title},
                "success"
            )
        else:
            print(f"\nNo note found with title: {title}")
            self.audit_logger.log_action(
                AuditAction.VIEW_NOTE,
                {"title": title, "error": "Note not found"},
                "failure"
            )
    
    def list_notes(self) -> None:
        """Handle listing all secure notes."""
        print("\nSecure Notes")
        print("-" * 20)
        
        notes = self.secure_notes_manager.list_notes()
        if not notes:
            print("No secure notes found.")
            return
        
        print("\nYour secure notes:")
        for i, note in enumerate(notes, 1):
            print(f"{i}. Title: {note['title']}")
            print(f"   Created: {format_timestamp(note['created_date'])}")
            print(f"   Last Modified: {format_timestamp(note['last_modified'])}")
            print()
    
    def remove_note(self) -> None:
        """Handle removing a secure note."""
        print("\nRemove Secure Note")
        print("-" * 20)
        
        title = input("Enter note title to remove: ")
        
        if self.secure_notes_manager.remove_note(title):
            print(f"\nNote '{title}' has been removed successfully!")
            self.audit_logger.log_action(
                AuditAction.REMOVE_NOTE,
                {"title": title},
                "success"
            )
        else:
            print(f"\nNo note found with title: {title}")
            self.audit_logger.log_action(
                AuditAction.REMOVE_NOTE,
                {"title": title, "error": "Note not found"},
                "failure"
            )
    
    def mfa_settings(self) -> None:
        """Handle MFA settings."""
        while True:
            print("\nMFA Settings")
            print("-" * 20)
            
            mfa_config = self.auth_manager.load_mfa_config()
            if mfa_config["enabled"]:
                print("MFA Status: Enabled")
                print("1. Disable MFA")
                print("2. Generate New Backup Codes")
            else:
                print("MFA Status: Disabled")
                print("1. Enable MFA")
            
            print("3. Return to Main Menu")
            
            choice = input("\nEnter your choice: ")
            
            if choice == "1":
                if mfa_config["enabled"]:
                    if self.auth_manager.verify_mfa():
                        self.auth_manager.save_mfa_config({"enabled": False})
                        print("MFA disabled successfully!")
                    else:
                        print("MFA verification failed. MFA remains enabled.")
                else:
                    self.auth_manager.setup_mfa()
            elif choice == "2" and mfa_config["enabled"]:
                if self.auth_manager.verify_mfa():
                    backup_codes = self.auth_manager.generate_backup_codes()
                    self.auth_manager.save_mfa_config({
                        "enabled": True,
                        "secret_key": mfa_config["secret_key"],
                        "backup_codes": backup_codes
                    })
                    print("\nNew Backup Codes:")
                    for code in backup_codes:
                        print(code)
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")
    
    def run(self) -> None:
        """Run the password manager application."""
        print("Welcome to Password Manager!")
        
        if not self.authenticate():
            sys.exit(1)
        
        while True:
            try:
                self.display_menu()
                choice = input("\nEnter your choice (1-9): ")
                
                if choice == "1":
                    self.add_password()
                elif choice == "2":
                    self.retrieve_password()
                elif choice == "3":
                    self.list_accounts()
                elif choice == "4":
                    self.remove_password()
                elif choice == "5":
                    length = input("Enter desired password length (minimum 8, press Enter for default 16): ")
                    length = int(length) if length.strip() else 16
                    password = self.password_manager.generate_password(length)
                    print(f"\nGenerated password: {password}")
                elif choice == "6":
                    self.secure_notes_menu()
                elif choice == "7":
                    # TODO: Implement audit log viewing
                    print("Audit log viewing not implemented yet.")
                elif choice == "8":
                    self.mfa_settings()
                elif choice == "9":
                    print("\nGoodbye!")
                    break
                else:
                    print("Invalid choice. Please enter a number between 1 and 9.")
                    
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
            except Exception as e:
                print(f"\nAn error occurred: {e}")
                self.audit_logger.log_action(
                    "Error",
                    {"error": str(e)},
                    "failure"
                )

def main():
    """Main entry point for the application."""
    cli = PasswordManagerCLI()
    cli.run()

if __name__ == "__main__":
    main()
