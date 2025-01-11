"""
Settings menu for the password manager.
"""

from ..config.user_settings import UserSettings
from ..utils.terminal_formatter import TerminalFormatter

class SettingsMenu:
    def __init__(self):
        self.settings = UserSettings()
        self.formatter = TerminalFormatter()

    def show_menu(self):
        """Display the settings menu."""
        while True:
            self.formatter.print_header("Settings Menu")
            
            menu_options = {
                "1": "Change Data Directory",
                "2": "Change Backup Directory",
                "3": "Password Preview Settings",
                "4": "Default Password Length",
                "5": "Password Age Warning",
                "6": "Security Settings",
                "7": "Theme Settings",
                "8": "Reset to Defaults",
                "9": "Return to Main Menu"
            }
            
            self.formatter.create_menu_table("Settings", menu_options)
            
            choice = self.formatter.get_input("\nEnter your choice")
            
            if choice == "1":
                self.change_data_directory()
            elif choice == "2":
                self.change_backup_directory()
            elif choice == "3":
                self.password_preview_settings()
            elif choice == "4":
                self.change_default_password_length()
            elif choice == "5":
                self.change_password_age_warning()
            elif choice == "6":
                self.security_settings()
            elif choice == "7":
                self.theme_settings()
            elif choice == "8":
                self.reset_settings()
            elif choice == "9":
                break
            else:
                self.formatter.print_error("Invalid choice")

    def change_data_directory(self):
        """Change the data directory setting."""
        current = self.settings.get_setting("data_directory")
        self.formatter.print_info(f"Current data directory: {current}")
        
        new_dir = self.formatter.get_input("Enter new data directory path (or Enter to cancel)")
        if new_dir:
            try:
                self.settings.set_setting("data_directory", new_dir)
                self.settings.ensure_directories()
                self.formatter.print_success("Data directory updated successfully")
            except Exception as e:
                self.formatter.print_error(f"Error updating data directory: {e}")

    def change_backup_directory(self):
        """Change the backup directory setting."""
        current = self.settings.get_setting("backup_directory")
        self.formatter.print_info(f"Current backup directory: {current}")
        
        new_dir = self.formatter.get_input("Enter new backup directory path (or Enter to cancel)")
        if new_dir:
            try:
                self.settings.set_setting("backup_directory", new_dir)
                self.settings.ensure_directories()
                self.formatter.print_success("Backup directory updated successfully")
            except Exception as e:
                self.formatter.print_error(f"Error updating backup directory: {e}")

    def password_preview_settings(self):
        """Configure password preview settings."""
        self.formatter.print_header("Password Preview Settings")
        
        # Toggle preview feature
        current = self.settings.get_setting("show_password_preview")
        if self.formatter.confirm(f"Password preview is currently {'enabled' if current else 'disabled'}. Toggle?"):
            self.settings.set_setting("show_password_preview", not current)
        
        # Change preview length
        if self.settings.get_setting("show_password_preview"):
            current = self.settings.get_setting("password_preview_chars")
            self.formatter.print_info(f"Current preview shows {current} characters from start and end")
            
            try:
                new_value = int(self.formatter.get_input("Enter new number of characters to show (0-5)"))
                if 0 <= new_value <= 5:
                    self.settings.set_setting("password_preview_chars", new_value)
                    self.formatter.print_success("Preview length updated successfully")
                else:
                    self.formatter.print_error("Value must be between 0 and 5")
            except ValueError:
                self.formatter.print_error("Please enter a valid number")

    def change_default_password_length(self):
        """Change the default password length setting."""
        current = self.settings.get_setting("default_password_length")
        self.formatter.print_info(f"Current default password length: {current}")
        
        try:
            new_length = int(self.formatter.get_input("Enter new default length (minimum 8)"))
            if new_length >= 8:
                self.settings.set_setting("default_password_length", new_length)
                self.formatter.print_success("Default password length updated successfully")
            else:
                self.formatter.print_error("Password length must be at least 8 characters")
        except ValueError:
            self.formatter.print_error("Please enter a valid number")

    def change_password_age_warning(self):
        """Change the password age warning threshold."""
        current = self.settings.get_setting("password_age_warning")
        self.formatter.print_info(f"Current password age warning: {current} days")
        
        try:
            new_days = int(self.formatter.get_input("Enter new warning threshold in days"))
            if new_days > 0:
                self.settings.set_setting("password_age_warning", new_days)
                self.formatter.print_success("Password age warning updated successfully")
            else:
                self.formatter.print_error("Warning threshold must be positive")
        except ValueError:
            self.formatter.print_error("Please enter a valid number")

    def security_settings(self):
        """Configure security-related settings."""
        self.formatter.print_header("Security Settings")
        
        # Max failed attempts
        current = self.settings.get_setting("max_failed_attempts")
        self.formatter.print_info(f"Current maximum failed attempts: {current}")
        
        try:
            new_value = int(self.formatter.get_input("Enter new maximum failed attempts (3-10)"))
            if 3 <= new_value <= 10:
                self.settings.set_setting("max_failed_attempts", new_value)
                self.formatter.print_success("Maximum failed attempts updated successfully")
            else:
                self.formatter.print_error("Value must be between 3 and 10")
        except ValueError:
            self.formatter.print_error("Please enter a valid number")
        
        # Session timeout
        current = self.settings.get_setting("session_timeout")
        self.formatter.print_info(f"\nCurrent session timeout: {current} seconds")
        
        try:
            new_value = int(self.formatter.get_input("Enter new session timeout in seconds (60-3600)"))
            if 60 <= new_value <= 3600:
                self.settings.set_setting("session_timeout", new_value)
                self.formatter.print_success("Session timeout updated successfully")
            else:
                self.formatter.print_error("Value must be between 60 and 3600 seconds")
        except ValueError:
            self.formatter.print_error("Please enter a valid number")

    def theme_settings(self):
        """Configure theme settings."""
        self.formatter.print_header("Theme Settings")
        
        current_theme = self.settings.get_theme()
        theme_elements = {
            "header": "Headers and titles",
            "success": "Success messages",
            "error": "Error messages",
            "warning": "Warning messages",
            "info": "Information messages"
        }
        
        self.formatter.print_info("Available styles: bold, dim, italic, underline")
        self.formatter.print_info("Available colors: black, red, green, yellow, blue, magenta, cyan, white")
        
        for element, description in theme_elements.items():
            current = current_theme.get(element, "")
            self.formatter.print_info(f"\nCurrent {description} style: {current}")
            
            new_style = self.formatter.get_input(f"Enter new style for {description} (or Enter to keep current)")
            if new_style:
                try:
                    self.settings.update_theme({element: new_style})
                    self.formatter.print_success(f"Updated {description} style")
                except Exception as e:
                    self.formatter.print_error(f"Error updating style: {e}")

    def reset_settings(self):
        """Reset all settings to defaults."""
        if self.formatter.confirm("Are you sure you want to reset all settings to defaults?"):
            self.settings.reset_to_defaults()
            self.formatter.print_success("Settings reset to defaults successfully") 