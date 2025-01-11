"""
Terminal formatting utilities using rich library.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.progress import Progress

console = Console()

class TerminalFormatter:
    @staticmethod
    def print_header(text):
        """Print a header with a panel."""
        console.print(Panel(text, style="bold blue"))

    @staticmethod
    def print_success(text):
        """Print a success message."""
        console.print(f"✓ {text}", style="bold green")

    @staticmethod
    def print_error(text):
        """Print an error message."""
        console.print(f"✗ {text}", style="bold red")

    @staticmethod
    def print_warning(text):
        """Print a warning message."""
        console.print(f"! {text}", style="bold yellow")

    @staticmethod
    def print_info(text):
        """Print an info message."""
        console.print(f"ℹ {text}", style="bold cyan")

    @staticmethod
    def create_menu_table(title, options):
        """Create a table for menu options."""
        table = Table(title=title, show_header=False, title_style="bold magenta")
        table.add_column("Option", style="cyan")
        table.add_column("Description", style="white")

        for key, value in options.items():
            table.add_row(str(key), value)

        console.print(table)

    @staticmethod
    def get_input(prompt_text, password=False):
        """Get user input with optional password masking."""
        return Prompt.ask(prompt_text, password=password)

    @staticmethod
    def confirm(prompt_text):
        """Get user confirmation."""
        return Confirm.ask(prompt_text)

    @staticmethod
    def create_progress():
        """Create a progress bar."""
        return Progress()

    @staticmethod
    def print_account_list(accounts):
        """Print a formatted list of accounts."""
        if not accounts:
            console.print("No accounts stored yet.", style="yellow")
            return

        table = Table(title="Stored Accounts", show_header=True)
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Account", style="green")
        table.add_column("Username", style="blue")
        table.add_column("Created Date", style="magenta")

        for i, (account, data) in enumerate(sorted(accounts.items()), 1):
            table.add_row(
                str(i),
                account,
                data.get("username", "N/A"),
                data.get("created_date", "N/A")
            )

        console.print(table)

    @staticmethod
    def print_password_preview(password, show_chars=3):
        """Print a password preview with partial masking."""
        if len(password) <= show_chars * 2:
            return "*" * len(password)
        
        return password[:show_chars] + "*" * (len(password) - show_chars * 2) + password[-show_chars:]

    @staticmethod
    def print_help_menu():
        """Print the help menu."""
        help_text = """
        [bold magenta]Password Manager Help[/bold magenta]

        [bold cyan]Main Menu Options:[/bold cyan]
        1. Add Password - Store a new password for an account
        2. Retrieve Password - View stored password details
        3. List Accounts - View all stored accounts
        4. Remove Password - Delete a stored password
        5. Generate Password - Create a strong random password
        6. Backup/Restore - Manage password database backups
        7. MFA Settings - Configure multi-factor authentication
        8. Password Health - Check password security status
        9. Improve Passwords - Get suggestions for weak passwords
        10. Secure Notes - Store and manage secure notes
        11. Audit Logs - View system activity logs
        12. Emergency Access - Configure emergency access options
        13. Passwordless Auth - Set up biometric authentication
        14. Exit - Close the password manager

        [bold yellow]Tips:[/bold yellow]
        • Use strong, unique passwords for each account
        • Enable MFA for additional security
        • Regularly check password health
        • Keep backup codes in a secure location
        • Set up emergency access for account recovery

        [bold red]Security Notes:[/bold red]
        • Never share your master password
        • Always verify biometric prompts carefully
        • Log out when finished
        • Keep your backup files secure
        """
        console.print(Panel(help_text, title="Help Menu", border_style="blue"))

    @staticmethod
    def search_accounts(accounts, search_term):
        """Search accounts and return matching results."""
        search_term = search_term.lower()
        matches = {}
        
        for account, data in accounts.items():
            if (search_term in account.lower() or 
                search_term in data.get("username", "").lower()):
                matches[account] = data
        
        return matches 