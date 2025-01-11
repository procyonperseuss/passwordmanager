"""
Terminal formatting utilities using rich library.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.progress import Progress

class TerminalFormatter:
    def __init__(self):
        self.console = Console()

    def print_header(self, text):
        """Print a header with a panel."""
        self.console.print(Panel(text, style="bold blue"))

    def print_success(self, text):
        """Print a success message."""
        self.console.print(f"✓ {text}", style="bold green")

    def print_error(self, text):
        """Print an error message."""
        self.console.print(f"✗ {text}", style="bold red")

    def print_warning(self, text):
        """Print a warning message."""
        self.console.print(f"! {text}", style="bold yellow")

    def print_info(self, text):
        """Print an info message."""
        self.console.print(f"ℹ {text}", style="bold cyan")

    def create_menu_table(self, title, options):
        """Create a table for menu options."""
        table = Table(title=title, show_header=False, title_style="bold magenta")
        table.add_column("Option", style="cyan")
        table.add_column("Description", style="white")

        for key, value in options.items():
            table.add_row(str(key), value)

        self.console.print(table)

    def get_input(self, prompt_text, password=False):
        """Get user input with optional password masking."""
        return Prompt.ask(prompt_text, password=password)

    def confirm(self, prompt_text):
        """Get user confirmation."""
        return Confirm.ask(prompt_text)

    def create_progress(self):
        """Create a progress bar."""
        return Progress(console=self.console)

    def print_account_list(self, accounts):
        """Print a formatted list of accounts."""
        if not accounts:
            self.console.print("No accounts stored yet.", style="yellow")
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

        self.console.print(table)

    def print_password_preview(self, password, show_chars=3):
        """Print a password preview with partial masking."""
        if len(password) <= show_chars * 2:
            return "*" * len(password)
        
        return password[:show_chars] + "*" * (len(password) - show_chars * 2) + password[-show_chars:]

    def print_help_menu(self):
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
        14. Settings - Configure application settings
        15. Help - Show this help menu
        16. Exit - Close the password manager

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
        self.console.print(Panel(help_text, title="Help Menu", border_style="blue"))

    def search_accounts(self, accounts, search_term):
        """Search accounts and return matching results."""
        search_term = search_term.lower()
        matches = {}
        
        for account, data in accounts.items():
            if (search_term in account.lower() or 
                search_term in data.get("username", "").lower()):
                matches[account] = data
        
        return matches 