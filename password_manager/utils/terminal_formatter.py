"""Terminal formatting utility for consistent UI presentation."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from getpass import getpass

class TerminalFormatter:
    def __init__(self):
        """Initialize terminal formatter."""
        self.console = Console()

    def print_header(self, text):
        """Print a header with consistent formatting."""
        self.console.print()
        self.console.print(Panel(
            Text(text, style="bold cyan", justify="center"),
            border_style="cyan"
        ))

    def print_success(self, message):
        """Print a success message."""
        self.console.print(f"✓ {message}", style="green")

    def print_error(self, message):
        """Print an error message."""
        self.console.print(f"✗ {message}", style="red")

    def print_warning(self, message):
        """Print a warning message."""
        self.console.print(f"! {message}", style="yellow")

    def print_info(self, message):
        """Print an info message."""
        self.console.print(message, style="blue")

    def get_input(self, prompt, password=False):
        """Get user input with consistent formatting."""
        if password:
            return getpass(f"{prompt}: ")
        return input(f"{prompt}: ").strip()

    def confirm(self, prompt):
        """Get user confirmation."""
        while True:
            response = self.get_input(f"{prompt} (y/n)").lower()
            if response in ['y', 'yes']:
                return True
            if response in ['n', 'no']:
                return False
            self.print_error("Please enter 'y' or 'n'")

    def print_password_preview(self, password, show_chars=3):
        """Print a password preview with partial masking."""
        if len(password) <= show_chars * 2:
            return "*" * len(password)
        
        return password[:show_chars] + "*" * (len(password) - show_chars * 2) + password[-show_chars:]

    def create_menu_table(self, title, options):
        """Create a menu table with consistent formatting."""
        table = Table(title=title, show_header=False, box=None)
        table.add_column("Option", style="cyan")
        table.add_column("Description")
        
        for key, value in options.items():
            table.add_row(f"[{key}]", value)
        
        self.console.print(table)

    def create_data_table(self, title, headers, rows):
        """Create a data table with consistent formatting."""
        table = Table(title=title)
        
        for header in headers:
            table.add_column(header, style="cyan")
        
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        
        self.console.print(table)

    def print_progress(self, message, completed, total):
        """Print a progress bar."""
        with self.console.status(message) as status:
            status.update(f"{message} [{completed}/{total}]") 

    def print_account_list(self, accounts):
        """Print a formatted list of accounts."""
        if not accounts:
            self.print_info("No accounts stored yet.")
            return

        table = Table(title="Stored Accounts")
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Account", style="green")
        table.add_column("Username", style="blue")
        table.add_column("Created Date", style="magenta")
        table.add_column("Last Modified", style="yellow")
        table.add_column("Strength", style="cyan")
        
        for i, (account, data) in enumerate(sorted(accounts.items()), 1):
            table.add_row(
                str(i),
                account,
                data.get("username", "N/A"),
                data.get("created_date", "N/A"),
                data.get("last_modified", "N/A"),
                data.get("strength", "N/A")
            )
        
        self.console.print(table)

    def search_accounts(self, accounts, search_term):
        """Search accounts and return matching results."""
        search_term = search_term.lower()
        matches = {}
        
        for account, data in accounts.items():
            if (search_term in account.lower() or 
                search_term in data.get("username", "").lower()):
                matches[account] = data
        
        return matches 

    def print_help_menu(self):
        """Print the help menu."""
        help_text = """
[bold cyan]Main Menu Options:[/bold cyan]

[bold green]Password Management:[/bold green]
1. Add Password - Store a new password for an account
2. Retrieve Password - View stored password details
3. List Accounts - View all stored accounts
4. Remove Password - Delete a stored password
5. Generate Password - Create a strong random password

[bold yellow]Security & Backup:[/bold yellow]
6. Backup/Restore - Manage password database backups
7. MFA Settings - Configure multi-factor authentication
8. Password Health - Check password security status
9. Improve Passwords - Get suggestions for weak passwords

[bold blue]Additional Features:[/bold blue]
10. Secure Notes - Store and manage secure notes
11. Audit Logs - View system activity logs
12. Emergency Access - Configure emergency access options
13. Passwordless Auth - Set up biometric authentication
14. Settings - Configure application settings
15. Help - Show this help menu
16. Exit - Close the password manager

[bold magenta]Security Tips:[/bold magenta]
• Use strong, unique passwords for each account
• Enable MFA for additional security
• Regularly check password health
• Keep backup codes in a secure location
• Set up emergency access for account recovery

[bold red]Important Notes:[/bold red]
• Never share your master password
• Always verify biometric prompts carefully
• Log out when finished
• Keep your backup files secure
• Regularly update your passwords
"""
        self.console.print(Panel(help_text, title="Help Menu", border_style="blue")) 

    def apply_theme(self, theme):
        """Apply theme settings to the formatter."""
        # Theme styles
        styles = {
            "default": {
                "header": "bold cyan",
                "success": "green",
                "error": "red",
                "warning": "yellow",
                "info": "blue"
            },
            "modern": {
                "header": "bold magenta",
                "success": "bold green",
                "error": "bold red",
                "warning": "bold yellow",
                "info": "bold cyan"
            },
            "classic": {
                "header": "white on blue",
                "success": "green",
                "error": "red",
                "warning": "yellow",
                "info": "cyan"
            },
            "minimal": {
                "header": "bold white",
                "success": "green",
                "error": "red",
                "warning": "yellow",
                "info": "blue"
            }
        }

        # Color schemes
        color_schemes = {
            "dark": {
                "background": "black",
                "text": "white",
                "accent": "cyan"
            },
            "light": {
                "background": "white",
                "text": "black",
                "accent": "blue"
            },
            "blue": {
                "background": "dark_blue",
                "text": "white",
                "accent": "cyan"
            },
            "green": {
                "background": "dark_green",
                "text": "white",
                "accent": "light_green"
            },
            "purple": {
                "background": "dark_magenta",
                "text": "white",
                "accent": "magenta"
            }
        }

        # Menu styles
        menu_styles = {
            "compact": {"box": None, "padding": (0, 1)},
            "expanded": {"box": "rounded", "padding": (1, 2)},
            "detailed": {"box": "double", "padding": (1, 3)}
        }

        # Get style settings
        style = styles.get(theme.get("style", "default"), styles["default"])
        colors = color_schemes.get(theme.get("color_scheme", "dark"), color_schemes["dark"])
        menu = menu_styles.get(theme.get("menu_style", "compact"), menu_styles["compact"])

        # Apply settings to console
        self.console = Console(
            style=f"{colors['text']} on {colors['background']}",
            highlight=True
        )

        # Store theme settings
        self._theme = {
            "style": style,
            "colors": colors,
            "menu": menu
        }

        # Update table settings
        self._table_style = {
            "box": menu["box"],
            "padding": menu["padding"],
            "header_style": style["header"],
            "border_style": colors["accent"]
        } 