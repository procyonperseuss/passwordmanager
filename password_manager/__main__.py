"""
Main entry point for the password manager.
"""

import sys
from .ui.cli import PasswordManagerCLI

def main():
    """Main function to run the password manager."""
    try:
        password_manager = PasswordManagerCLI()
        password_manager.run()
    except KeyboardInterrupt:
        print("\nExiting password manager...")
        sys.exit(0)
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 