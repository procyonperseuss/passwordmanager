"""
Main entry point for the password manager.
"""

from .ui.cli import PasswordManagerCLI

def main():
    """Main entry point."""
    try:
        password_manager = PasswordManagerCLI()
        password_manager.run()
    except KeyboardInterrupt:
        print("\nGoodbye!")
        exit(0)
    except Exception as e:
        print(f"\nFatal error: {e}")
        exit(1)

if __name__ == "__main__":
    main() 