# Secure Password Manager

A secure command-line password manager with encryption, MFA, secure notes, and audit logging capabilities.

## Features

- Strong password encryption using Fernet (symmetric encryption)
- Master password protection with bcrypt hashing
- Multi-Factor Authentication (MFA) support
  - TOTP-based authentication (Google Authenticator, Authy, etc.)
  - Backup codes for account recovery
- Secure password generation
- Password strength analysis
- Secure notes storage
- Comprehensive audit logging
- Backup and restore functionality
- Biometric authentication support (where available)

## Project Structure

```
password_manager/
├── src/
│   ├── __init__.py
│   ├── main.py           # Main entry point
│   ├── auth.py           # Authentication and MFA
│   ├── encryption.py     # Encryption operations
│   ├── password_manager.py # Password management
│   ├── secure_notes.py   # Secure notes functionality
│   ├── audit_logs.py     # Audit logging
│   └── utils.py          # Helper functions
├── data/                 # Encrypted data storage
│   ├── passwords.json
│   ├── secure_notes.json
│   ├── audit_logs.json
│   └── ...
└── backups/             # Backup storage
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the password manager:
```bash
python -m password_manager.src.main
```

2. First-time setup:
   - Set your master password
   - Optionally enable MFA
   - Save your backup codes in a secure location

3. Available commands:
   - Add/retrieve/remove passwords
   - Generate strong passwords
   - Manage secure notes
   - View audit logs
   - Configure MFA settings

## Security Features

### Encryption
- Uses Fernet symmetric encryption (based on AES)
- Secure key derivation using PBKDF2
- All sensitive data is encrypted at rest

### Authentication
- Master password is hashed using bcrypt
- Optional MFA using TOTP
- Backup codes for account recovery
- Biometric authentication support

### Password Security
- Strong password generation
- Password strength analysis
- Secure password input handling

### Audit Logging
- All operations are logged
- Logs are encrypted
- Suspicious activity detection

## Development

### Adding New Features

1. Create a new module in the `src` directory
2. Update `main.py` to include the new functionality
3. Add appropriate tests
4. Update documentation

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Add docstrings for all functions and classes
- Keep functions focused and modular

## Security Considerations

- Master password is never stored in plain text
- All sensitive data is encrypted
- MFA adds an extra layer of security
- Regular security audits are recommended
- Backup your data regularly

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 