# Secure Password Manager

A secure, feature-rich password manager with encryption, MFA, and advanced security features.

## Features

- Strong encryption for passwords and secure notes
- Multi-factor authentication (MFA) support
- Biometric authentication (where available)
- Password strength analysis
- Password breach checking via HaveIBeenPwned API
- Secure password generation
- Backup and restore functionality
- Comprehensive audit logging
- Emergency access management
- Secure notes storage
- Password health reporting

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the password manager:
```bash
python -m password_manager
```

On first run, you'll be prompted to:
1. Set up a master password
2. Configure MFA (optional)
3. Set up biometric authentication (if available)

## Security Features

### Encryption
- Uses industry-standard encryption (Fernet)
- All sensitive data is encrypted at rest
- Secure key derivation using PBKDF2

### Authentication
- Master password with bcrypt hashing
- Multi-factor authentication (TOTP)
- Biometric authentication support
- Backup codes for account recovery

### Password Security
- Password strength analysis
- Breach checking via HaveIBeenPwned
- Secure password generation
- Password age monitoring

### Audit & Monitoring
- Comprehensive audit logging
- Suspicious activity detection
- Failed login attempt tracking

## Directory Structure

```
password_manager/
├── __init__.py
├── __main__.py
├── authentication/
│   ├── __init__.py
│   └── auth_manager.py
├── encryption/
│   ├── __init__.py
│   └── crypto.py
├── storage/
│   ├── __init__.py
│   └── file_handler.py
├── utils/
│   ├── __init__.py
│   ├── password_utils.py
│   └── audit_logger.py
├── ui/
│   ├── __init__.py
│   └── cli.py
└── config/
    ├── __init__.py
    └── settings.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Considerations

- The master password is never stored in plain text
- All sensitive data is encrypted using strong cryptography
- MFA adds an additional layer of security
- Regular security audits are recommended
- Keep your master password and backup codes secure
- Enable biometric authentication where available

## Backup and Recovery

- Regular backups are recommended
- Store backup codes in a secure location
- Configure trusted contacts for emergency access
- Test the restore process periodically

## Requirements

- Python 3.8 or higher
- See requirements.txt for package dependencies

## Disclaimer

This password manager is provided as-is, without any warranties. Always maintain secure backups of your passwords and use strong security practices.
