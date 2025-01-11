"""Password utilities for the password manager."""

import re
import string
import secrets
import hashlib
import requests

class PasswordUtils:
    def __init__(self):
        """Initialize password utilities."""
        self.MIN_LENGTH = 12
        self.SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate_strong_password(self, length=16):
        """Generate a strong random password."""
        if length < self.MIN_LENGTH:
            length = self.MIN_LENGTH

        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = self.SPECIAL_CHARS

        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]

        # Fill the rest with random characters
        all_chars = lowercase + uppercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))

        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)

    def calculate_password_strength(self, password):
        """Calculate password strength score (0-100)."""
        if not password:
            return 0

        score = 0
        length = len(password)
        
        # Length score (up to 30 points)
        if length >= self.MIN_LENGTH:
            score += 30
        else:
            score += (length / self.MIN_LENGTH) * 30

        # Character variety score (up to 40 points)
        if re.search(r'[A-Z]', password):  # Uppercase
            score += 10
        if re.search(r'[a-z]', password):  # Lowercase
            score += 10
        if re.search(r'\d', password):     # Digits
            score += 10
        if re.search(f'[{re.escape(self.SPECIAL_CHARS)}]', password):  # Special chars
            score += 10

        # Complexity score (up to 30 points)
        # Check for repeated characters
        if not re.search(r'(.)\1{2,}', password):  # No character repeated more than twice
            score += 10
        # Check for sequential characters
        if not re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)', password.lower()):
            score += 10
        # Check for keyboard patterns
        if not re.search(r'(qwer|asdf|zxcv|!@#$|1234|4321)', password.lower()):
            score += 10

        return min(100, score)  # Cap at 100

    def check_password_strength(self, password):
        """Check password strength and return feedback."""
        score = self.calculate_password_strength(password)
        
        # Initialize feedback
        strengths = []
        weaknesses = []
        
        # Length checks
        if len(password) >= self.MIN_LENGTH:
            strengths.append("Good length")
        else:
            weaknesses.append(f"Password should be at least {self.MIN_LENGTH} characters long")
            
        # Character variety checks
        if re.search(r'[A-Z]', password):
            strengths.append("Contains uppercase letters")
        else:
            weaknesses.append("Missing uppercase letters")
            
        if re.search(r'[a-z]', password):
            strengths.append("Contains lowercase letters")
        else:
            weaknesses.append("Missing lowercase letters")
            
        if re.search(r'\d', password):
            strengths.append("Contains numbers")
        else:
            weaknesses.append("Missing numbers")
            
        if re.search(f'[{re.escape(self.SPECIAL_CHARS)}]', password):
            strengths.append("Contains special characters")
        else:
            weaknesses.append("Missing special characters")
            
        # Complexity checks
        if re.search(r'(.)\1{2,}', password):
            weaknesses.append("Contains repeated characters")
            
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)', password.lower()):
            weaknesses.append("Contains sequential characters")
            
        if re.search(r'(qwer|asdf|zxcv|!@#$|1234|4321)', password.lower()):
            weaknesses.append("Contains keyboard patterns")
            
        # Determine overall strength
        if score >= 80:
            strength = "Strong"
        elif score >= 60:
            strength = "Medium"
        else:
            strength = "Weak"
            
        return {
            'score': score,
            'strength': strength,
            'strengths': strengths,
            'weaknesses': weaknesses
        }

    def check_haveibeenpwned(self, password):
        """Check if password has been exposed in data breaches using HaveIBeenPwned API."""
        # Create SHA-1 hash of the password
        password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = password_hash[:5]
        suffix = password_hash[5:]
        
        try:
            # Query the API with the hash prefix
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
            response.raise_for_status()
            
            # Check if the hash suffix appears in the response
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return int(count)
            
            return 0
        except Exception as e:
            print(f"Error checking HaveIBeenPwned: {str(e)}")
            return 0 