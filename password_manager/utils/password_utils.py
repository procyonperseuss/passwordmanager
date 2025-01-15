"""Password utilities for the password manager."""

import re
import string
import secrets
import hashlib
import requests
import zxcvbn
from ..config.settings import Colors

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
        """Calculate password strength score using zxcvbn (0-100)."""
        if not password:
            return 0

        # Use zxcvbn for sophisticated password analysis
        result = zxcvbn.zxcvbn(password)
        
        # Convert zxcvbn score (0-4) to our scale (0-100)
        base_score = result['score'] * 25  # This gives us 0, 25, 50, 75, or 100
        
        # Additional points for length beyond minimum
        length_bonus = min(10, max(0, len(password) - self.MIN_LENGTH))
        
        return min(100, base_score + length_bonus)

    def check_password_strength(self, password):
        """Check password strength and return detailed feedback with visual meter."""
        if not password:
            return {
                'score': 0,
                'strength': "Invalid",
                'strengths': [],
                'weaknesses': ["Password cannot be empty"],
                'visual_meter': self._generate_strength_meter(0)
            }

        # Get zxcvbn analysis
        result = zxcvbn.zxcvbn(password)
        score = self.calculate_password_strength(password)
        
        # Initialize feedback lists
        strengths = []
        weaknesses = []

        # Basic requirements check
        if len(password) >= self.MIN_LENGTH:
            strengths.append("Good length")
        else:
            weaknesses.append(f"Password should be at least {self.MIN_LENGTH} characters long")

        # Add zxcvbn feedback
        if result['feedback']['warning']:
            weaknesses.append(result['feedback']['warning'])
        for suggestion in result['feedback']['suggestions']:
            weaknesses.append(suggestion)

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

        # Determine strength category
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
            'weaknesses': weaknesses,
            'visual_meter': self._generate_strength_meter(score),
            'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second']
        }

    def _generate_strength_meter(self, score):
        """Generate a visual strength meter."""
        total_bars = 10
        filled_bars = int(score / 100 * total_bars)
        
        if score >= 80:
            color = Colors.GREEN
        elif score >= 60:
            color = Colors.YELLOW
        else:
            color = Colors.RED
            
        meter = f"{color}{'█' * filled_bars}{'░' * (total_bars - filled_bars)}{Colors.RESET}"
        return f"Strength: [{meter}] {score}/100"

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