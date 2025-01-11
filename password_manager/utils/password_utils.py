"""
Password management utilities for the password manager.
"""

import random
import string
import requests
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from ..config.settings import Colors, PasswordStrength

class PasswordUtils:
    @staticmethod
    def generate_strong_password(length=16):
        """
        Generate a strong random password.
        The password will contain uppercase, lowercase, numbers, and special characters.
        """
        if length < 8:
            length = 8  # Minimum length for security
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each set
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill the rest with random characters from all sets
        all_characters = lowercase + uppercase + digits + special
        for _ in range(length - 4):
            password.append(random.choice(all_characters))
        
        # Shuffle the password
        random.shuffle(password)
        
        return ''.join(password)

    @staticmethod
    def calculate_password_strength(password):
        """
        Calculate a detailed password strength score and provide specific feedback.
        Returns a tuple of (score, list of strengths, list of weaknesses)
        """
        score = 0
        strengths = []
        weaknesses = []
        
        # Length check
        if len(password) >= 12:
            score += 2
            strengths.append("Good length (12+ characters)")
        elif len(password) >= 8:
            score += 1
            strengths.append("Minimum length met (8+ characters)")
        else:
            weaknesses.append("Password is too short (minimum 8 characters)")
        
        # Character type checks
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if has_upper:
            score += 1
            strengths.append("Contains uppercase letters")
        else:
            weaknesses.append("Missing uppercase letters")
            
        if has_lower:
            score += 1
            strengths.append("Contains lowercase letters")
        else:
            weaknesses.append("Missing lowercase letters")
            
        if has_digit:
            score += 1
            strengths.append("Contains numbers")
        else:
            weaknesses.append("Missing numbers")
            
        if has_special:
            score += 1
            strengths.append("Contains special characters")
        else:
            weaknesses.append("Missing special characters")
        
        # Additional checks
        if len(set(password)) < len(password) * 0.75:
            weaknesses.append("Too many repeated characters")
            score -= 1
        
        if len(password) >= 14:
            score += 1
            strengths.append("Extra long password (bonus)")
        
        return score, strengths, weaknesses

    @staticmethod
    def check_password_strength(password):
        """
        Check password strength and return detailed feedback with color coding.
        Returns a tuple (is_strong_enough, colored_message)
        """
        score, strengths, weaknesses = PasswordUtils.calculate_password_strength(password)
        
        # Determine strength level
        if score >= 6:
            strength = PasswordStrength.STRONG
            color = Colors.GREEN
            status = "Strong"
        elif score >= 4:
            strength = PasswordStrength.MEDIUM
            color = Colors.YELLOW
            status = "Medium"
        else:
            strength = PasswordStrength.WEAK
            color = Colors.RED
            status = "Weak"
        
        # Build detailed feedback message
        message = [f"\nPassword Strength: {color}{status}{Colors.RESET}"]
        
        if strengths:
            message.append("\nStrengths:")
            for s in strengths:
                message.append(f"✓ {s}")
        
        if weaknesses:
            message.append("\nWeaknesses:")
            for w in weaknesses:
                message.append(f"✗ {w}")
        
        # Password is considered strong enough if it's at least medium strength
        is_strong_enough = strength >= PasswordStrength.MEDIUM
        
        if not is_strong_enough:
            message.append("\nPlease improve your password by addressing the weaknesses.")
        
        return is_strong_enough, "\n".join(message)

    @staticmethod
    def check_haveibeenpwned(password):
        """Check if a password has been compromised using HaveIBeenPwned API."""
        # Hash the password
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        try:
            # Query the API with the hash prefix
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if response.status_code == 200:
                # Check if the hash suffix exists in the response
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return int(count)
            return 0
        except Exception as e:
            print(f"Error checking HaveIBeenPwned: {e}")
            return 0

    @staticmethod
    def analyze_password_health(passwords, encryption_manager):
        """Generate a comprehensive password health report."""
        stats = {
            "total": len(passwords),
            "strength": {"weak": 0, "medium": 0, "strong": 0},
            "reused": defaultdict(list),
            "compromised": [],
            "old": [],
            "problems": defaultdict(list)
        }
        
        # Analyze each password
        for account, data in passwords.items():
            decrypted_password = encryption_manager.decrypt_data(data['password'])
            
            # Check strength
            score, strengths, _ = PasswordUtils.calculate_password_strength(decrypted_password)
            
            if score >= 6:
                stats["strength"]["strong"] += 1
            elif score >= 4:
                stats["strength"]["medium"] += 1
                stats["problems"][account].append("Medium strength")
            else:
                stats["strength"]["weak"] += 1
                stats["problems"][account].append("Weak password")
            
            # Check for reuse
            stats["reused"][decrypted_password].append(account)
            
            # Check for compromised passwords
            if PasswordUtils.check_haveibeenpwned(decrypted_password) > 0:
                stats["compromised"].append(account)
                stats["problems"][account].append("Compromised in data breach")
            
            # Check password age if timestamp exists
            if "created_date" in data:
                created_date = datetime.fromisoformat(data["created_date"])
                if datetime.now() - created_date > timedelta(days=90):
                    stats["old"].append(account)
                    stats["problems"][account].append("Password older than 90 days")
        
        # Remove non-reused passwords from reused dict
        stats["reused"] = {k: v for k, v in stats["reused"].items() if len(v) > 1}
        
        return stats 