"""
Utility functions for the password manager.
Contains helper functions used across different modules.
"""

import os
import shutil
from datetime import datetime
from typing import Dict, List, Optional

class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'

def create_backup(data_dir: str, backup_dir: str) -> Optional[str]:
    """
    Create a backup of all password manager data.
    
    Args:
        data_dir: Directory containing data files
        backup_dir: Directory to store backups
        
    Returns:
        Optional[str]: Path to backup directory if successful, None otherwise
    """
    try:
        # Create backup directory if it doesn't exist
        os.makedirs(backup_dir, exist_ok=True)
        
        # Create a timestamp for the backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"backup_{timestamp}")
        os.makedirs(backup_path)
        
        # Copy all files from data directory to backup directory
        for item in os.listdir(data_dir):
            src = os.path.join(data_dir, item)
            dst = os.path.join(backup_path, item)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
        
        return backup_path
        
    except Exception as e:
        print(f"Error creating backup: {e}")
        return None

def list_backups(backup_dir: str) -> List[str]:
    """
    List all available backups.
    
    Args:
        backup_dir: Directory containing backups
        
    Returns:
        List[str]: List of backup directory names
    """
    if not os.path.exists(backup_dir):
        return []
    
    backups = []
    for item in os.listdir(backup_dir):
        if item.startswith("backup_"):
            backups.append(item)
    
    return sorted(backups, reverse=True)  # Most recent first

def restore_from_backup(backup_path: str, data_dir: str) -> bool:
    """
    Restore password manager data from a backup.
    
    Args:
        backup_path: Path to the backup directory
        data_dir: Directory to restore data to
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Verify backup directory exists
        if not os.path.exists(backup_path):
            print("Backup directory not found.")
            return False
        
        # Create data directory if it doesn't exist
        os.makedirs(data_dir, exist_ok=True)
        
        # Copy all files from backup to data directory
        for item in os.listdir(backup_path):
            src = os.path.join(backup_path, item)
            dst = os.path.join(data_dir, item)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
        
        return True
        
    except Exception as e:
        print(f"Error restoring from backup: {e}")
        return False

def format_timestamp(timestamp: str) -> str:
    """
    Format an ISO timestamp into a readable string.
    
    Args:
        timestamp: ISO format timestamp string
        
    Returns:
        str: Formatted timestamp string
    """
    try:
        dt = datetime.fromisoformat(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return timestamp

def colorize(text: str, color: str) -> str:
    """
    Add color to text for terminal output.
    
    Args:
        text: Text to colorize
        color: Color to use (from Colors class)
        
    Returns:
        str: Colorized text
    """
    return f"{color}{text}{Colors.RESET}"

def format_password_strength(strength: str) -> str:
    """
    Format password strength with appropriate color.
    
    Args:
        strength: Password strength level
        
    Returns:
        str: Colorized strength string
    """
    if strength == "Strong":
        return colorize(strength, Colors.GREEN)
    elif strength == "Medium":
        return colorize(strength, Colors.YELLOW)
    else:
        return colorize(strength, Colors.RED)

def parse_date(date_str: str) -> Optional[datetime]:
    """
    Parse date string in YYYY-MM-DD format.
    
    Args:
        date_str: Date string to parse
        
    Returns:
        Optional[datetime]: Parsed datetime object or None if invalid
    """
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None

def secure_string_comparison(str1: str, str2: str) -> bool:
    """
    Perform timing-safe string comparison.
    
    Args:
        str1: First string to compare
        str2: Second string to compare
        
    Returns:
        bool: True if strings are equal, False otherwise
    """
    if len(str1) != len(str2):
        return False
    
    result = 0
    for x, y in zip(str1, str2):
        result |= ord(x) ^ ord(y)
    return result == 0
