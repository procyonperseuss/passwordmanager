"""
Secure notes module for the password manager.
Handles secure note storage and retrieval.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from .encryption import EncryptionManager

class SecureNotesManager:
    """Handles secure notes operations."""
    
    NOTES_FILE = "data/secure_notes.json"
    
    def __init__(self, encryption_manager: EncryptionManager):
        """
        Initialize the secure notes manager.
        
        Args:
            encryption_manager: Instance of EncryptionManager for encryption operations
        """
        self.encryption_manager = encryption_manager
        self.notes = self.load_notes()
        os.makedirs(os.path.dirname(self.NOTES_FILE), exist_ok=True)
    
    def load_notes(self) -> Dict:
        """
        Load secure notes from the JSON file.
        
        Returns:
            Dict: Dictionary of stored notes
        """
        try:
            with open(self.NOTES_FILE, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {}
    
    def save_notes(self) -> None:
        """Save secure notes to the JSON file."""
        with open(self.NOTES_FILE, 'w') as file:
            json.dump(self.notes, file, indent=4)
    
    def add_note(self, title: str, content: str) -> bool:
        """
        Add a new secure note.
        
        Args:
            title: Title of the note
            content: Content of the note
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            encrypted_content = self.encryption_manager.encrypt(content)
            
            self.notes[title] = {
                "content": encrypted_content,
                "created_date": datetime.now().isoformat(),
                "last_modified": datetime.now().isoformat()
            }
            
            self.save_notes()
            return True
            
        except Exception as e:
            print(f"Error adding note: {e}")
            return False
    
    def retrieve_note(self, title: str) -> Optional[Dict]:
        """
        Retrieve a secure note.
        
        Args:
            title: Title of the note to retrieve
            
        Returns:
            Optional[Dict]: Note details if found, None otherwise
        """
        if title not in self.notes:
            return None
        
        note = self.notes[title]
        try:
            decrypted_content = self.encryption_manager.decrypt(note['content'])
            return {
                "title": title,
                "content": decrypted_content,
                "created_date": note['created_date'],
                "last_modified": note['last_modified']
            }
        except Exception as e:
            print(f"Error retrieving note: {e}")
            return None
    
    def remove_note(self, title: str) -> bool:
        """
        Remove a secure note.
        
        Args:
            title: Title of the note to remove
            
        Returns:
            bool: True if successful, False otherwise
        """
        if title not in self.notes:
            return False
        
        try:
            del self.notes[title]
            self.save_notes()
            return True
        except Exception as e:
            print(f"Error removing note: {e}")
            return False
    
    def list_notes(self) -> List[Dict]:
        """
        Get a list of all stored notes.
        
        Returns:
            List[Dict]: List of note details
        """
        notes_list = []
        for title, details in self.notes.items():
            notes_list.append({
                "title": title,
                "created_date": details["created_date"],
                "last_modified": details["last_modified"]
            })
        return sorted(notes_list, key=lambda x: x["title"])
    
    def update_note(self, title: str, new_content: str) -> bool:
        """
        Update the content of an existing note.
        
        Args:
            title: Title of the note to update
            new_content: New content for the note
            
        Returns:
            bool: True if successful, False otherwise
        """
        if title not in self.notes:
            return False
        
        try:
            encrypted_content = self.encryption_manager.encrypt(new_content)
            
            self.notes[title].update({
                "content": encrypted_content,
                "last_modified": datetime.now().isoformat()
            })
            
            self.save_notes()
            return True
            
        except Exception as e:
            print(f"Error updating note: {e}")
            return False
