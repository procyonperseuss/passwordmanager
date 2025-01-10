"""
Audit logs module for the password manager.
Handles logging and auditing of all operations.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from .encryption import EncryptionManager

class AuditAction:
    """Constants for audit log action types."""
    LOGIN_ATTEMPT = "Login Attempt"
    ADD_PASSWORD = "Added Password"
    UPDATE_PASSWORD = "Updated Password"
    REMOVE_PASSWORD = "Removed Password"
    GENERATE_PASSWORD = "Generated Password"
    ADD_NOTE = "Added Note"
    UPDATE_NOTE = "Updated Note"
    REMOVE_NOTE = "Removed Note"
    CREATE_BACKUP = "Created Backup"
    RESTORE_BACKUP = "Restored Backup"
    VIEW_PASSWORD = "Viewed Password"
    VIEW_NOTE = "Viewed Note"
    ADD_TRUSTED_CONTACT = "Added Trusted Contact"
    REMOVE_TRUSTED_CONTACT = "Removed Trusted Contact"
    EMERGENCY_ACCESS_REQUEST = "Emergency Access Request"
    EMERGENCY_ACCESS_GRANTED = "Emergency Access Granted"
    EMERGENCY_ACCESS_DENIED = "Emergency Access Denied"
    BIOMETRIC_AUTH_ATTEMPT = "Biometric Authentication Attempt"
    HARDWARE_TOKEN_AUTH_ATTEMPT = "Hardware Token Authentication Attempt"

class AuditLogger:
    """Handles audit logging operations."""
    
    AUDIT_LOG_FILE = "data/audit_logs.json"
    
    def __init__(self, encryption_manager: EncryptionManager):
        """
        Initialize the audit logger.
        
        Args:
            encryption_manager: Instance of EncryptionManager for encryption operations
        """
        self.encryption_manager = encryption_manager
        os.makedirs(os.path.dirname(self.AUDIT_LOG_FILE), exist_ok=True)
    
    def load_logs(self) -> List[Dict]:
        """
        Load audit logs from the encrypted file.
        
        Returns:
            List[Dict]: List of audit log entries
        """
        try:
            with open(self.AUDIT_LOG_FILE, 'r') as f:
                encrypted_data = f.read()
                if encrypted_data:
                    decrypted_data = self.encryption_manager.decrypt(encrypted_data)
                    return json.loads(decrypted_data)
        except FileNotFoundError:
            return []
        except Exception as e:
            print(f"Error loading audit logs: {e}")
            return []
    
    def save_logs(self, logs: List[Dict]) -> None:
        """
        Save audit logs to the encrypted file.
        
        Args:
            logs: List of log entries to save
        """
        try:
            encrypted_data = self.encryption_manager.encrypt(json.dumps(logs, indent=4))
            with open(self.AUDIT_LOG_FILE, 'w') as f:
                f.write(encrypted_data)
        except Exception as e:
            print(f"Error saving audit logs: {e}")
    
    def log_action(self, action: str, details: Dict, status: str = "success") -> None:
        """
        Log an action in the audit log.
        
        Args:
            action: The type of action performed
            details: Additional details about the action
            status: Status of the action (success/failure)
        """
        try:
            logs = self.load_logs()
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "details": details,
                "status": status
            }
            
            logs.append(log_entry)
            self.save_logs(logs)
        except Exception as e:
            print(f"Error logging action: {e}")
    
    def filter_logs(self, start_date: Optional[datetime] = None,
                   end_date: Optional[datetime] = None,
                   action_type: Optional[str] = None,
                   status: Optional[str] = None) -> List[Dict]:
        """
        Filter logs based on criteria.
        
        Args:
            start_date: Start date for filtering
            end_date: End date for filtering
            action_type: Type of action to filter
            status: Status to filter
            
        Returns:
            List[Dict]: Filtered log entries
        """
        filtered_logs = self.load_logs()
        
        if start_date:
            filtered_logs = [log for log in filtered_logs 
                           if datetime.fromisoformat(log["timestamp"]) >= start_date]
        
        if end_date:
            filtered_logs = [log for log in filtered_logs 
                           if datetime.fromisoformat(log["timestamp"]) <= end_date]
        
        if action_type:
            filtered_logs = [log for log in filtered_logs 
                           if log["action"] == action_type]
        
        if status:
            filtered_logs = [log for log in filtered_logs 
                           if log["status"] == status]
        
        return filtered_logs
    
    def get_activity_summary(self, days: int = 30) -> Dict:
        """
        Get a summary of activities over a period.
        
        Args:
            days: Number of days to summarize
            
        Returns:
            Dict: Summary of activities
        """
        from datetime import timedelta
        
        start_date = datetime.now() - timedelta(days=days)
        logs = self.filter_logs(start_date=start_date)
        
        summary = {
            "total_actions": len(logs),
            "success_rate": 0,
            "action_types": {},
            "failed_actions": []
        }
        
        success_count = 0
        for log in logs:
            # Count action types
            action = log["action"]
            summary["action_types"][action] = summary["action_types"].get(action, 0) + 1
            
            # Count successful actions
            if log["status"] == "success":
                success_count += 1
            else:
                summary["failed_actions"].append({
                    "timestamp": log["timestamp"],
                    "action": action,
                    "details": log["details"]
                })
        
        if logs:
            summary["success_rate"] = (success_count / len(logs)) * 100
        
        return summary
    
    def detect_suspicious_activity(self) -> List[Dict]:
        """
        Detect suspicious activities in the audit logs.
        
        Returns:
            List[Dict]: List of suspicious activities
        """
        from datetime import timedelta
        
        suspicious = []
        recent_logs = self.filter_logs(
            start_date=datetime.now() - timedelta(hours=24)
        )
        
        # Track login attempts
        login_attempts = [log for log in recent_logs 
                         if log["action"] == AuditAction.LOGIN_ATTEMPT]
        failed_logins = [log for log in login_attempts 
                        if log["status"] == "failure"]
        
        # Alert on multiple failed login attempts
        if len(failed_logins) >= 3:
            suspicious.append({
                "type": "Multiple Failed Logins",
                "count": len(failed_logins),
                "last_attempt": failed_logins[-1]["timestamp"]
            })
        
        # Track password views
        password_views = [log for log in recent_logs 
                         if log["action"] == AuditAction.VIEW_PASSWORD]
        if len(password_views) > 10:  # Arbitrary threshold
            suspicious.append({
                "type": "Excessive Password Views",
                "count": len(password_views),
                "last_view": password_views[-1]["timestamp"]
            })
        
        # Track emergency access attempts
        emergency_attempts = [log for log in recent_logs 
                            if log["action"] in [
                                AuditAction.EMERGENCY_ACCESS_REQUEST,
                                AuditAction.EMERGENCY_ACCESS_GRANTED,
                                AuditAction.EMERGENCY_ACCESS_DENIED
                            ]]
        if emergency_attempts:
            suspicious.append({
                "type": "Emergency Access Activity",
                "attempts": len(emergency_attempts),
                "details": emergency_attempts
            })
        
        return suspicious
