"""
Audit logging functionality for the password manager.
"""

from datetime import datetime
from ..config.settings import AUDIT_LOG_FILE
from ..storage.file_handler import FileHandler
from ..encryption.crypto import EncryptionManager

class AuditLogger:
    def __init__(self):
        self.file_handler = FileHandler()
        self.encryption_manager = EncryptionManager()

    def load_audit_logs(self):
        """Load audit logs from the encrypted file."""
        try:
            encrypted_data = self.file_handler.load_json_file(AUDIT_LOG_FILE)
            if encrypted_data:
                decrypted_data = self.encryption_manager.decrypt_data(encrypted_data)
                return json.loads(decrypted_data)
        except FileNotFoundError:
            return []
        except Exception as e:
            print(f"Error loading audit logs: {e}")
            return []

    def save_audit_logs(self, logs):
        """Save audit logs to the encrypted file."""
        try:
            encrypted_data = self.encryption_manager.encrypt_data(json.dumps(logs, indent=4))
            self.file_handler.save_json_file(AUDIT_LOG_FILE, encrypted_data)
        except Exception as e:
            print(f"Error saving audit logs: {e}")

    def log_action(self, action, details, status="success"):
        """
        Log an action in the audit log.
        
        Args:
            action (str): The type of action performed
            details (dict): Additional details about the action
            status (str): Status of the action (success/failure)
        """
        try:
            logs = self.load_audit_logs()
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "details": details,
                "status": status
            }
            
            logs.append(log_entry)
            self.save_audit_logs(logs)
        except Exception as e:
            print(f"Error logging action: {e}")

    def filter_logs(self, logs, start_date=None, end_date=None, action_type=None, status=None):
        """Filter logs based on criteria."""
        filtered_logs = logs
        
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

    def detect_suspicious_activity(self):
        """Detect suspicious activities in the audit logs."""
        logs = self.load_audit_logs()
        suspicious = []
        
        # Check for suspicious activities in the last 24 hours
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        # Track failed login attempts
        failed_logins = defaultdict(int)
        
        for log in logs:
            log_time = datetime.fromisoformat(log["timestamp"])
            if log_time < cutoff_time:
                continue
            
            if log["action"] == "Login Attempt" and log["status"] == "failure":
                account = log["details"].get("account", "unknown")
                failed_logins[account] += 1
                
                if failed_logins[account] >= 3:
                    suspicious.append({
                        "type": "Multiple Failed Login Attempts",
                        "account": account,
                        "count": failed_logins[account],
                        "last_attempt": log["timestamp"]
                    })
        
        return suspicious 