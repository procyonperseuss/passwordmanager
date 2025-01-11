"""Audit logging functionality for the password manager."""
import os
import json
from datetime import datetime, timedelta
from ..config.settings import AUDIT_LOG_FILE

class AuditLogger:
    def __init__(self):
        """Initialize the audit logger."""
        self.logs = []
        self.load_logs()

    def load_logs(self):
        """Load audit logs from file."""
        try:
            if os.path.exists(AUDIT_LOG_FILE):
                with open(AUDIT_LOG_FILE, 'r') as f:
                    self.logs = json.load(f)
            else:
                self.logs = []
                self.save_logs()  # Create the file with empty logs
        except Exception as e:
            self.logs = []
            print(f"Error loading audit logs: {str(e)}")

    def save_logs(self):
        """Save audit logs to file."""
        try:
            os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)
            with open(AUDIT_LOG_FILE, 'w') as f:
                json.dump(self.logs, f, indent=4)
        except Exception as e:
            print(f"Error saving audit logs: {str(e)}")

    def log_action(self, action, details, status="success"):
        """Log an action with timestamp and details."""
        if self.logs is None:
            self.logs = []
            
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'action': action,
            'details': details,
            'status': status
        }
        self.logs.append(log_entry)
        self.save_logs()

    def get_logs(self, start_date=None, end_date=None, action_type=None, status=None):
        """Get filtered logs based on criteria."""
        filtered_logs = self.logs.copy()
        
        if start_date:
            filtered_logs = [log for log in filtered_logs if datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S') >= start_date]
        
        if end_date:
            filtered_logs = [log for log in filtered_logs if datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S') <= end_date]
        
        if action_type:
            filtered_logs = [log for log in filtered_logs if log['action'] == action_type]
        
        if status:
            filtered_logs = [log for log in filtered_logs if log['status'] == status]
        
        return filtered_logs

    def get_recent_activity(self, hours=24):
        """Get logs from the last specified hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [log for log in self.logs if datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S') >= cutoff_time]

    def clear_old_logs(self, days=90):
        """Clear logs older than specified days."""
        cutoff_time = datetime.now() - timedelta(days=days)
        self.logs = [log for log in self.logs if datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S') >= cutoff_time]
        self.save_logs()

    def export_logs(self, format='json'):
        """Export logs in specified format."""
        if format == 'json':
            return self.logs
        elif format == 'csv':
            # Convert logs to CSV format
            csv_data = "timestamp,action,details,status\n"
            for log in self.logs:
                csv_data += f"{log['timestamp']},{log['action']},{log['details']},{log['status']}\n"
            return csv_data
        else:
            raise ValueError("Unsupported export format")

    def get_statistics(self):
        """Get statistics about audit logs."""
        stats = {
            'total_logs': len(self.logs),
            'actions': {},
            'statuses': {},
            'recent_activity': len(self.get_recent_activity())
        }
        
        for log in self.logs:
            # Count actions
            action = log['action']
            stats['actions'][action] = stats['actions'].get(action, 0) + 1
            
            # Count statuses
            status = log['status']
            stats['statuses'][status] = stats['statuses'].get(status, 0) + 1
        
        return stats 