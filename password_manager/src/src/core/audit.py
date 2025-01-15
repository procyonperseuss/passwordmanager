"""Audit logging functionality for the password manager."""

import json
import os
from datetime import datetime, timedelta
from ..config.settings import AUDIT_LOG_FILE, AuditAction

class AuditLogger:
    def __init__(self):
        """Initialize the audit logger."""
        self.log_file = AUDIT_LOG_FILE
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        self.logs = self._load_logs()

    def _load_logs(self):
        """Load existing audit logs."""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    return json.load(f)
            return {'logs': []}
        except Exception as e:
            print(f"Error loading audit logs: {str(e)}")
            return {'logs': []}

    def _save_logs(self):
        """Save audit logs to file."""
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.logs, f, indent=4, default=str)
        except Exception as e:
            print(f"Error saving audit logs: {str(e)}")

    def log_action(self, action, details, status="success"):
        """Log an action with timestamp and details."""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'details': details,
                'status': status
            }
            
            if 'logs' not in self.logs:
                self.logs['logs'] = []
                
            self.logs['logs'].append(log_entry)
            self._save_logs()
        except Exception as e:
            print(f"Error logging action: {str(e)}")

    def get_logs(self, start_date=None, end_date=None, action_type=None, status=None):
        """Retrieve filtered logs."""
        try:
            filtered_logs = self.logs.get('logs', [])
            
            if start_date:
                filtered_logs = [log for log in filtered_logs 
                               if datetime.fromisoformat(log['timestamp']) >= start_date]
            
            if end_date:
                filtered_logs = [log for log in filtered_logs 
                               if datetime.fromisoformat(log['timestamp']) <= end_date]
            
            if action_type:
                filtered_logs = [log for log in filtered_logs 
                               if log['action'] == action_type]
            
            if status:
                filtered_logs = [log for log in filtered_logs 
                               if log['status'] == status]
            
            # Sort logs by timestamp in descending order (newest first)
            return sorted(filtered_logs, 
                        key=lambda x: datetime.fromisoformat(x['timestamp']), 
                        reverse=True)
        except Exception as e:
            print(f"Error retrieving logs: {str(e)}")
            return []

    def get_recent_activity(self, limit=10):
        """Get the most recent audit log entries."""
        try:
            logs = self.get_logs()  # This will get all logs sorted by timestamp
            return logs[:limit]  # Return only the specified number of most recent logs
        except Exception as e:
            print(f"Error retrieving recent activity: {str(e)}")
            return []

    def clear_old_logs(self, days_to_keep):
        """Remove logs older than specified days."""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            self.logs['logs'] = [
                log for log in self.logs.get('logs', [])
                if datetime.fromisoformat(log['timestamp']) >= cutoff_date
            ]
            self._save_logs()
        except Exception as e:
            print(f"Error clearing old logs: {str(e)}")

    def export_logs(self, filename, format='json'):
        """Export logs to a file in the specified format."""
        try:
            logs = self.get_logs()
            
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump({'logs': logs}, f, indent=4, default=str)
            elif format == 'csv':
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(['Timestamp', 'Action', 'Details', 'Status'])
                    # Write data
                    for log in logs:
                        writer.writerow([
                            log['timestamp'],
                            log['action'],
                            log['details'],
                            log['status']
                        ])
            
            return True
        except Exception as e:
            print(f"Error exporting logs: {str(e)}")
            return False

    def get_statistics(self):
        """Get statistics about the audit logs."""
        try:
            logs = self.logs.get('logs', [])
            
            stats = {
                'total_entries': len(logs),
                'action_counts': {},
                'status_counts': {
                    'success': 0,
                    'failure': 0
                },
                'first_entry': None,
                'last_entry': None
            }
            
            if logs:
                # Sort logs by timestamp
                sorted_logs = sorted(logs, key=lambda x: x['timestamp'])
                stats['first_entry'] = sorted_logs[0]['timestamp']
                stats['last_entry'] = sorted_logs[-1]['timestamp']
                
                # Count actions and statuses
                for log in logs:
                    # Count actions
                    action = log['action']
                    stats['action_counts'][action] = stats['action_counts'].get(action, 0) + 1
                    
                    # Count statuses
                    status = log['status']
                    stats['status_counts'][status] = stats['status_counts'].get(status, 0) + 1
            
            return stats
        except Exception as e:
            print(f"Error getting statistics: {str(e)}")
            return None 