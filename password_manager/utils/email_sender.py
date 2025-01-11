"""Email sender utility for the password manager."""
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ..config.settings import EMAIL_CONFIG

class EmailSender:
    def __init__(self):
        """Initialize the email sender with configuration."""
        self.smtp_server = EMAIL_CONFIG.get('smtp_server', 'smtp.gmail.com')
        self.smtp_port = EMAIL_CONFIG.get('smtp_port', 587)
        self.sender_email = EMAIL_CONFIG.get('sender_email', '')
        self.sender_password = EMAIL_CONFIG.get('sender_password', '')

    def send_emergency_access_request(self, owner_email, requester_email, reason):
        """Send emergency access request notification."""
        subject = "Emergency Access Request - Password Manager"
        body = f"""
        Dear Vault Owner,

        An emergency access request has been made for your password vault.

        Details:
        - Requester: {requester_email}
        - Reason: {reason}
        - Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

        To approve or deny this request, please log in to your password manager and go to:
        Emergency Access > Approve/Deny Access Requests

        If you did not expect this request, please deny it immediately.

        Best regards,
        Your Password Manager
        """
        
        return self.send_email(owner_email, subject, body)

    def send_emergency_access_decision(self, requester_email, approved, waiting_period=None):
        """Send notification about emergency access decision."""
        subject = "Emergency Access Request - Decision"
        if approved:
            body = f"""
            Dear User,

            Your emergency access request has been approved.
            
            Waiting Period: {waiting_period} hours
            You will be granted access after the waiting period expires.

            Please log in to your password manager to view the shared credentials
            once the waiting period has elapsed.

            Best regards,
            Your Password Manager
            """
        else:
            body = """
            Dear User,

            Your emergency access request has been denied by the vault owner.

            If you still need access, please submit a new request or contact
            the vault owner directly.

            Best regards,
            Your Password Manager
            """
        
        return self.send_email(requester_email, subject, body)

    def send_email(self, to_email, subject, body):
        """Send an email using SMTP."""
        if not self.sender_email or not self.sender_password:
            return False, "Email configuration is incomplete"

        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = to_email
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            return True, "Email sent successfully"
        except Exception as e:
            return False, f"Failed to send email: {str(e)}" 