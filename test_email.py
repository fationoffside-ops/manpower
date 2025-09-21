from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables
load_dotenv()

# Email configuration
MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

def test_email_connection():
    try:
        # Create server connection
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
        server.starttls()
        
        # Login
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        print("✓ Successfully connected to email server")
        
        # Create test message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Test Email - Manpower Platform'
        msg['From'] = MAIL_USERNAME
        msg['To'] = MAIL_USERNAME  # Send to yourself
        
        text = "This is a test email from Manpower Platform"
        html = "<h1>Test Email</h1><p>This is a test email from Manpower Platform</p>"
        
        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        
        # Send email
        server.send_message(msg)
        print("✓ Test email sent successfully")
        
        # Close connection
        server.quit()
        print("✓ Connection closed")
        
        assert True
        
    except Exception as e:
        print(f"Error: {str(e)}")
        assert False, str(e)

if __name__ == '__main__':
    test_email_connection()
