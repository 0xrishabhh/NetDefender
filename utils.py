import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from zxcvbn import zxcvbn
from dotenv import load_dotenv
import re
import ssl

load_dotenv()

# Email configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 465  # Using SSL port instead of TLS
EMAIL_USER = 'Replace this wit your email'
EMAIL_PASSWORD = 'enter app passwd'  # Google App Password

def load_wordlist(file_path):
    """Load a wordlist from file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return set(line.strip().lower() for line in f)
    except FileNotFoundError:
        print(f"Warning: Wordlist file {file_path} not found")
        return set()

def check_password_strength(password):
    """Check password strength using zxcvbn."""
    result = zxcvbn(password)
    return {
        'score': result['score'],
        'feedback': result['feedback'],
        'crack_time': result['crack_times_display']
    }

def send_email(to_email, subject, body):
    """Send an email using SMTP with SSL."""
    if not all([EMAIL_USER, EMAIL_PASSWORD]):
        print("Warning: Email credentials not configured")
        print(f"EMAIL_USER: {'Set' if EMAIL_USER else 'Not Set'}")
        print(f"EMAIL_PASSWORD: {'Set' if EMAIL_PASSWORD else 'Not Set'}")
        return False
    
    try:
        print(f"Attempting to send email to {to_email}")
        print(f"Using SMTP server: {EMAIL_HOST}:{EMAIL_PORT}")
        
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT, context=context) as server:
            print("Connected to SMTP server")
            try:
                server.login(EMAIL_USER, EMAIL_PASSWORD)
                print("Login successful")
                server.send_message(msg)
                print(f"Email sent successfully to {to_email}")
                return True
            except smtplib.SMTPAuthenticationError as auth_error:
                print(f"Authentication failed: {auth_error}")
                print("\nThis error occurs because:")
                print("1. You need to enable 2-Step Verification in your Google Account")
                print("2. Generate an App Password for this application")
                print("\nTo fix this:")
                print("1. Go to https://myaccount.google.com/security")
                print("2. Enable 2-Step Verification if not already enabled")
                print("3. Go to https://myaccount.google.com/apppasswords")
                print("4. Generate a new App Password:")
                print("   - Select 'Mail' for the app")
                print("   - Select your device")
                print("   - Click Generate")
                print("5. Copy the 16-character password")
                print("6. Update the EMAIL_PASSWORD in your .env file")
                return False
            
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {
        # Documents
        'pdf', 'doc', 'docx', 'txt', 'rtf', 'odt',
        # Spreadsheets
        'csv', 'xls', 'xlsx', 'ods',
        # Images
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp',
        # Presentations
        'ppt', 'pptx', 'odp',
        # Archives
        'zip', 'rar', '7z',
        # Audio
        'mp3', 'wav', 'ogg', 'm4a',
        # Video
        'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv'
    }
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS 
