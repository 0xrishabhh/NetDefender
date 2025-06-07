from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import hashlib
import os
import random
import string
from utils import send_email

db = SQLAlchemy()

# Admin email configuration
ADMIN_EMAIL = "Replace with Admin mail"
SYSTEM_EMAIL = "Replace with system mail"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    lockout_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    otp = db.Column(db.String(6), nullable=True)
    otp_created_at = db.Column(db.DateTime, nullable=True)
    is_otp_verified = db.Column(db.Boolean, default=False)
    otp_method = db.Column(db.String(10), nullable=True)  # 'whatsapp' or 'email'

    def set_password(self, password):
        # Generate a random salt
        salt = os.urandom(32)
        # Hash the password with the salt using SHA256
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,  # Number of iterations
            dklen=128  # Length of the derived key
        )
        # Store both salt and key
        self.password_hash = salt.hex() + ':' + key.hex()

    def check_password(self, password):
        try:
            # Split the stored hash into salt and key
            salt_hex, key_hex = self.password_hash.split(':')
            salt = bytes.fromhex(salt_hex)
            stored_key = bytes.fromhex(key_hex)
            
            # Hash the provided password with the same salt
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000,  # Same number of iterations
                dklen=128  # Same key length
            )
            
            # Compare the keys
            return key == stored_key
        except Exception:
            return False

    def generate_otp(self, method='whatsapp'):
        """Generate a 6-digit OTP and set the verification method"""
        self.otp = ''.join(random.choices(string.digits, k=6))
        self.otp_created_at = datetime.now(timezone.utc)
        self.is_otp_verified = False
        self.otp_method = method
        db.session.commit()
        return self.otp

    def verify_otp(self, otp):
        """Verify the OTP and check if it's expired (5 minutes validity)"""
        if not self.otp or not self.otp_created_at:
            return False
        
        # Ensure otp_created_at is timezone-aware
        if self.otp_created_at.tzinfo is None:
            self.otp_created_at = self.otp_created_at.replace(tzinfo=timezone.utc)
        
        # Check if OTP is expired (5 minutes)
        if (datetime.now(timezone.utc) - self.otp_created_at).total_seconds() > 300:
            return False
        
        if self.otp == otp:
            self.is_otp_verified = True
            self.otp = None  # Clear the OTP after successful verification
            self.otp_method = None  # Clear the verification method
            db.session.commit()
            return True
        return False

    def increment_login_attempts(self):
        self.login_attempts += 1
        if self.login_attempts >= 5:  # Changed from 4 to 5 attempts
            self.is_locked = True
            self.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=15)  # 15-minute lockout
            self.send_lockout_notifications()
        db.session.commit()

    def send_lockout_notifications(self):
        """Send lockout notifications to both user and admin"""
        lockout_time = self.lockout_until.strftime("%Y-%m-%d %H:%M:%S")
        
        # Email to user
        user_subject = "Account Locked - Security Alert"
        user_body = f"""
Dear User,

Your account has been locked due to multiple failed login attempts.

Details:
- Email: {self.email}
- Lockout Time: {lockout_time}
- Lockout Duration: 15 minutes

For security reasons, please wait 15 minutes before attempting to log in again.
If you believe this is a mistake, please contact the administrator.

Best regards,
Your Security Team
"""
        send_email(self.email, user_subject, user_body)

        # Email to admin
        admin_subject = "Account Lockout Alert - Security Notification"
        admin_body = f"""
Security Alert - Account Locked

A user account has been locked due to multiple failed login attempts.

User Details:
- Email: {self.email}
- Phone: {self.phone_number}
- Lockout Time: {lockout_time}
- Lockout Duration: 15 minutes

This is an automated security notification.
Please monitor this account for any suspicious activity.

Best regards,
Security System
"""
        send_email(ADMIN_EMAIL, admin_subject, admin_body)

    def reset_login_attempts(self):
        self.login_attempts = 0
        self.is_locked = False
        self.lockout_until = None
        db.session.commit()

    def is_account_locked(self):
        if not self.is_locked:
            return False
        if self.lockout_until:
            # Convert lockout_until to UTC if it's naive
            if self.lockout_until.tzinfo is None:
                self.lockout_until = self.lockout_until.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > self.lockout_until:
                self.reset_login_attempts()
                return False
        return True 