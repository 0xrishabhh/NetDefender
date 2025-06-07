from flask_dance.contrib.google import make_google_blueprint
from flask_dance.consumer import oauth_authorized
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_login import current_user, login_user
from flask import flash, redirect, url_for, session
from models import db, User
import os
import requests
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'   # Allow scope changes

# Get Google OAuth credentials from environment variables
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

def init_oauth(app):
    # Configure Google OAuth
    google_bp = make_google_blueprint(
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scope=[
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
        ],
        storage=SQLAlchemyStorage(
            db.Model,
            db.session,
            user=current_user,
            user_required=False,
        ),
        redirect_to='index',
        reprompt_consent=True
    )
    
    app.register_blueprint(google_bp, url_prefix="/oauth")

    @oauth_authorized.connect_via(google_bp)
    def google_logged_in(blueprint, token):
        if not token:
            flash("Failed to log in with Google.", "error")
            return False

        resp = blueprint.session.get("/oauth2/v2/userinfo")  # Updated endpoint
        if not resp.ok:
            flash("Failed to fetch user info from Google.", "error")
            return False

        google_info = resp.json()
        google_user_id = google_info.get("id")
        google_email = google_info.get("email")

        if not google_email:
            flash("Failed to get email from Google.", "error")
            return False

        # Find this OAuth token in the database, or create it
        user = User.query.filter_by(email=google_email).first()
        if not user:
            # Create a new user
            user = User(
                email=google_email,
            )
            # Set a random password since we won't use it
            user.set_password(os.urandom(24).hex())
            db.session.add(user)
            db.session.commit()
            flash("Successfully signed up with Google.", "success")
        else:
            flash("Successfully logged in with Google.", "success")

        # Log in the user
        login_user(user)

        # Disable Flask-Dance's default behavior for saving the OAuth token
        return False 