from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import os
from cryptography.fernet import Fernet
from models import db, User
from utils import check_password_strength, send_email
from oauth import init_oauth
from dotenv import load_dotenv
from encryption import encrypt_file
from cryptography.hazmat.primitives import serialization
from decryption import handle_decryption_routes
from whatsapp_utils import send_whatsapp_otp
from port_scanner import scan_ports, get_system_info, save_scan_results
from scanner import VirusScanner, scan_file, scan_folder
from werkzeug.utils import secure_filename
import google.generativeai as genai
from haveIbeenpwned import is_password_pwned
from datetime import datetime, timezone

# Load environment variables
load_dotenv()

# Configure the Gemini API
API_KEY = os.environ.get('GEMINI_API_KEY', "ENTER YOUR KEY HERE")
genai.configure(api_key=API_KEY)

# Initialize the Gemini model
generation_config = {
    "temperature": 0.9,
    "top_p": 1,
    "top_k": 1,
    "max_output_tokens": 2048,
}

safety_settings = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
]

model = genai.GenerativeModel(
    model_name="gemini-1.5-pro",
    generation_config=generation_config,
    safety_settings=safety_settings
)

chat = model.start_chat(history=[])

def get_chatbot_response(user_input):
    """
    Sends user input to the Gemini API and returns the response.
    """
    try:
        response = model.generate_content(user_input)
        return response.text
    except Exception as e:
        return f"Error: {str(e)}"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['OAUTHLIB_INSECURE_TRANSPORT'] = True  # Only for development
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize OAuth
init_oauth(app)

# Initialize Virus Scanner
virus_scanner = VirusScanner()

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static/scans', exist_ok=True)

# Register decryption routes
handle_decryption_routes(app)

@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        return User.query.get(int(user_id))
    return None

# Create database tables
with app.app_context():
    db.create_all()

# Decryption function
def decrypt_file(file, key_file):
    key = key_file.read()
    fernet = Fernet(key)
    encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_' + file.filename)
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    return decrypted_file_path

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.args.get('next'):
        session['next'] = request.args.get('next')
    
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        verification_method = request.form.get('verification_method', 'whatsapp')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.is_account_locked():
            remaining_time = (user.lockout_until - datetime.now(timezone.utc)).total_seconds() / 60
            flash(f'Your account is locked due to too many failed attempts. Please try again in {int(remaining_time)} minutes.', 'warning')
            return redirect(url_for('login'))
        
        if user and user.check_password(password):
            # Generate and send OTP
            otp = user.generate_otp(method=verification_method)
            
            if verification_method == 'whatsapp':
                success, message = send_whatsapp_otp(user.phone_number, otp)
            elif verification_method == 'email':
                success = send_email(
                    user.email,
                    'Your Login OTP',
                    f'Your OTP for login is: {otp}. This OTP is valid for 5 minutes. Do not share this OTP with anyone.'
                )
                message = "Email sent" if success else "Failed to send email"
            else:
                success = False
                message = "Invalid verification method"
            
            if success:
                # Store user email and verification method in session
                session['pending_user_email'] = user.email
                session['verification_method'] = verification_method
                return redirect(url_for('verify_otp'))
            else:
                flash(f'Failed to send OTP via {verification_method}. Please try again.', 'error')
                return redirect(url_for('login'))
        
        if user:
            user.increment_login_attempts()
            remaining_attempts = 5 - user.login_attempts
            if remaining_attempts > 0:
                flash(f'Invalid password. {remaining_attempts} attempts remaining.', 'error')
            else:
                flash('Account locked for 15 minutes due to too many failed attempts.', 'error')
        else:
            flash('Email not found', 'error')
            
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_user_email' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        email = session.get('pending_user_email')
        otp = request.form.get('otp')
        verification_method = session.get('verification_method', 'whatsapp')
        
        user = User.query.filter_by(email=email).first()
        if user and user.verify_otp(otp):
            session.permanent = True
            login_user(user, remember=True)
            user.reset_login_attempts()
            session.pop('pending_user_email', None)
            session.pop('verification_method', None)
            flash('Logged in successfully!', 'success')
            
            next_url = session.pop('next', url_for('index'))
            if next_url and next_url.startswith('/'):
                return redirect(next_url)
            return redirect(url_for('index'))
        else:
            flash('Invalid or expired OTP', 'error')
            
    return render_template('verify_otp.html', 
                         email=session.get('pending_user_email'),
                         verification_method=session.get('verification_method', 'whatsapp'))

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email')
    verification_method = data.get('verification_method', 'whatsapp')
    
    if not email or email != session.get('pending_user_email'):
        return jsonify({'success': False, 'message': 'Invalid request'})
        
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
        
    otp = user.generate_otp(method=verification_method)
    
    if verification_method == 'whatsapp':
        success, message = send_whatsapp_otp(user.phone_number, otp)
    elif verification_method == 'email':
        success = send_email(
            user.email,
            'Your Login OTP',
            f'Your OTP for login is: {otp}. This OTP is valid for 5 minutes. Do not share this OTP with anyone.'
        )
        message = "Email sent" if success else "Failed to send email"
    else:
        success = False
        message = "Invalid verification method"
    
    if success:
        return jsonify({'success': True, 'message': f'OTP sent successfully via {verification_method}'})
    else:
        return jsonify({'success': False, 'message': message})

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        phone = request.form.get('phone')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))
            
        # Check if phone number already exists
        if User.query.filter_by(phone_number=phone).first():
            flash('Phone number already registered', 'error')
            return redirect(url_for('signup'))
        
        # Create new user
        user = User(email=email, phone_number=phone)
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating your account.', 'error')
            return redirect(url_for('signup'))
            
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/password_checker', methods=['GET', 'POST'])
@login_required
def password_checker():
    strength = None
    if request.method == 'POST':
        password = request.form['password']
        is_strong, message = check_password_strength(password)
        strength = message
    return render_template('password_checker.html', strength=strength)

@app.route('/encryption', methods=['GET', 'POST'])
@login_required
def encryption():
    if request.method == 'POST':
        file = request.files['file']
        algorithm = request.form['algorithm']
        encrypted_file_path, key = encrypt_file(file, algorithm, app.config['UPLOAD_FOLDER'])
        
        # Prepare response data
        response_data = {
            'key': key,
            'file_url': url_for('serve_uploads', filename=os.path.basename(encrypted_file_path))
        }
        
        return response_data  # Return JSON response
    
    return render_template('encryption.html')

@app.route('/awareness')
@login_required
def awareness():
    return render_template('awareness.html')

@app.route('/dos_donts')
@login_required
def dos_donts():
    return render_template('dos_donts.html')

@app.route('/attacks')
@login_required
def attacks():
    return render_template('attacks.html')

@app.route('/ppt')
@login_required
def ppt():
    return render_template('ppt.html')

@app.route('/phishing-protection')
@login_required
def phishing_protection():
    return render_template('phishing_protection.html')

@app.route('/uploads/<path:filename>')
def serve_uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/port_scanner')
def port_scanner():
    return render_template('port_scanner.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        target_host = data.get('target', 'localhost')
        scan_type = data.get('scan_type', 'common')
        
        # Determine port range based on scan type
        if scan_type == 'common':
            results = scan_ports(target_host, common_ports=True)
        elif scan_type == 'quick':
            results = scan_ports(target_host, port_range=(1, 1024))
        elif scan_type == 'all':
            results = scan_ports(target_host, port_range=(1, 65535))
        else:  # custom
            start_port = int(data.get('start_port', 1))
            end_port = int(data.get('end_port', 1024))
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                raise ValueError("Port numbers must be between 1 and 65535")
            if start_port > end_port:
                raise ValueError("Start port must be less than or equal to end port")
            results = scan_ports(target_host, port_range=(start_port, end_port))
        
        # Get system information
        system_info = get_system_info()
        
        # Save results
        filename = save_scan_results(results, system_info)
        
        return jsonify({
            'system_info': system_info,
            'scan_results': results,
            'filename': filename
        })
        
    except ValueError as e:
        return jsonify({
            'error': str(e),
            'system_info': get_system_info(),
            'scan_results': []
        }), 400
    except Exception as e:
        return jsonify({
            'error': str(e),
            'system_info': get_system_info(),
            'scan_results': []
        }), 500

@app.route('/scan-file', methods=['GET', 'POST'])
@login_required
def scan_file_route():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type', 'file')
        
        if scan_type == 'file':
            if 'file' not in request.files:
                flash('No file selected', 'error')
                return redirect(request.url)
                
            file = request.files['file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(request.url)
                
            if file:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                try:
                    # Scan the file
                    result = scan_file(file_path)
                    if result['success']:
                        if result['is_infected']:
                            flash(result['message'], 'danger')
                        else:
                            flash(result['message'], 'success')
                    else:
                        flash('Scan failed', 'error')
                    
                except Exception as e:
                    flash(f'Error during scan: {str(e)}', 'error')
                finally:
                    # Clean up the uploaded file
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        
        return redirect(url_for('scan_file_route'))
            
    scanner = VirusScanner()
    return render_template('scan_file.html', scanner_version=scanner.get_version())

@app.route('/scan-folder', methods=['POST'])
@login_required
def scan_folder_route():
    folder_path = request.form.get('folder_path')
    if not folder_path or not os.path.exists(folder_path):
        return jsonify({
            'success': False,
            'message': '❌ Invalid folder path'
        })
        
    try:
        result = scan_folder(folder_path)
        
        # Parse the output for threats
        threats = []
        for line in result['output'].split('\n'):
            if 'FOUND' in line:
                threats.append(line.strip())
        
        return jsonify({
            'success': True,
            'message': f'✅ Folder scan completed! {len(threats)} threat(s) found.',
            'threats': threats,
            'infected_files': len(threats)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'❌ Error during scan: {str(e)}'
        })

@app.route('/chatbot')
@login_required
def chatbot():
    return render_template('chatbot.html')

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.json
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'response': 'Please provide a message.'})
    
    try:
        response = get_chatbot_response(user_message)
        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'response': f'Error: {str(e)}'}), 500

@app.route('/haveibeenpwned', methods=['GET', 'POST'])
@login_required
def haveibeenpwned():
    """Handle the Have I Been Pwned password checker."""
    result = False
    is_pwned = False
    count = 0
    
    if request.method == 'POST':
        password = request.form.get('password')
        if password:
            is_pwned, count = is_password_pwned(password)
            result = True
    
    return render_template('haveIbeenpwned.html', 
                         result=result,
                         is_pwned=is_pwned, 
                         count=count)

if __name__ == '__main__':
    app.run(debug=True, port=8080)