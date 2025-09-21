from flask import Flask, render_template, jsonify, send_from_directory, redirect, g, session
from flask_cors import CORS
from flask import request, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
import json
import os
from datetime import datetime, timedelta
import filelock
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading

from dotenv import load_dotenv
from logger import ManpowerLogger, PerformanceMonitor
from validation import Validator, ContractValidator, UserValidator, PaymentValidator
from email_templates import EmailTemplateService
import secrets

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# CORS Configuration
cors_origin = os.getenv('CORS_ORIGIN', '*')
CORS(app, origins=[cors_origin] if cors_origin != '*' else None)

# Template context processor to make nonce available in all templates
@app.context_processor
def inject_nonce():
    if hasattr(g, 'nonce'):
        return {'nonce': g.nonce}
    return {}

# Security Configuration
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    app.logger.warning("No SECRET_KEY set! Using random secret key - sessions will be invalidated on restart")
    app.secret_key = secrets.token_hex(32)

# Session Configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(app.root_path, 'flask_session')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.getenv('SESSION_LIFETIME', 86400)))
app.config['SESSION_PERMANENT'] = os.getenv('SESSION_PERMANENT', 'True').lower() == 'true'
Session(app)

# File Upload Configuration
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # Default 16MB
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = set(os.getenv('ALLOWED_EXTENSIONS', 'txt,pdf,png,jpg,jpeg,gif,doc,docx').split(','))

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

# JSON file paths
JSON_DIR = os.path.join(app.root_path, 'data')
os.makedirs(JSON_DIR, exist_ok=True)

REGISTRATIONS_FILE = os.path.join(JSON_DIR, 'registrations.json')
CONTRACTS_FILE = os.path.join(JSON_DIR, 'contracts.json')
APPLICATIONS_FILE = os.path.join(JSON_DIR, 'applications.json')
MESSAGES_FILE = os.path.join(JSON_DIR, 'messages.json')
NOTIFICATIONS_FILE = os.path.join(JSON_DIR, 'notifications.json')
VERIFICATIONS_FILE = os.path.join(JSON_DIR, 'verifications.json')

# Initialize JSON files if they don't exist
for file_path in [REGISTRATIONS_FILE, CONTRACTS_FILE, APPLICATIONS_FILE, 
                  MESSAGES_FILE, NOTIFICATIONS_FILE, VERIFICATIONS_FILE]:
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump([], f)

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# Initialize logger and services
logger = ManpowerLogger(app)  # Logger now handles its own internals
email_service = EmailTemplateService()

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Rate limiting decorators for different endpoints
def rate_limit_auth():
    """5 attempts per minute for authentication endpoints"""
    return limiter.limit("5 per minute")

def rate_limit_api():
    """100 requests per minute for API endpoints"""
    return limiter.limit("100 per minute")

def rate_limit_uploads():
    """10 uploads per hour"""
    return limiter.limit("10 per hour")

def rate_limit_heavy():
    """20 requests per minute for resource-intensive endpoints"""
    return limiter.limit("20 per minute")

# Security headers
@app.before_request
def before_request():
    # Generate CSP nonce for scripts and store in g
    g.nonce = secrets.token_urlsafe(16)

@app.after_request
def add_security_headers(response):
    if request:
        # Get nonce from g
        nonce = getattr(g, 'nonce', '')
        
        # Set security headers
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        # Build CSP header - include nonce only when present and valid
        script_src_parts = ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com"]
        if nonce:
            # sanitize nonce to be safe for header (simple alnum check)
            safe_nonce = ''.join([c for c in nonce if c.isalnum() or c in ('-', '_')])
            if safe_nonce:
                script_src_parts.append(f"'nonce-{safe_nonce}'")

        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            f"script-src {' '.join(script_src_parts)}; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https: blob:; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "connect-src 'self' https://api.manpower-platform.com; "
            "frame-ancestors 'none'; "
            "media-src 'self' blob:; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'"
        )
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
            
    return response


# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def safe_read_json(file_path):
    """Safely read a JSON file with file locking"""
    lock_path = file_path + '.lock'
    lock = filelock.FileLock(lock_path)
    
    try:
        with lock.acquire(timeout=10):  # Wait up to 10 seconds
            if not os.path.exists(file_path):
                return []
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except filelock.Timeout:
        logger.log_error(
            Exception(f"Timeout waiting for file lock: {file_path}"),
            {'file': file_path}
        )
        raise Exception("System is busy, please try again")
    except json.JSONDecodeError as e:
        logger.log_error(
            e,
            {'file': file_path, 'operation': 'read'}
        )
        return []
    except Exception as e:
        logger.log_error(
            e,
            {'file': file_path, 'operation': 'read'}
        )
        raise

def create_notification(user_id, title, message, notification_type='info'):
    """Create a notification for a specific user"""
    try:
        notifications = safe_read_json(NOTIFICATIONS_FILE) or {}
        now = datetime.utcnow().isoformat() + 'Z'
        
        notification = {
            'id': str(uuid.uuid4()),
            'title': title,
            'message': message,
            'type': notification_type,
            'created_at': now,
            'read': False
        }

        # Initialize user's notifications list if it doesn't exist
        notifications.setdefault(user_id, []).append(notification)
        safe_write_json(NOTIFICATIONS_FILE, notifications)
        
        logger.log_user_action(
            'notification_created',
            user_id=user_id,
            details={'title': title, 'type': notification_type}
        )
        return True
    except Exception as e:
        logger.log_error(e, {
            'user_id': user_id,
            'title': title
        })
        return False

def create_notification_for_role(role, title, message, notification_type='info'):
    """Create a notification for all users with a specific role"""
    try:
        users = safe_read_json(REGISTRATIONS_FILE)
        success = True

        for user in users:
            if user.get('payload', {}).get('signupRole') == role:
                user_email = user.get('payload', {}).get('email')
                if user_email:
                    if not create_notification(user_email, title, message, notification_type):
                        success = False

        return success
    except Exception as e:
        logger.log_error(e, {
            'role': role,
            'title': title
        })
        return False

def notify_message_received(recipient_email, sender_email, preview):
    """Create a notification for a new message"""
    title = "New Message"
    message = f"New message from {sender_email}: {preview[:100]}..."
    return create_notification(recipient_email, title, message, 'message')

def safe_write_json(file_path, data):
    """Safely write to a JSON file with file locking"""
    lock_path = file_path + '.lock'
    lock = filelock.FileLock(lock_path)
    
    try:
        with lock.acquire(timeout=10):  # Wait up to 10 seconds
            # Create backup
            if os.path.exists(file_path):
                backup_path = file_path + '.bak'
                os.replace(file_path, backup_path)
            
            # Write new data
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            # Remove backup if write was successful
            backup_path = file_path + '.bak'
            if os.path.exists(backup_path):
                os.remove(backup_path)
                
    except filelock.Timeout:
        logger.log_error(
            Exception(f"Timeout waiting for file lock: {file_path}"),
            {'file': file_path}
        )
        raise Exception("System is busy, please try again")
    except Exception as e:
        # Restore from backup if write failed
        backup_path = file_path + '.bak'
        if os.path.exists(backup_path):
            os.replace(backup_path, file_path)
        
        logger.log_error(
            e,
            {'file': file_path, 'operation': 'write'}
        )
        raise

def send_email_async(app, msg):
    """Send email asynchronously"""
    import os
    from datetime import datetime

    with app.app_context():
        # Ensure directories for storing copies exist so we can inspect outgoing messages
        try:
            os.makedirs(os.path.join('logs', 'sent_emails'), exist_ok=True)
            os.makedirs(os.path.join('logs', 'failed_emails'), exist_ok=True)
        except Exception:
            # Non-fatal; continue and rely on logger
            pass

        timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

        def _safe_filename(part: str) -> str:
            # Replace unsafe characters for filenames
            return ''.join([c if c.isalnum() or c in ('-', '_') else '_' for c in (part or '')])[:120]

        to_addr = msg.get('To') or 'unknown'
        subject = msg.get('Subject') or 'no_subject'
        safe_to = _safe_filename(to_addr)
        safe_sub = _safe_filename(subject)

        try:
            server = smtplib.SMTP(app.config.get('MAIL_SERVER'), app.config.get('MAIL_PORT'))
            # Start TLS only if configured
            try:
                if app.config.get('MAIL_USE_TLS'):
                    server.starttls()
            except Exception:
                # Continue; starttls may fail on some environments
                pass

            username = app.config.get('MAIL_USERNAME')
            password = app.config.get('MAIL_PASSWORD')
            if username and password:
                try:
                    server.login(username, password)
                except Exception as e:
                    # Save failed login attempt with message dump
                    logfile = os.path.join('logs', 'failed_emails', f"{timestamp}_{safe_to}_{safe_sub}_login_failure.txt")
                    try:
                        with open(logfile, 'w', encoding='utf-8') as f:
                            f.write(f"LOGIN FAILURE: {str(e)}\n\n")
                            f.write(msg.as_string())
                    except Exception:
                        pass
                    logger.log_error(e, {'to': to_addr, 'subject': subject, 'stage': 'login'})
                    raise

            server.send_message(msg)
            server.quit()

            # Persist a copy of the sent email for troubleshooting & auditing
            try:
                sent_file = os.path.join('logs', 'sent_emails', f"{timestamp}_{safe_to}_{safe_sub}.eml")
                with open(sent_file, 'w', encoding='utf-8') as f:
                    f.write(msg.as_string())
            except Exception:
                # Non-fatal
                pass

            logger.log_api_request(
                'send_email',
                'POST',
                user_id=to_addr,
                ip_address=None
            )

        except Exception as e:
            # On any exception attempt to persist the failed message and exception details
            try:
                fail_file = os.path.join('logs', 'failed_emails', f"{timestamp}_{safe_to}_{safe_sub}.txt")
                with open(fail_file, 'w', encoding='utf-8') as f:
                    f.write(f"Exception: {repr(e)}\n\n")
                    try:
                        f.write(msg.as_string())
                    except Exception:
                        f.write('FAILED TO DUMP MESSAGE')
            except Exception:
                pass

            logger.log_error(
                e,
                {'to': to_addr, 'subject': subject}
            )
            # Re-raise so calling code can observe failure if needed
            raise

def send_email(to_email, subject, body, html_body=None):
    """Send email notification"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = to_email
    
    # Add text part
    text_part = MIMEText(body, 'plain')
    msg.attach(text_part)
    
    # Add HTML part if provided
    if html_body:
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
    
    # Send email in background thread
    thread = threading.Thread(target=send_email_async, args=(app, msg))
    thread.start()

@app.route('/')
def index():
    # Generate a nonce for inline scripts
    g.nonce = secrets.token_urlsafe(16)
    return render_template('index.html', nonce=g.nonce)

@app.route('/api/health')
def health():
    try:
        # Test different logging functions
        logger.log_error(Exception("Test error"), {"test": "context"})
        logger.log_security_event("test_event", "test@example.com", "127.0.0.1", {"test": "details"})
        logger.log_api_request("/api/test", "GET", "test@example.com", "127.0.0.1")
        logger.log_api_response("/api/test", 200, "test@example.com", 0.1)
        logger.log_user_action("test_action", "test@example.com", {"test": "details"})
        
        return jsonify({
            "status": "ok",
            "message": "Logging test completed successfully"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# Messaging Routes
@app.route('/messages')
def messages_page():
    # Get current user
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')
    return render_template('messaging.html', user=user)

@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    """Get all notifications for the current user"""
    try:
        user = _get_user_by_cookie()
        if not user:
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401

        email = user.get('email')
        notifications = safe_read_json(NOTIFICATIONS_FILE) or {}
        user_notifications = notifications.get(email, [])

        # Sort by created_at, newest first
        user_notifications.sort(key=lambda x: x['created_at'], reverse=True)

        return jsonify({
            'success': True,
            'notifications': user_notifications
        })

    except Exception as e:
        logger.log_error(e, {'email': email if 'email' in locals() else None})
        return jsonify({'success': False, 'message': 'Error fetching notifications'}), 500

@app.route('/api/notifications/read', methods=['POST'])
def mark_notifications_read():
    """Mark notifications as read"""
    try:
        user = _get_user_by_cookie()
        if not user:
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401

        email = user.get('email')
        data = request.get_json(force=True) or {}
        notification_ids = data.get('ids', [])

        notifications = safe_read_json(NOTIFICATIONS_FILE) or {}
        user_notifications = notifications.get(email, [])

        # Mark specified notifications as read
        if notification_ids:
            for note in user_notifications:
                if note['id'] in notification_ids:
                    note['read'] = True
        else:
            # If no IDs specified, mark all as read
            for note in user_notifications:
                note['read'] = True

        notifications[email] = user_notifications
        safe_write_json(NOTIFICATIONS_FILE, notifications)

        return jsonify({
            'success': True,
            'message': 'Notifications marked as read'
        })

    except Exception as e:
        logger.log_error(e, {'email': email if 'email' in locals() else None})
        return jsonify({'success': False, 'message': 'Error updating notifications'}), 500

@app.route('/api/messages/conversations', methods=['GET'])
def get_conversations():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    messages = safe_read_json(MESSAGES_FILE)
    user_email = user.get('email')

    # Get conversations where the user is a participant
    user_conversations = []
    for conv in messages.get('conversations', []):
        if user_email in conv.get('participants', []):
            # Remove sensitive info before sending to client
            conv_data = {
                'id': conv['id'],
                'participants': conv['participants'],
                'created_at': conv['created_at'],
                'updated_at': conv['updated_at'],
                'last_message': conv['last_message'],
                'unread_count': conv['unread_counts'].get(user_email, 0)
            }
            # Get the other participant's info
            other_participant = next(p for p in conv['participants'] if p != user_email)
            # In a real app, you'd fetch user profile info here
            conv_data['other_participant'] = {
                'email': other_participant,
                'name': other_participant  # In real app, get actual name
            }
            user_conversations.append(conv_data)

    return jsonify({
        'success': True,
        'conversations': sorted(user_conversations, key=lambda x: x['updated_at'], reverse=True)
    })

@app.route('/api/messages/<conversation_id>', methods=['GET'])
def get_messages(conversation_id):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    messages = safe_read_json(MESSAGES_FILE)
    user_email = user.get('email')

    # Find the conversation
    conversation = None
    for conv in messages.get('conversations', []):
        if conv['id'] == conversation_id and user_email in conv['participants']:
            conversation = conv
            break

    if not conversation:
        return jsonify({'success': False, 'message': 'Conversation not found'}), 404

    # Mark messages as read
    if conversation['unread_counts'].get(user_email, 0) > 0:
        conversation['unread_counts'][user_email] = 0
        safe_write_json(MESSAGES_FILE, messages)

    return jsonify({
        'success': True,
        'messages': conversation['messages']
    })

@app.route('/api/messages/send', methods=['POST'])
def send_message():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    data = request.get_json(force=True) or {}
    conversation_id = data.get('conversation_id')
    content = (data.get('content') or '').strip()
    recipient = data.get('recipient')  # Only needed for new conversations

    if not content:
        return jsonify({'success': False, 'message': 'Message content required'}), 400

    messages = safe_read_json(MESSAGES_FILE)
    user_email = user.get('email')
    now = datetime.utcnow().isoformat() + 'Z'

    # Create or find conversation
    conversation = None
    if conversation_id:
        for conv in messages.get('conversations', []):
            if conv['id'] == conversation_id and user_email in conv['participants']:
                conversation = conv
                break
        if not conversation:
            return jsonify({'success': False, 'message': 'Conversation not found'}), 404
    elif recipient:
        # Create new conversation
        conversation_id = f"conv_{str(uuid.uuid4())[:8]}"
        conversation = {
            'id': conversation_id,
            'participants': [user_email, recipient],
            'created_at': now,
            'updated_at': now,
            'last_message': content,
            'unread_counts': {
                user_email: 0,
                recipient: 1
            },
            'messages': []
        }
        messages.setdefault('conversations', []).append(conversation)
        # Update user_conversations mapping
        messages.setdefault('user_conversations', {})
        messages['user_conversations'].setdefault(user_email, []).append(conversation_id)
        messages['user_conversations'].setdefault(recipient, []).append(conversation_id)
    else:
        return jsonify({'success': False, 'message': 'Either conversation_id or recipient required'}), 400

    # Add message to conversation
    message = {
        'id': f"msg_{str(uuid.uuid4())[:8]}",
        'sender': user_email,
        'content': content,
        'timestamp': now,
        'read_by': [user_email],
        'attachments': [],
        'type': 'text'
    }
    conversation['messages'].append(message)

    # Update conversation metadata
    conversation['last_message'] = content
    conversation['updated_at'] = now
    # Update unread counts for other participants
    for participant in conversation['participants']:
        if participant != user_email:
            conversation['unread_counts'][participant] = conversation['unread_counts'].get(participant, 0) + 1

    # Save changes
    safe_write_json(MESSAGES_FILE, messages)

    return jsonify({
        'success': True,
        'message': message,
        'conversation': conversation
    })

@app.route('/api/messages/<conversation_id>/read', methods=['POST'])
def mark_messages_read(conversation_id):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    messages = safe_read_json(MESSAGES_FILE)
    user_email = user.get('email')

    # Find the conversation
    conversation = None
    for conv in messages.get('conversations', []):
        if conv['id'] == conversation_id and user_email in conv['participants']:
            conversation = conv
            break

    if not conversation:
        return jsonify({'success': False, 'message': 'Conversation not found'}), 404

    # Mark all messages as read for this user
    conversation['unread_counts'][user_email] = 0
    for message in conversation['messages']:
        if user_email not in message['read_by']:
            message['read_by'].append(user_email)

    # Save changes
    safe_write_json(MESSAGES_FILE, messages)

    return jsonify({'success': True})

@app.route('/api/messages/users', methods=['GET'])
def get_available_users():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    # Get all users from registrations
    users = safe_read_json(REGISTRATIONS_FILE)
    available_users = []
    
    for r in users:
        p = r.get('payload') if isinstance(r, dict) else None
        if p and p.get('email') and p.get('email') != user.get('email'):
            available_users.append({
                'email': p.get('email'),
                'name': p.get('contact') or p.get('company') or p.get('email'),
                'role': p.get('signupRole')
            })

    return jsonify({
        'success': True,
        'users': available_users
    })

@app.route('/api/contracts', methods=['GET', 'POST'])
def list_or_create_contracts():
    try:
        # Check authentication
        email = request.cookies.get('manpower_user')
        session_user = session.get('user_id')
        
        if not email or not session_user or email != session_user:
            logger.log_security_event(
                "unauthorized_access",
                user_id=email,
                ip_address=request.remote_addr,
                details={'cookie_user': email, 'session_user': session_user}
            )
            return jsonify({
                'success': False,
                'message': 'Not signed in'
            }), 401

        # Load contracts safely
        contracts = safe_read_json(CONTRACTS_FILE)
        
        # Filter based on user role
        role = session.get('user_role')
        if role == 'contractors':
            # Contractors see own contracts
            filtered = [c for c in contracts if c.get('owner') == email]
        elif role == 'agency':
            # Agency sees available and claimed contracts
            filtered = [c for c in contracts if c.get('status') == 'open' or c.get('claimed_by') == email]
        elif role == 'individual':
            # Individual sees available contracts
            filtered = [c for c in contracts if c.get('status') == 'open']
        else:
            filtered = contracts

        # GET: return the list of contracts (frontend expects an array)
        if request.method == 'GET':
            logger.log_api_request('/api/contracts', 'GET', user_id=email, ip_address=request.remote_addr)
            return jsonify(filtered)

        # POST: create a new contract
        logger.log_api_request('/api/contracts', 'POST', user_id=email, ip_address=request.remote_addr)

        data = request.get_json(silent=True) or {}
        title = (data.get('title') or '').strip()
        location = (data.get('location') or '').strip()
        workers = data.get('workers')
        skills = data.get('skills', [])
        budget = data.get('budget', 0)

        validation_errors = []
        if not title:
            validation_errors.append('Title is required')
        if not location:
            validation_errors.append('Location is required')
        if not workers or not isinstance(workers, int) or workers < 1:
            validation_errors.append('Valid number of workers is required')
        if not skills or not isinstance(skills, list):
            validation_errors.append('Skills list is required')
        if budget and not (isinstance(budget, (int, float)) and budget > 0):
            validation_errors.append('Budget must be a positive number')

        if validation_errors:
            return jsonify({
                'success': False,
                'message': 'Validation failed',
                'errors': validation_errors
            }), 400

        # Create contract record
        contract = {
            'title': title,
            'location': location,
            'workers': workers,
            'description': data.get('description') or '',
            'owner': email,
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'budget': budget,
            'skills': skills,
            'urgency': data.get('urgency', 'normal'),  # normal, urgent, critical
            'status': 'open',
            'escrow_amount': data.get('escrow_amount', 0),
            'escrow_status': 'pending',
            'attachments': data.get('attachments', []),
            'milestones': data.get('milestones', []),
            'applications': [],
            'matched_agencies': [],
            'reviews': [],
            'rating': 0
        }

        # Save contract
        contracts = safe_read_json(CONTRACTS_FILE)
        max_id = max([int(c.get('id', 0)) for c in contracts]) if contracts else 0
        contract['id'] = max_id + 1
        contracts.append(contract)
        safe_write_json(CONTRACTS_FILE, contracts)

        # Create notification for agencies
        create_notification_internal(
            'agency',  # Special recipient type for all agencies
            'New Contract Available',
            f'New contract posted: {title} in {location}',
            'info'
        )

        logger.log_user_action('contract_created', user_id=email, details={'contract_id': contract['id']})

        return jsonify({'success': True, 'contract': contract}), 201

    except Exception as e:
        logger.log_error(e, {'email': email if 'email' in locals() else None})
        return jsonify({'success': False, 'message': 'An error occurred while processing contracts'}), 500


@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/api/signup', methods=['POST'])
@limiter.limit("5 per minute")
def signup():
    try:
        payload = request.get_json(force=True)
        logger.log_api_request('/api/signup', 'POST',
                           user_id=payload.get('email'),
                           ip_address=request.remote_addr)
        
        # Normalize email and validate signup data using updated validator
        if payload.get('email'):
            payload['email'] = payload.get('email').strip().lower()

        is_valid, errors = UserValidator.validate_signup_data(payload)
        if not is_valid:
            logger.log_security_event(
                                  'validation_failed',
                                  user_id=payload.get('email'),
                                  ip_address=request.remote_addr,
                                  details={'errors': errors})
                                  
            # Filter out any jobTitle-related errors
            errors = [err for err in errors if 'jobTitle' not in err]
            
            if errors:  # Only return error if there are non-jobTitle validation failures
                return jsonify({
                    'success': False,
                    'errors': errors,
                    'message': 'Please correct the following issues:',
                    'validation_errors': {
                        'fields': [error.split(' is ')[0] for error in errors if ' is ' in error],
                        'general': [error for error in errors if ' is ' not in error]
                    }
                }), 400

        # Hash password
        pwd = payload.get('password')
        payload['password_hash'] = generate_password_hash(pwd)
        if 'password' in payload:
            del payload['password']

        # Enhance payload with additional fields
        payload.setdefault('rating', 0)
        payload.setdefault('reviews', [])
        payload.setdefault('verified', False)
        payload.setdefault('email_verified', False)
        payload.setdefault('verification_badges', [])
        payload.setdefault('profile_complete', False)
        payload.setdefault('specializations', [])
        payload.setdefault('portfolio', [])
        payload.setdefault('certifications', [])
        payload.setdefault('mfa_enabled', payload.get('enableMFA', False))
        payload.setdefault('mfa_secret', None)

        # Generate verification token and persist it (expires in 24h)
        verification_token = secrets.token_urlsafe(32)
        tokens_path = 'verification_tokens.json'
        tokens = {}
        if os.path.exists(tokens_path):
            try:
                with open(tokens_path, 'r', encoding='utf-8') as f:
                    tokens = json.load(f)
            except Exception:
                tokens = {}

        # Save token with expiry and associated email so verification can be validated
        try:
            tokens[verification_token] = {
                'email': payload.get('email'),
                'expires': (datetime.utcnow() + timedelta(hours=24)).isoformat() + 'Z'
            }
            with open(tokens_path, 'w', encoding='utf-8') as f:
                json.dump(tokens, f, indent=2)
        except Exception as e:
            logger.log_error(e, {'operation': 'save_verification_token', 'email': payload.get('email')})

        # Check if email already exists
        existing_users = safe_read_json(REGISTRATIONS_FILE)
        if any(r.get('payload', {}).get('email') == payload.get('email') for r in existing_users):
            logger.log_security_event(
                'duplicate_email',
                user_id=payload.get('email'),
                ip_address=request.remote_addr
            )
            return jsonify({
                'success': False,
                'message': 'An account with this email already exists'
            }), 409
        
        # Create new registration record
        rec = {
            'received_at': datetime.utcnow().isoformat() + 'Z',
            'payload': payload,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'verified': False
        }
        
        # Add to registrations
        existing_users.append(rec)
        safe_write_json(REGISTRATIONS_FILE, existing_users)

        # Send verification email
        send_verification_email(payload.get('email'), payload.get('contact'), verification_token)

        logger.log_user_action(
            'registration_success',
            user_id=payload.get('email'),
            details={'role': payload.get('signupRole')}
        )

        return jsonify({
            'success': True,
            'message': 'Registration successful! Please check your email to verify your account.'
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.svg')



@app.route('/api/signin', methods=['POST'])
@limiter.limit("5 per minute")
def signin():
    try:
        payload = request.get_json(force=True) or {}
        email = (payload.get('email') or '').strip().lower()
        pwd = (payload.get('password') or '')
        print(f"[DEBUG] Received signin: email='{email}', password='{pwd}'")
        
        # Input validation
        if not email:
            return jsonify({
                'success': False, 
                'message': 'Email required'
            }), 400

        logger.log_api_request(
            '/api/signin',
            'POST',
            user_id=email,
            ip_address=request.remote_addr
        )

        # Load and validate user
        users = safe_read_json(REGISTRATIONS_FILE)
        found = None
        
        for r in users:
            p = r.get('payload') if isinstance(r, dict) else None
            if p and p.get('email') and p.get('email').strip().lower() == email:
                found = p
                break

        if not found:
            logger.log_security_event(
                'invalid_email',
                user_id=email,
                ip_address=request.remote_addr
            )
            return jsonify({
                'success': False,
                'message': 'No account with that email'
            }), 401

        # Verify password
        # pwd already set above for debug
        stored_hash = found.get('password_hash')

        if stored_hash:
            if not pwd or not check_password_hash(stored_hash, pwd):
                logger.log_security_event(
                    'invalid_password',
                    user_id=email,
                    ip_address=request.remote_addr
                )
                return jsonify({
                    'success': False,
                    'message': 'Invalid credentials'
                }), 401
        else:
            # Legacy account without password
            logger.log_security_event(
                'legacy_signin',
                user_id=email,
                ip_address=request.remote_addr
            )
            
            # Force password setup for legacy accounts
            return jsonify({
                'success': False,
                'message': 'Please set up a password for your account',
                'code': 'PASSWORD_REQUIRED'
            }), 403

        # Verify email is confirmed
        if not found.get('email_verified'):
            return jsonify({
                'success': False,
                'message': 'Please verify your email address',
                'code': 'EMAIL_VERIFICATION_REQUIRED'
            }), 403

        # Create session
        session.permanent = True
        session['user_id'] = email
        session['user_role'] = found.get('signupRole')
        session['login_time'] = datetime.utcnow().isoformat()
        session['ip_address'] = request.remote_addr

        # Set secure cookie for additional validation
        resp = make_response(jsonify({
            'success': True,
            'redirect': '/dashboard',
            'user': {
                'email': email,
                'role': found.get('signupRole'),
                'name': found.get('contact') or found.get('company')
            }
        }))
        
        # Set secure, HTTP-only cookie with SameSite protection
        resp.set_cookie(
            'manpower_user',
            email,
            httponly=True,
            secure=not app.debug,  # True in production
            samesite='Lax',
            max_age=int(os.getenv('SESSION_LIFETIME', 86400))
        )

        logger.log_user_action('login_success',
            user_id=email,
            details={'role': found.get('signupRole')})

        return resp

    except Exception as e:
        logger.log_error(
            e,
            {'email': email if 'email' in locals() else None}
        )
        return jsonify({
            'success': False,
            'message': 'An error occurred during sign in'
        }), 500


# (Old simple dashboard route removed; role-aware dashboard is defined later)


@app.route('/api/profile')
def profile():
    try:
        # Check both cookie and session for authentication
        email = request.cookies.get('manpower_user')
        session_user = session.get('user_id')
        
        if not email or not session_user or email != session_user:
            logger.log_security_event(
                'unauthorized_access',
                ip_address=request.remote_addr,
                details={'cookie_user': email, 'session_user': session_user}
            )
            return jsonify({
                'success': False,
                'message': 'Not signed in'
            }), 401

        # Load user data safely
        users = safe_read_json(REGISTRATIONS_FILE)
        found = None
        
        for r in users:
            p = r.get('payload') if isinstance(r, dict) else None
            if p and p.get('email') and p.get('email').strip().lower() == email.strip().lower():
                found = p
                break

        if not found:
            logger.log_security_event(
                'profile_not_found',
                user_id=email,
                ip_address=request.remote_addr
            )
            return jsonify({
                'success': False,
                'message': 'Account not found'
            }), 404

        # Verify session data matches stored data
        if found.get('signupRole') != session.get('user_role'):
            logger.log_security_event(
                'role_mismatch',
                user_id=email,
                ip_address=request.remote_addr
            )
            return jsonify({
                'success': False,
                'message': 'Session invalid'
            }), 401

        # Remove sensitive data before sending
        profile_data = {
            'email': found.get('email'),
            'company': found.get('company'),
            'contact': found.get('contact'),
            'role': found.get('signupRole') or found.get('role'),
            'verified': found.get('verified', False),
            'email_verified': found.get('email_verified', False),
            'verification_badges': found.get('verification_badges', []),
            'rating': found.get('rating', 0),
            'reviews': found.get('reviews', []),
            'profile_complete': found.get('profile_complete', False),
            'specializations': found.get('specializations', []),
            'portfolio': found.get('portfolio', []),
            'certifications': found.get('certifications', []),
            'mfa_enabled': found.get('mfa_enabled', False)
        }
        
        logger.log_user_action(
            'profile_viewed',
            user_id=email
        )

        return jsonify({
            'success': True,
            'profile': profile_data
        })

    except Exception as e:
        logger.log_error(
            e,
            {'email': email if 'email' in locals() else None}
        )
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching profile'
        }), 500


def _get_user_by_cookie():
    email = request.cookies.get('manpower_user')
    if not email:
        return None
    path = REGISTRATIONS_FILE
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                users = json.load(f)
            for r in users:
                p = r.get('payload') if isinstance(r, dict) else None
                if p and p.get('email') and p.get('email').strip().lower() == email.strip().lower():
                    return p
        except Exception:
            return None
    return None


@limiter.exempt
@app.route('/dashboard')
def dashboard():
    """Main dashboard router that redirects to appropriate role-based dashboard"""
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')

    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)

    if role == 'contractors':
        return redirect('/dashboard/contractors')
    elif role == 'agency':
        return redirect('/dashboard/agency')
    elif role == 'admin':
        return redirect('/dashboard/admin')
    else:
        return redirect('/dashboard/individual')


@limiter.exempt
@app.route('/dashboard/contractors')
def dashboard_contractors():
    """Contractors dashboard - for businesses looking to hire workers"""
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')

    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)
    if role != 'contractors':
        return redirect('/dashboard')

    return render_template('dashboard_contractors.html', user=user)


@limiter.exempt
@app.route('/dashboard/agency')
def dashboard_agency():
    """Agency dashboard - for staffing agencies"""
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')

    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)
    if role != 'agency':
        return redirect('/dashboard')

    return render_template('dashboard_agency.html', user=user)


@limiter.exempt
@app.route('/dashboard/individual')
def dashboard_individual():
    """Individual dashboard - for job seekers"""
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')

    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)
    if role not in ['individual', 'job_seeker', None]:
        return redirect('/dashboard')

    return render_template('dashboard_individual.html', user=user)


@limiter.exempt
@app.route('/dashboard/admin')
def dashboard_admin():
    """Admin dashboard - for platform administrators"""
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')

    # Check if user is admin
    if user.get('email') != 'admin@local':
        return redirect('/dashboard')

    return render_template('dashboard_admin.html', user=user)


@app.route('/api/contracts/<int:contract_id>/claim', methods=['POST'])
def claim_contract(contract_id):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    path = 'contracts.json'
    if not os.path.exists(path):
        return jsonify({'success': False, 'message': 'No contracts'}), 404
    try:
        with open(path, 'r', encoding='utf-8') as f:
            contracts = json.load(f)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to read contracts'}), 500
    found = None
    for c in contracts:
        if int(c.get('id', 0)) == contract_id:
            found = c
            break
    if not found:
        return jsonify({'success': False, 'message': 'Contract not found'}), 404
    if found.get('claimed_by'):
        return jsonify({'success': False, 'message': 'Already claimed'}), 400
    found['claimed_by'] = user.get('email')
    found['status'] = 'claimed'
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(contracts, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to save'}), 500
    return jsonify({'success': True, 'contract': found})


@app.route('/api/contracts/<int:contract_id>/approve-claim', methods=['POST'])
def approve_claim(contract_id):
    # Admin action: approve a claim so contract is active
    # For demo, allow any logged-in user whose email is 'admin@local' or the owner
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    path = 'contracts.json'
    if not os.path.exists(path):
        return jsonify({'success': False, 'message': 'No contracts'}), 404
    try:
        with open(path, 'r', encoding='utf-8') as f:
            contracts = json.load(f)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to read contracts'}), 500
    found = None
    for c in contracts:
        if int(c.get('id', 0)) == contract_id:
            found = c
            break
    if not found:
        return jsonify({'success': False, 'message': 'Contract not found'}), 404
    # simple admin check: allow if current user is the contract owner or admin
    owner = found.get('owner')
    if user.get('email') != owner and user.get('email') != 'admin@local':
        return jsonify({'success': False, 'message': 'Not authorized'}), 403
    found['status'] = 'approved'
    found['approved_at'] = datetime.utcnow().isoformat() + 'Z'
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(contracts, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to save'}), 500
    return jsonify({'success': True, 'contract': found})


@app.route('/api/contracts/<int:contract_id>/apply', methods=['POST'])
def apply_contract(contract_id):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    # Only individual recruits / job seekers are allowed to apply from marketplace
    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)
    if not role or str(role).lower() not in ('individual', 'job seeker', 'job_seeker'):
        return jsonify({'success': False, 'message': 'Only individual recruits may apply'}), 403
    data = request.get_json(force=True) or {}
    resume = data.get('resume') or ''
    apps_path = 'applications.json'
    apps = []
    if os.path.exists(apps_path):
        try:
            with open(apps_path, 'r', encoding='utf-8') as f:
                apps = json.load(f)
        except Exception:
            apps = []
    new_id = (max([int(a.get('id',0)) for a in apps]) + 1) if apps else 1
    apprec = {
        'id': new_id,
        'contract_id': contract_id,
        'applicant': user.get('email'),
        'resume': resume,
        'status': 'submitted',
        'applied_at': datetime.utcnow().isoformat() + 'Z',
        'bid_amount': data.get('bid_amount', 0),
        'proposal': data.get('proposal', ''),
        'estimated_duration': data.get('estimated_duration', ''),
        'worker_profiles': data.get('worker_profiles', []),
        'attachments': data.get('attachments', []),
        'negotiations': [],
        'reviews': [],
        'rating': 0
    }
    apps.append(apprec)
    try:
        with open(apps_path, 'w', encoding='utf-8') as f:
            json.dump(apps, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to save application'}), 500
    return jsonify({'success': True, 'application': apprec}), 201



@app.route('/api/messages')
def api_messages():
    """Get all messages for the current user"""
    try:
        # Verify authentication
        user = _get_user_by_cookie()
        if not user:
            logger.log_security_event(
                'unauthorized_access',
                ip_address=request.remote_addr,
                details={'endpoint': '/api/messages'}
            )
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401

        email = user.get('email')
        messages = safe_read_json(MESSAGES_FILE)
        
        # Get all conversations for this user
        user_conversations = []
        for conv in messages.get('conversations', []):
            if email in conv.get('participants', []):
                # Clean conversation data for client
                conv_data = {
                    'id': conv['id'],
                    'participants': conv['participants'],
                    'created_at': conv['created_at'],
                    'updated_at': conv['updated_at'],
                    'last_message': conv['last_message'],
                    'messages': conv['messages'],
                    'unread_count': conv['unread_counts'].get(email, 0)
                }
                user_conversations.append(conv_data)

        # Sort by most recent first
        user_conversations.sort(key=lambda x: x['updated_at'], reverse=True)

        logger.log_api_request(
            'get_messages',
            'GET',
            user_id=email,
            ip_address=request.remote_addr
        )

        return jsonify({
            'success': True,
            'conversations': user_conversations
        })

    except Exception as e:
        logger.log_error(e, {'email': email if 'email' in locals() else None})
        return jsonify({
            'success': False,
            'message': 'Error retrieving messages'
        }), 500

@app.route('/api/messages/send', methods=['POST'])
def api_messages_send():
    """Send a new message"""
    try:
        # Verify authentication
        user = _get_user_by_cookie()
        if not user:
            logger.log_security_event(
                'unauthorized_access',
                ip_address=request.remote_addr,
                details={'endpoint': '/api/messages/send'}
            )
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401

        data = request.get_json(force=True) or {}
        to_email = (data.get('to') or '').strip().lower()
        message_text = (data.get('message') or '').strip()
        conversation_id = data.get('conversation_id')

        # Validate input
        if not to_email or not message_text:
            return jsonify({
                'success': False,
                'message': 'Recipient and message text are required'
            }), 400

        from_email = user.get('email')
        
        # Check if recipient exists
        users = safe_read_json(REGISTRATIONS_FILE)
        recipient_exists = False
        for r in users:
            p = r.get('payload', {})
            if p.get('email') == to_email:
                recipient_exists = True
                break

        if not recipient_exists:
            return jsonify({
                'success': False,
                'message': 'Recipient not found'
            }), 404

        messages = safe_read_json(MESSAGES_FILE)
        now = datetime.utcnow().isoformat() + 'Z'

        # Find or create conversation
        if conversation_id:
            conversation = None
            for conv in messages.get('conversations', []):
                if conv['id'] == conversation_id:
                    if from_email not in conv['participants']:
                        return jsonify({
                            'success': False,
                            'message': 'Not authorized for this conversation'
                        }), 403
                    conversation = conv
                    break
        else:
            # Create new conversation
            conversation_id = str(uuid.uuid4())
            conversation = {
                'id': conversation_id,
                'participants': [from_email, to_email],
                'created_at': now,
                'updated_at': now,
                'last_message': message_text,
                'messages': [],
                'unread_counts': {
                    from_email: 0,
                    to_email: 1
                }
            }
            messages.setdefault('conversations', []).append(conversation)

        if not conversation:
            return jsonify({
                'success': False,
                'message': 'Conversation not found'
            }), 404

        # Add message
        message = {
            'id': str(uuid.uuid4()),
            'from': from_email,
            'content': message_text,
            'timestamp': now,
            'read_by': [from_email]
        }
        
        conversation['messages'].append(message)
        conversation['last_message'] = message_text
        conversation['updated_at'] = now
        conversation['unread_counts'][to_email] = conversation['unread_counts'].get(to_email, 0) + 1

        # Save changes
        safe_write_json(MESSAGES_FILE, messages)

        logger.log_api_request(
            'send_message',
            'POST',
            user_id=from_email,
            ip_address=request.remote_addr
        )

        return jsonify({
            'success': True,
            'message': message,
            'conversation': conversation
        })

    except Exception as e:
        logger.log_error(e, {
            'from_email': from_email if 'from_email' in locals() else None,
            'to_email': to_email if 'to_email' in locals() else None
        })
        return jsonify({
            'success': False,
            'message': 'Error sending message'
        }), 500


@app.route('/api/applications/<int:app_id>/decide', methods=['POST'])
def decide_application(app_id):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    apps_path = 'applications.json'
    if not os.path.exists(apps_path):
        return jsonify({'success': False, 'message': 'No applications'}), 404
    try:
        with open(apps_path, 'r', encoding='utf-8') as f:
            apps = json.load(f)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to read applications'}), 500
    found = None
    for a in apps:
        if int(a.get('id',0)) == app_id:
            found = a
            break
    if not found:
        return jsonify({'success': False, 'message': 'Application not found'}), 404
    data = request.get_json(force=True) or {}
    decision = data.get('decision')  # 'approve' or 'reject'
    if decision not in ('approve','reject'):
        return jsonify({'success': False, 'message': 'Invalid decision'}), 400
    # authorization: only agency who claimed the contract or admin can decide
    contract_id = found.get('contract_id')
    contract = None
    cpath = 'contracts.json'
    if os.path.exists(cpath):
        try:
            with open(cpath,'r',encoding='utf-8') as f:
                cs = json.load(f)
            for c in cs:
                if int(c.get('id',0)) == int(contract_id):
                    contract = c; break
        except Exception:
            contract = None
    if not contract:
        return jsonify({'success': False, 'message': 'Contract not found'}), 404
    if contract.get('claimed_by') and user.get('email') != contract.get('claimed_by') and user.get('email') != 'admin@local':
        return jsonify({'success': False, 'message': 'Not authorized to decide'}), 403
    if decision == 'approve':
        found['status'] = 'approved'
        # mark applicant as certified in registrations.json
        email = found.get('applicant')
        rpath = REGISTRATIONS_FILE
        if os.path.exists(rpath):
            try:
                with open(rpath,'r',encoding='utf-8') as f:
                    regs = json.load(f)
                for r in regs:
                    p = r.get('payload') if isinstance(r, dict) else None
                    if p and p.get('email') and p.get('email').strip().lower() == email.strip().lower():
                        p['certified'] = True
                        break
                with open(rpath,'w',encoding='utf-8') as f:
                    json.dump(regs,f,indent=2)
            except Exception:
                pass
    else:
        found['status'] = 'rejected'
    try:
        with open(apps_path,'w',encoding='utf-8') as f:
            json.dump(apps,f,indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to save application decision'}), 500
    return jsonify({'success': True, 'application': found})


@app.route('/api/signout', methods=['POST'])
def signout():
    # Clear session data
    session.clear()
    
    # Clear the authentication cookie with proper security settings
    resp = make_response(jsonify({'success': True}))
    resp.set_cookie(
        'manpower_user',
        '',
        expires=0,
        httponly=True,
        secure=not app.debug,
        samesite='Lax',
        path='/'
    )
    return resp


@app.route('/api/reset-password', methods=['POST'])
@limiter.limit("3 per hour")
def request_password_reset():
    data = request.get_json(force=True) or {}
    email = data.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400
        
    # Generate reset token
    reset_token = str(uuid.uuid4())

    # Persist reset tokens to a file
    reset_tokens_path = 'reset_tokens.json'
    if os.path.exists(reset_tokens_path):
        try:
            with open(reset_tokens_path, 'r', encoding='utf-8') as f:
                reset_tokens = json.load(f)
        except Exception:
            reset_tokens = {}
    else:
        reset_tokens = {}

    reset_tokens[reset_token] = {
        'email': email,
        'expires': (datetime.utcnow() + timedelta(hours=1)).isoformat() + 'Z'
    }
    try:
        with open(reset_tokens_path, 'w', encoding='utf-8') as f:
            json.dump(reset_tokens, f, indent=2)
    except Exception as e:
        logger.log_error(e, {'operation': 'save_reset_token', 'email': email})

    # Send reset email
    reset_link = f"http://localhost:5000/reset-password?token={reset_token}"
    send_email(
        email,
        'Reset Your Password - Manpower',
        f'Click the following link to reset your password: {reset_link}',
        f'<h2>Reset Your Password</h2><p>Click the button below to reset your password:</p><p><a href="{reset_link}" class="btn">Reset Password</a></p>'
    )

    return jsonify({'success': True, 'message': 'Password reset instructions sent'})

@app.route('/reset-password')
def reset_password_page():
    token = request.args.get('token')
    if token:
        return render_template('reset_password.html', token=token)
    return render_template('request_reset.html')

@app.route('/api/set-password', methods=['POST'])
def set_password():

    # Require logged-in demo cookie or reset token
    email = request.cookies.get('manpower_user')
    reset_token = request.args.get('token')

    if not email and not reset_token:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    # If using reset token, verify it
    if reset_token:
        # Load and validate reset token
        reset_tokens_path = 'reset_tokens.json'
        if not os.path.exists(reset_tokens_path):
            return jsonify({'success': False, 'message': 'Invalid or expired reset token'}), 400
        try:
            with open(reset_tokens_path, 'r', encoding='utf-8') as f:
                reset_tokens = json.load(f)
        except Exception:
            return jsonify({'success': False, 'message': 'Invalid or expired reset token'}), 400
        token_data = reset_tokens.get(reset_token)
        if not token_data:
            return jsonify({'success': False, 'message': 'Invalid or expired reset token'}), 400
        expires = datetime.fromisoformat(token_data['expires'].replace('Z', '+00:00'))
        now = datetime.utcnow().replace(tzinfo=expires.tzinfo)
        if now > expires:
            return jsonify({'success': False, 'message': 'Reset token has expired'}), 400
        email = token_data.get('email')
        # Remove token after use
        del reset_tokens[reset_token]
        with open(reset_tokens_path, 'w', encoding='utf-8') as f:
            json.dump(reset_tokens, f, indent=2)

    data = request.get_json(force=True) or {}
    pwd = data.get('password')
    if not pwd or len(pwd) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    path = REGISTRATIONS_FILE
    if not os.path.exists(path):
        return jsonify({'success': False, 'message': 'No registrations found'}), 400

    try:
        with open(path, 'r', encoding='utf-8') as f:
            users = json.load(f)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to read registrations'}), 500

    updated = False
    for r in users:
        p = r.get('payload') if isinstance(r, dict) else None
        if p and p.get('email') and p.get('email').strip().lower() == email.strip().lower():
            p['password_hash'] = generate_password_hash(pwd)
            # Remove any plaintext password if present
            p.pop('password', None)
            updated = True
            break

    if not updated:
        return jsonify({'success': False, 'message': 'Account not found'}), 404

    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to save password'}), 500

    return jsonify({'success': True, 'message': 'Password updated'})


@app.route('/api/users/<email>/rate', methods=['POST'])
def rate_user(email):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    data = request.get_json(force=True) or {}
    rating = data.get('rating', 0)
    review = data.get('review', '')

    if not (1 <= rating <= 5):
        return jsonify({'success': False, 'message': 'Rating must be between 1-5'}), 400

    # Find target user
    path = REGISTRATIONS_FILE
    if not os.path.exists(path):
        return jsonify({'success': False, 'message': 'Users not found'}), 404

    try:
        with open(path, 'r', encoding='utf-8') as f:
            users = json.load(f)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to read users'}), 500

    target_user = None
    for r in users:
        p = r.get('payload') if isinstance(r, dict) else None
        if p and p.get('email') == email:
            target_user = p
            break

    if not target_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Add review
    review_obj = {
        'from': user.get('email'),
        'rating': rating,
        'review': review,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    target_user['reviews'].append(review_obj)

    # Update average rating
    ratings = [r['rating'] for r in target_user['reviews']]
    target_user['rating'] = sum(ratings) / len(ratings) if ratings else 0

    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to save review'}), 500

    return jsonify({'success': True, 'message': 'Review added'})


@app.route('/api/contracts/<int:contract_id>/escrow', methods=['POST'])
def update_escrow(contract_id):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    data = request.get_json(force=True) or {}
    action = data.get('action')  # 'deposit', 'release', 'dispute'

    path = 'contracts.json'
    if not os.path.exists(path):
        return jsonify({'success': False, 'message': 'Contracts not found'}), 404

    try:
        with open(path, 'r', encoding='utf-8') as f:
            contracts = json.load(f)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to read contracts'}), 500

    contract = None
    for c in contracts:
        if int(c.get('id', 0)) == contract_id:
            contract = c
            break

    if not contract:
        return jsonify({'success': False, 'message': 'Contract not found'}), 404

    if action == 'deposit':
        contract['escrow_status'] = 'funded'
        contract['escrow_amount'] = data.get('amount', contract.get('escrow_amount', 0))
    elif action == 'release':
        contract['escrow_status'] = 'released'
    elif action == 'dispute':
        contract['escrow_status'] = 'disputed'

    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(contracts, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to update escrow'}), 500

    return jsonify({'success': True, 'contract': contract})


@app.route('/api/users/<email>/verify', methods=['POST'])
def verify_user(email):
    user = _get_user_by_cookie()
    if not user or user.get('email') != 'admin@local':  # Simple admin check
        return jsonify({'success': False, 'message': 'Not authorized'}), 403

    data = request.get_json(force=True) or {}
    badge = data.get('badge', '')

    path = REGISTRATIONS_FILE
    if not os.path.exists(path):
        return jsonify({'success': False, 'message': 'Users not found'}), 404

    try:
        with open(path, 'r', encoding='utf-8') as f:
            users = json.load(f)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to read users'}), 500

    target_user = None
    for r in users:
        p = r.get('payload') if isinstance(r, dict) else None
        if p and p.get('email') == email:
            target_user = p
            break

    if not target_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if badge not in target_user['verification_badges']:
        target_user['verification_badges'].append(badge)
        target_user['verified'] = True

    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to save verification'}), 500

    return jsonify({'success': True, 'message': 'User verified'})


@app.route('/api/analytics')
def get_analytics():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({}), 401

    # Simple analytics data
    analytics = {
        'total_contracts': 0,
        'active_contracts': 0,
        'completed_contracts': 0,
        'total_earnings': 0,
        'average_rating': user.get('rating', 0),
        'total_reviews': len(user.get('reviews', []))
    }

    # Read contracts
    path = 'contracts.json'
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                contracts = json.load(f)
            analytics['total_contracts'] = len(contracts)
            analytics['active_contracts'] = len([c for c in contracts if c.get('status') == 'active'])
            analytics['completed_contracts'] = len([c for c in contracts if c.get('status') == 'completed'])
        except Exception:
            pass

    return jsonify(analytics)
@app.route('/api/verify-mfa', methods=['POST'])
def verify_mfa():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    data = request.get_json(force=True) or {}
    code = data.get('code', '')

    # Simple MFA simulation: accept any 6-digit code for demo
    if len(code) == 6 and code.isdigit():
        return jsonify({'success': True, 'message': 'MFA verified'})
    else:
        return jsonify({'success': False, 'message': 'Invalid MFA code'}), 400


@app.route('/preview/dashboard/contractors')
def preview_contractors():
    return render_template('dashboard_contractors.html')


@app.route('/preview/dashboard/agency')
def preview_agency():
    return render_template('dashboard_agency.html')


@app.route('/preview/dashboard/individual')
def preview_individual():
    return render_template('dashboard_individual.html')


# --- Manager / Marketplace endpoints ---
def _load_json(name):
    start_time = datetime.utcnow()
    path = name
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            duration = (datetime.utcnow() - start_time).total_seconds()
            PerformanceMonitor.log_slow_query(
                'read',
                duration,
                {'file': name, 'size': len(str(data))}
            )
            return data
    except Exception as e:
        logger.log_error(e, {'operation': 'read', 'file': name})
        return []


def _save_json(name, data):
    start_time = datetime.utcnow()
    try:
        with open(name, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            duration = (datetime.utcnow() - start_time).total_seconds()
            PerformanceMonitor.log_slow_query(
                'write',
                duration,
                {'file': name, 'size': len(str(data))}
            )
    except Exception as e:
        logger.log_error(e, 
                        {'operation': 'write', 'file': name})


@app.route('/api/marketplace')
def api_marketplace():
    regs = _load_json(REGISTRATIONS_FILE)
    apps = _load_json('applications.json') or []
    client_counts = {}
    for a in apps:
        email = a.get('applicant')
        if not email: continue
        client_counts[email] = client_counts.get(email, 0) + 1

    # helper to coerce numeric-like values to int safely
    def _to_int(val):
        try:
            if val is None:
                return 0
            return int(val)
        except Exception:
            try:
                return int(float(val))
            except Exception:
                return 0

    recruits = []
    for r in regs:
        p = r.get('payload') if isinstance(r, dict) else r
        role = (p.get('signupRole') if isinstance(p, dict) else None) or (p.get('role') if isinstance(p, dict) else None)
        role = (role or '')
        if role and str(role).lower() not in ('individual','job seeker','job_seeker'):
            continue
        email = p.get('email')
        exp = _to_int(p.get('experience', 0))
        loyalty = _to_int(p.get('loyalty', 0))
        clients = _to_int(client_counts.get(email, 0))
        recruits.append({
            'email': email,
            'name': p.get('company') or p.get('contact') or email,
            'experience_years': exp,
            'loyalty_score': loyalty,
            'clients_count': clients,
            'portfolio': p.get('portfolio', []),
            'rating': _to_int(p.get('rating', 0))
        })

    recruits.sort(key=lambda x: (x.get('experience_years',0)*2 + x.get('clients_count',0) + x.get('loyalty_score',0)), reverse=True)
    # determine current user permissions
    current = _get_user_by_cookie()
    role = (current.get('signupRole') if current else None) or (current.get('role') if current else None)
    can_apply = False
    can_message = False
    can_review = False
    if role:
        r = str(role).lower()
        if r in ('individual','job seeker','job_seeker'):
            can_apply = True
        if r in ('agency',):
            can_message = True
        if r in ('contractors'):
            can_review = True

    return jsonify({'recruits': recruits, 'permissions': {'can_apply': can_apply, 'can_message': can_message, 'can_review': can_review}})



@app.route('/api/marketplace/<email>/message', methods=['POST'])
def api_marketplace_message(email):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)
    if not role or str(role).lower() != 'agency':
        return jsonify({'success': False, 'message': 'Only agencies can message recruits'}), 403

    data = request.get_json(force=True) or {}
    text = (data.get('message') or '').strip()
    if not text:
        return jsonify({'success': False, 'message': 'Message required'}), 400

    msg = {
        'to': email,
        'from': user.get('email'),
        'message': text,
        'sent_at': datetime.utcnow().isoformat() + 'Z'
    }
    path = 'messages.json'
    existing = []
    if os.path.exists(path):
        try:
            with open(path,'r',encoding='utf-8') as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.append(msg)
    try:
        with open(path,'w',encoding='utf-8') as f:
            json.dump(existing,f,indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to save message'}), 500

    return jsonify({'success': True, 'message': 'Message sent'})


@app.route('/api/orders')
def api_orders():
    contracts = _load_json('contracts.json') or []
    applications = _load_json('applications.json') or []
    for c in contracts:
        cid = c.get('id')
        c['applications'] = [a for a in applications if a.get('contract_id') == cid]
    return jsonify({'orders': contracts})


@app.route('/api/orders/<int:order_id>/decide', methods=['POST'])
def api_order_decide(order_id):
    payload = request.get_json() or {}
    decision = payload.get('decision')
    reason = payload.get('reason','')
    user = request.cookies.get('manpower_user') or 'manager'
    contracts = _load_json('contracts.json') or []
    found = None
    for c in contracts:
        if int(c.get('id', -1)) == order_id:
            c['decision'] = decision
            c['decision_by'] = user
            c['decision_reason'] = reason
            found = c
            break
    if not found:
        return jsonify({'error':'Order not found'}), 404
    _save_json('contracts.json', contracts)
    return jsonify({'ok': True, 'order': found})


@app.route('/preview/dashboard/manager')
def preview_dashboard_manager():
    return render_template('dashboard_manager.html')

@app.route('/preview/dashboard/admin')
def preview_dashboard_admin():
    return render_template('dashboard_admin.html')


# Email Verification Endpoint
@app.route('/verify')
def verify_email():
    token = request.args.get('token')
    if not token:
        return redirect('/')

    # Load verification tokens
    tokens_path = 'verification_tokens.json'
    tokens = {}
    if os.path.exists(tokens_path):
        try:
            with open(tokens_path, 'r', encoding='utf-8') as f:
                tokens = json.load(f)
        except Exception as e:
            logger.log_error(e)
            return "Verification failed", 400

    # Find and validate token
    token_data = tokens.get(token)
    if not token_data:
        return "Invalid or expired token", 400

    email = token_data.get('email')
    expires = datetime.fromisoformat(token_data['expires'].replace('Z', '+00:00'))
    now = datetime.utcnow().replace(tzinfo=expires.tzinfo)
    if now > expires:
        return "Verification token has expired", 400

    # Update user verification status
    path = REGISTRATIONS_FILE
    try:
        with open(path, 'r', encoding='utf-8') as f:
            users = json.load(f)
        
        for r in users:
            p = r.get('payload')
            if p and p.get('email') == email:
                p['email_verified'] = True
                p.setdefault('verification_badges', []).append('email_verified')
                break

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2)

        # Remove used token
        del tokens[token]
        with open(tokens_path, 'w', encoding='utf-8') as f:
            json.dump(tokens, f, indent=2)

        # Log successful verification
        logger.log_user_action('email_verified',
            user_id=email)

        return render_template('verification_success.html')

    except Exception as e:
        logger.log_error(e)
        return "Verification failed", 400

# File Upload Endpoints
@app.route('/api/upload', methods=['POST'])
def upload_file():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Add timestamp to avoid conflicts
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Store file info in user's profile
        file_info = {
            'filename': filename,
            'original_name': file.filename,
            'upload_date': datetime.utcnow().isoformat() + 'Z',
            'file_type': request.form.get('file_type', 'document'),
            'file_size': os.path.getsize(file_path)
        }
        
        # Update user's files in registrations
        path = REGISTRATIONS_FILE
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    users = json.load(f)
                
                for r in users:
                    p = r.get('payload') if isinstance(r, dict) else None
                    if p and p.get('email') == user.get('email'):
                        if 'uploaded_files' not in p:
                            p['uploaded_files'] = []
                        p['uploaded_files'].append(file_info)
                        break
                
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(users, f, indent=2)
                    
            except Exception as e:
                return jsonify({'success': False, 'message': 'Failed to update profile'}), 500
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'file_info': file_info
        })
    
    return jsonify({'success': False, 'message': 'Invalid file type'}), 400


@app.route('/api/files/<filename>')
def uploaded_file(filename):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Payment Processing Endpoints
@app.route('/api/payments/create', methods=['POST'])
def create_payment():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.get_json(force=True) or {}
    amount = data.get('amount', 0)
    contract_id = data.get('contract_id')
    payment_type = data.get('payment_type', 'escrow')  # escrow, direct, milestone
    
    if not amount or not contract_id:
        return jsonify({'success': False, 'message': 'Amount and contract ID required'}), 400
    
    # Create payment record
    payment = {
        'id': str(uuid.uuid4()),
        'contract_id': contract_id,
        'payer': user.get('email'),
        'amount': amount,
        'payment_type': payment_type,
        'status': 'pending',
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'payment_method': data.get('payment_method', 'card'),
        'transaction_fee': round(amount * 0.029 + 30),  # Stripe-like fees
        'net_amount': amount - round(amount * 0.029 + 30)
    }
    
    # Save payment
    payments_path = 'payments.json'
    payments = []
    if os.path.exists(payments_path):
        try:
            with open(payments_path, 'r', encoding='utf-8') as f:
                payments = json.load(f)
        except Exception:
            payments = []
    
    payments.append(payment)
    
    try:
        with open(payments_path, 'w', encoding='utf-8') as f:
            json.dump(payments, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Failed to create payment'}), 500
    
    # Send notification email
    send_email(
        user.get('email'),
        'Payment Created - Manpower Platform',
        f'Your payment of ₹{amount} has been created and is pending processing.',
        f'<h2>Payment Created</h2><p>Your payment of <strong>₹{amount}</strong> has been created and is pending processing.</p><p>Payment ID: {payment["id"]}</p>'
    )
    
    return jsonify({'success': True, 'payment': payment})


@app.route('/api/payments/<payment_id>/process', methods=['POST'])
def process_payment(payment_id):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    payments_path = 'payments.json'
    if not os.path.exists(payments_path):
        return jsonify({'success': False, 'message': 'Payment not found'}), 404
    
    try:
        with open(payments_path, 'r', encoding='utf-8') as f:
            payments = json.load(f)
    except Exception:
        return jsonify({'success': False, 'message': 'Failed to read payments'}), 500
    
    payment = None
    for p in payments:
        if p.get('id') == payment_id and p.get('payer') == user.get('email'):
            payment = p
            break
    
    if not payment:
        return jsonify({'success': False, 'message': 'Payment not found'}), 404
    
    # Simulate payment processing
    payment['status'] = 'completed'
    payment['processed_at'] = datetime.utcnow().isoformat() + 'Z'
    payment['transaction_id'] = f'txn_{uuid.uuid4().hex[:12]}'
    
    try:
        with open(payments_path, 'w', encoding='utf-8') as f:
            json.dump(payments, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Failed to update payment'}), 500
    
    # Send confirmation email
    send_email(
        user.get('email'),
        'Payment Processed - Manpower Platform',
        f'Your payment of ₹{payment["amount"]} has been successfully processed.',
        f'<h2>Payment Processed</h2><p>Your payment of <strong>₹{payment["amount"]}</strong> has been successfully processed.</p><p>Transaction ID: {payment["transaction_id"]}</p>'
    )
    
    return jsonify({'success': True, 'payment': payment})


# Notification System



@app.route('/api/notifications/create', methods=['POST'])
def create_notification():
    data = request.get_json(force=True) or {}
    recipient = data.get('recipient')
    title = data.get('title')
    message = data.get('message')
    notification_type = data.get('type', 'info')  # info, success, warning, error
    
    if not recipient or not title or not message:
        return jsonify({'success': False, 'message': 'Recipient, title, and message required'}), 400
    
    notification = {
        'id': str(uuid.uuid4()),
        'recipient': recipient,
        'title': title,
        'message': message,
        'type': notification_type,
        'read': False,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    
    notifications_path = 'notifications.json'
    notifications = []
    
    if os.path.exists(notifications_path):
        try:
            with open(notifications_path, 'r', encoding='utf-8') as f:
                notifications = json.load(f)
        except Exception:
            notifications = []
    
    notifications.append(notification)
    
    try:
        with open(notifications_path, 'w', encoding='utf-8') as f:
            json.dump(notifications, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Failed to create notification'}), 500
    
    return jsonify({'success': True, 'notification': notification})


@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
def mark_notification_read(notification_id):
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    notifications_path = 'notifications.json'
    if not os.path.exists(notifications_path):
        return jsonify({'success': False, 'message': 'Notification not found'}), 404
    
    try:
        with open(notifications_path, 'r', encoding='utf-8') as f:
            notifications = json.load(f)
    except Exception:
        return jsonify({'success': False, 'message': 'Failed to read notifications'}), 500
    
    for notification in notifications:
        if notification.get('id') == notification_id and notification.get('recipient') == user.get('email'):
            notification['read'] = True
            notification['read_at'] = datetime.utcnow().isoformat() + 'Z'
            break
    else:
        return jsonify({'success': False, 'message': 'Notification not found'}), 404
    
    try:
        with open(notifications_path, 'w', encoding='utf-8') as f:
            json.dump(notifications, f, indent=2)
    except Exception:
        return jsonify({'success': False, 'message': 'Failed to update notification'}), 500
    
    return jsonify({'success': True})


# Advanced Search and Filtering
@app.route('/api/search')
def advanced_search():
    query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all')  # all, contracts, users, agencies
    location = request.args.get('location', '')
    skills = request.args.get('skills', '')
    experience = request.args.get('experience', '')
    rating_min = request.args.get('rating_min', 0)
    
    results = {
        'contracts': [],
        'users': [],
        'agencies': []
    }
    
    try:
        rating_min = float(rating_min)
    except:
        rating_min = 0
    
    # Search contracts
    if search_type in ['all', 'contracts']:
        contracts_path = 'contracts.json'
        if os.path.exists(contracts_path):
            try:
                with open(contracts_path, 'r', encoding='utf-8') as f:
                    contracts = json.load(f)
                
                for contract in contracts:
                    # Text search
                    if query and query.lower() not in (contract.get('title', '') + ' ' + contract.get('description', '')).lower():
                        continue
                    
                    # Location filter
                    if location and location.lower() not in contract.get('location', '').lower():
                        continue
                    
                    # Skills filter
                    if skills:
                        contract_skills = contract.get('skills', [])
                        if not any(skill.lower() in [s.lower() for s in contract_skills] for skill in skills.split(',')):
                            continue
                    
                    results['contracts'].append(contract)
            except Exception:
                pass
    
    # Search users
    if search_type in ['all', 'users']:
        users_path = REGISTRATIONS_FILE
        if os.path.exists(users_path):
            try:
                with open(users_path, 'r', encoding='utf-8') as f:
                    users = json.load(f)
                
                for user_record in users:
                    user = user_record.get('payload', {})
                    
                    # Skip if rating is below minimum
                    if user.get('rating', 0) < rating_min:
                        continue
                    
                    # Text search
                    if query:
                        searchable_text = (
                            user.get('company', '') + ' ' +
                            user.get('contact', '') + ' ' +
                            user.get('email', '') + ' ' +
                            user.get('skills', '') + ' ' +
                            user.get('bio', '')
                        ).lower()
                        if query.lower() not in searchable_text:
                            continue
                    
                    # Location filter
                    if location and location.lower() not in user.get('city', '').lower():
                        continue
                    
                    # Experience filter
                    if experience and user.get('experience') != experience:
                        continue
                    
                    # Remove sensitive information
                    safe_user = {
                        'email': user.get('email'),
                        'company': user.get('company'),
                        'contact': user.get('contact'),
                        'city': user.get('city'),
                        'rating': user.get('rating', 0),
                        'verified': user.get('verified', False),
                        'experience': user.get('experience'),
                        'skills': user.get('skills'),
                        'role': user.get('signupRole')
                    }
                    results['users'].append(safe_user)
            except Exception:
                pass
    
    return jsonify(results)


# Analytics and Reporting Endpoints
@app.route('/api/analytics/dashboard')
def dashboard_analytics():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({}), 401
    
    role = user.get('signupRole') or user.get('role')
    analytics = {}
    try:
        # Load data files
        contracts = _load_json('contracts.json')
        applications = _load_json('applications.json')
        payments = _load_json('payments.json')
        users = _load_json(REGISTRATIONS_FILE)

        if role == 'contractors':
            # Contractor analytics
            user_contracts = [c for c in contracts if c.get('owner') == user.get('email')]
            analytics = {
                'total_contracts': len(user_contracts),
                'active_contracts': len([c for c in user_contracts if c.get('status') == 'active']),
                'completed_contracts': len([c for c in user_contracts if c.get('status') == 'completed']),
                'total_spent': sum([p.get('amount', 0) for p in payments if p.get('payer') == user.get('email')]),
                'pending_applications': len([a for a in applications if any(c.get('id') == a.get('contract_id') for c in user_contracts)]),
                'avg_completion_time': 7.5,  # days
                'success_rate': 92.5,
                'monthly_spending': [
                    {'month': 'Jan', 'amount': 45000},
                    {'month': 'Feb', 'amount': 52000},
                    {'month': 'Mar', 'amount': 38000},
                    {'month': 'Apr', 'amount': 61000},
                    {'month': 'May', 'amount': 47000},
                    {'month': 'Jun', 'amount': 55000}
                ]
            }

        elif role == 'agency':
            # Agency analytics
            claimed_contracts = [c for c in contracts if c.get('claimed_by') == user.get('email')]
            analytics = {
                'active_contracts': len([c for c in claimed_contracts if c.get('status') == 'active']),
                'completed_contracts': len([c for c in claimed_contracts if c.get('status') == 'completed']),
                'total_earnings': sum([p.get('net_amount', 0) for p in payments if p.get('recipient') == user.get('email')]),
                'success_rate': 88.3,
                'avg_rating': user.get('rating', 4.2),
                'total_workers': 45,
                'available_workers': 32,
                'assigned_workers': 13,
                'monthly_earnings': [
                    {'month': 'Jan', 'amount': 125000},
                    {'month': 'Feb', 'amount': 138000},
                    {'month': 'Mar', 'amount': 142000},
                    {'month': 'Apr', 'amount': 156000},
                    {'month': 'May', 'amount': 149000},
                    {'month': 'Jun', 'amount': 163000}
                ]
            }

        elif role == 'individual':
            # Individual worker analytics
            user_applications = [a for a in applications if a.get('applicant') == user.get('email')]
            analytics = {
                'applications_sent': len(user_applications),
                'applications_approved': len([a for a in user_applications if a.get('status') == 'approved']),
                'total_earnings': sum([p.get('net_amount', 0) for p in payments if p.get('recipient') == user.get('email')]),
                'avg_rating': user.get('rating', 4.1),
                'profile_completion': 75,
                'skills_count': len(user.get('skills', '').split(',')) if user.get('skills') else 0,
                'certifications_count': len(user.get('certifications', [])),
                'monthly_earnings': [
                    {'month': 'Jan', 'amount': 28000},
                    {'month': 'Feb', 'amount': 32000},
                    {'month': 'Mar', 'amount': 29000},
                    {'month': 'Apr', 'amount': 35000},
                    {'month': 'May', 'amount': 31000},
                    {'month': 'Jun', 'amount': 38000}
                ]
            }

        # Common analytics for all roles
        analytics.update({
            'platform_stats': {
                'total_users': len(users),
                'total_contracts': len(contracts),
                'total_payments': len(payments),
                'platform_growth': 15.3  # percentage
            }
        })

    except Exception as e:
        print(f"Analytics error: {e}")
        analytics = {'error': 'Failed to load analytics'}

    return jsonify(analytics)


@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.get_json(force=True) or {}
    report_type = data.get('type', 'summary')  # summary, detailed, financial
    date_range = data.get('date_range', '30')  # days
    
    try:
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=int(date_range))
        
        # Load data
        contracts = _load_json('contracts.json')
        applications = _load_json('applications.json')
        payments = _load_json('payments.json')
        
        # Filter data by date range and user
        user_email = user.get('email')
        role = user.get('signupRole') or user.get('role')
        
        if role == 'contractors':
            filtered_contracts = [c for c in contracts if c.get('owner') == user_email]
        elif role == 'agency':
            filtered_contracts = [c for c in contracts if c.get('claimed_by') == user_email]
        else:
            filtered_contracts = []
        
        filtered_payments = [p for p in payments if p.get('payer') == user_email or p.get('recipient') == user_email]
        
        # Generate report
        report = {
            'id': str(uuid.uuid4()),
            'type': report_type,
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'date_range': {
                'start': start_date.isoformat() + 'Z',
                'end': end_date.isoformat() + 'Z',
                'days': int(date_range)
            },
            'summary': {
                'total_contracts': len(filtered_contracts),
                'total_payments': len(filtered_payments),
                'total_amount': sum([p.get('amount', 0) for p in filtered_payments]),
                'success_rate': 89.2
            },
            'details': {
                'contracts': filtered_contracts[:10],  # Limit for demo
                'payments': filtered_payments[:10]
            }
        }
        
        # Save report
        reports_path = 'reports.json'
        reports = _load_json(reports_path)
        reports.append(report)
        _save_json(reports_path, reports)
        
        return jsonify({'success': True, 'report': report})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to generate report: {str(e)}'}), 500


# Enhanced User Verification System
@app.route('/api/verification/request', methods=['POST'])
def request_verification():
    user = _get_user_by_cookie()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.get_json(force=True) or {}
    verification_type = data.get('type', 'identity')  # identity, skills, business
    documents = data.get('documents', [])
    
    verification_request = {
        'id': str(uuid.uuid4()),
        'user_email': user.get('email'),
        'type': verification_type,
        'documents': documents,
        'status': 'pending',
        'requested_at': datetime.utcnow().isoformat() + 'Z',
        'notes': data.get('notes', '')
    }
    
    # Save verification request
    verifications_path = 'verifications.json'
    verifications = _load_json(verifications_path)
    verifications.append(verification_request)
    _save_json(verifications_path, verifications)
    
    # Create notification for admin
    create_notification_internal(
        'admin@local',
        'New Verification Request',
        f'User {user.get("email")} has requested {verification_type} verification.',
        'info'
    )
    
    return jsonify({'success': True, 'verification_request': verification_request})


def send_verification_email(user_email, user_name, verification_token):
    verification_link = f"{request.host_url}verify?token={verification_token}"
    email_content = email_service.get_verification_email(user_name, verification_link)
    send_email(user_email, "Verify Your Account", email_content['text'], email_content['html'])

@app.route('/api/verification/approve/<request_id>', methods=['POST'])
def approve_verification(request_id):
    user = _get_user_by_cookie()
    if not user or user.get('email') != 'admin@local':
        logger.log_security_event(
            'unauthorized_verification_approval', 
            user_id=user.get('email') if user else None,
            ip_address=request.remote_addr
        )
        return jsonify({'success': False, 'message': 'Not authorized'}), 403
    
    data = request.get_json(force=True) or {}
    badge = data.get('badge', 'verified')
    
    # Find verification request
    verifications_path = 'verifications.json'
    verifications = _load_json(verifications_path)
    
    verification_request = None
    for v in verifications:
        if v.get('id') == request_id:
            verification_request = v
            break
    
    if not verification_request:
        return jsonify({'success': False, 'message': 'Verification request not found'}), 404
    
    # Update user's verification status
    verification_request['status'] = 'approved'
    verification_request['approved_at'] = datetime.utcnow().isoformat() + 'Z'
    verification_request['approved_by'] = user.get('email')
    
    # Update user's verification status
    target_email = verification_request.get('user_email')
    users_path = REGISTRATIONS_FILE
    users = _load_json(users_path)
    
    for user_record in users:
        user_data = user_record.get('payload', {})
        if user_data.get('email') == target_email:
            if badge not in user_data.get('verification_badges', []):
                user_data.setdefault('verification_badges', []).append(badge)
                user_data['verified'] = True
            break
    
    # Save updates
    _save_json(verifications_path, verifications)
    _save_json(users_path, users)
    
    # Notify user
    create_notification_internal(
        target_email,
        'Verification Approved',
        f'Your {verification_request.get("type")} verification has been approved!',
        'success'
    )
    
    return jsonify({'success': True, 'message': 'Verification approved'})


def create_notification_internal(recipient, title, message, notification_type='info'):
    """Internal helper to create notifications"""
    notification = {
        'id': str(uuid.uuid4()),
        'recipient': recipient,
        'title': title,
        'message': message,
        'type': notification_type,
        'read': False,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    
    notifications_path = 'notifications.json'
    notifications = _load_json(notifications_path)
    notifications.append(notification)
    _save_json(notifications_path, notifications)
    
    return notification


@app.route('/marketplace')
def marketplace():
    """Dispatch users to a role-specific marketplace view"""
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')

    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)
    role = (role or '').lower()

    if role == 'contractors':
        return redirect('/marketplace/contractors')
    elif role == 'agency':
        return redirect('/marketplace/agency')
    else:
        return redirect('/marketplace/individual')


@app.route('/marketplace/contractors')
def marketplace_contractors():
    """Contractors see agency listings to hire from"""
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')
    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)
    if (role or '').lower() != 'contractors':
        return redirect('/marketplace')

    # Load agencies from registrations
    agencies = []
    try:
        regs = safe_read_json(REGISTRATIONS_FILE)
        for r in regs:
            p = r.get('payload') if isinstance(r, dict) else r
            rrole = (p.get('signupRole') if isinstance(p, dict) else None) or (p.get('role') if isinstance(p, dict) else None)
            if rrole and str(rrole).lower() in ('agency', 'agencies'):
                agencies.append(p)
    except Exception:
        agencies = []

    return render_template('marketplace.html', user=user, role='contractors', agencies=agencies)


@app.route('/marketplace/agency')
def marketplace_agency():
    """Agency view of the marketplace - see workers/recruits"""
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')
    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)
    if (role or '').lower() != 'agency':
        return redirect('/marketplace')

    # Load recruits (individuals) from registrations
    recruits = []
    try:
        regs = safe_read_json(REGISTRATIONS_FILE)
        for r in regs:
            p = r.get('payload') if isinstance(r, dict) else r
            rrole = (p.get('signupRole') if isinstance(p, dict) else None) or (p.get('role') if isinstance(p, dict) else None)
            if rrole and str(rrole).lower() in ('individual', 'job seeker', 'job_seeker'):
                recruits.append(p)
    except Exception:
        recruits = []

    return render_template('marketplace.html', user=user, role='agency', recruits=recruits)


@app.route('/marketplace/individual')
def marketplace_individual():
    """Individual/job seeker marketplace - browse contracts and agencies"""
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')
    role = (user.get('signupRole') if user else None) or (user.get('role') if user else None)
    if (role or '').lower() not in ('individual', 'job seeker', 'job_seeker', ''):
        return redirect('/marketplace')

    # Provide contracts and agencies for individuals to browse
    contracts = _load_json('contracts.json')
    agencies = []
    try:
        regs = safe_read_json(REGISTRATIONS_FILE)
        for r in regs:
            p = r.get('payload') if isinstance(r, dict) else r
            rrole = (p.get('signupRole') if isinstance(p, dict) else None) or (p.get('role') if isinstance(p, dict) else None)
            if rrole and str(rrole).lower() in ('agency', 'agencies'):
                agencies.append(p)
    except Exception:
        agencies = []

    return render_template('marketplace.html', user=user, role='individual', contracts=contracts, agencies=agencies)


@app.route('/agency/<path:email>')
def agency_profile(email):
    """Render a minimal agency profile page for the given email."""
    # require logged-in user
    user = _get_user_by_cookie()
    if not user:
        return redirect('/')

    agency = None
    try:
        regs = safe_read_json(REGISTRATIONS_FILE)
        for r in regs:
            p = r.get('payload') if isinstance(r, dict) else r
            if p and p.get('email') and p.get('email').strip().lower() == (email or '').strip().lower():
                # only allow agency records
                role = (p.get('signupRole') if p else None) or (p.get('role') if p else None)
                if role and str(role).lower() in ('agency', 'agencies'):
                    agency = p
                    break
    except Exception:
        agency = None

    if not agency:
        return redirect('/marketplace')

    return render_template('agency_profile.html', agency=agency)


if __name__ == '__main__':
    # Initialize logger first
    logger.init_app(app)
    app.logger.info("Starting Manpower Platform...")
    
    # Get environment settings
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    port = int(os.getenv('PORT', 5000))
    
    # Start the application
    app.run(debug=debug_mode, port=port)

