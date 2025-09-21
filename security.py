from functools import wraps
from flask import request, jsonify, session
import secrets
from datetime import datetime, timedelta

def generate_csrf_token():
    """Generate a new CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def verify_csrf_token():
    """Verify the CSRF token in the request against the session token"""
    token = request.headers.get('X-CSRF-Token')
    return token and token == session.get('csrf_token')

def csrf_protected(f):
    """Decorator to require CSRF token for POST/PUT/DELETE requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            if not verify_csrf_token():
                return jsonify({'error': 'Invalid or missing CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_exceeded(ip_address, endpoint, limit, period):
    """Check if rate limit is exceeded for IP and endpoint"""
    now = datetime.utcnow()
    key = f"rate_limit:{ip_address}:{endpoint}"
    
    if key not in session:
        session[key] = {'count': 0, 'reset_time': now + timedelta(seconds=period)}
    
    limit_data = session[key]
    
    # Reset if period expired
    if now > limit_data['reset_time']:
        limit_data['count'] = 0
        limit_data['reset_time'] = now + timedelta(seconds=period)
    
    # Check and increment
    if limit_data['count'] >= limit:
        return True
    
    limit_data['count'] += 1
    session[key] = limit_data
    return False

def rate_limited(limit, period):
    """Decorator to apply rate limiting to endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            endpoint = request.endpoint
            
            if rate_limit_exceeded(ip, endpoint, limit, period):
                return jsonify({'error': 'Rate limit exceeded'}), 429
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def sanitize_json(data):
    """Recursively sanitize JSON input by stripping strings and validating types"""
    if isinstance(data, dict):
        return {k: sanitize_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_json(x) for x in data]
    elif isinstance(data, str):
        return data.strip()
    else:
        return data
        
def validate_file_type(file, content_type):
    """Validate file content type matches expected type"""
    try:
        import magic
        mime = magic.from_buffer(file.read(2048), mime=True)
        file.seek(0)  # Reset file pointer
        return mime.startswith(content_type)
    except ImportError:
        # Fallback to basic extension checking if python-magic not available
        filename = file.filename.lower()
        if content_type == 'image/':
            return any(filename.endswith(ext) for ext in ['.jpg','.jpeg','.png','.gif'])
        elif content_type == 'application/pdf':
            return filename.endswith('.pdf')
        return False