from datetime import timedelta
import secrets
import os

class Config:
    # Basic Flask config
    DEBUG = False
    TESTING = False
    
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.getenv('WTF_CSRF_SECRET_KEY', secrets.token_hex(32))
    
    # File Upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    
    # Rate Limiting
    RATELIMIT_DEFAULT = "200 per day"
    RATELIMIT_STORAGE_URL = "memory://"
    
    # Email
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    
    # Session
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_session')
    SESSION_PERMANENT = True
    
    # Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'; "
                                 "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; "
                                 "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
                                 "img-src 'self' data: https: blob:; "
                                 "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
                                 "connect-src 'self' https://api.manpower-platform.com; "
                                 "frame-ancestors 'none'; "
                                 "base-uri 'self'; "
                                 "form-action 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    # Password Policy
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_NUMBERS = True
    PASSWORD_REQUIRE_SPECIAL = True
    
    # API
    API_RATE_LIMIT = {
        'DEFAULT': '100 per minute',
        'AUTH': '5 per minute',
        'SIGNUP': '3 per hour',
        'RESET_PASSWORD': '3 per hour'
    }
    
    # Data Storage
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
    
    @staticmethod
    def init_app(app):
        """Initialize application with security settings"""
        # Ensure required directories exist
        for directory in [Config.UPLOAD_FOLDER, Config.SESSION_FILE_DIR, 
                         Config.DATA_DIR, Config.BACKUP_DIR]:
            os.makedirs(directory, exist_ok=True)
        
        # Set security headers
        @app.after_request
        def add_security_headers(response):
            for key, value in Config.SECURITY_HEADERS.items():
                response.headers[key] = value
            return response
            
class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development
    
class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SERVER_NAME = 'localhost'
    
class ProductionConfig(Config):
    # Production overrides
    SESSION_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = 'https'
    
    # Stricter CSP in production
    SECURITY_HEADERS = Config.SECURITY_HEADERS.copy()
    SECURITY_HEADERS.update({
        'Content-Security-Policy': Config.SECURITY_HEADERS['Content-Security-Policy'].replace(
            "'unsafe-inline' 'unsafe-eval'", 
            "'nonce-{nonce}'"
        )
    })

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}