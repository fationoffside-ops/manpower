"""
Logging utilities for Manpower Platform
Provides structured logging with different levels and formatters
"""

import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
import json

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        if hasattr(record, 'ip_address'):
            log_entry['ip_address'] = record.ip_address
        
        return json.dumps(log_entry)

class ManpowerLogger:
    """Centralized logging configuration for Manpower Platform"""
    
    def __init__(self, app=None):
        self.app = app
        self.logger = logging.getLogger('manpower')
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize logging for Flask app"""
        
        # Create logs directory if it doesn't exist
        log_dir = 'logs'
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure logger
        self.logger.setLevel(logging.INFO)
        
        # Remove default handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Console handler for development
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        
        # File handler for application logs
        app_handler = RotatingFileHandler(
            os.path.join(log_dir, 'app.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        app_handler.setLevel(logging.INFO)
        app_handler.setFormatter(JSONFormatter())
        
        # Error handler for errors only
        error_handler = RotatingFileHandler(
            os.path.join(log_dir, 'error.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(JSONFormatter())
        
        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(app_handler)
        self.logger.addHandler(error_handler)
        
        # Configure Flask app logger
        app.logger.setLevel(logging.INFO)
        
        # Log application startup
        self.logger.info("Manpower Platform application started", extra={
            'event': 'app_startup',
            'version': '1.0.0'
        })

    # Backwards-compatibility helpers / proxy
    def log_exception(self, error: Exception, context: dict = None):
        """Alias for log_error used in some codepaths"""
        return self.log_error(error, context)

    def __getattr__(self, name):
        """Proxy unknown attributes to the underlying stdlib logger when possible.

        This prevents AttributeError in call sites that expect a richer logger
        interface (for example when reloading modules or when older code calls
        methods that aren't present on this wrapper).
        """
        # Allow direct access to underlying logger methods (info, debug, error, etc.)
        if hasattr(self.logger, name):
            return getattr(self.logger, name)
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
    
    def log_error(self, error: Exception, context: dict = None):
        """Log error with context"""
        self.logger.error(f"Error: {str(error)}", extra={
            'event': 'error',
            'error_type': type(error).__name__,
            'context': context or {}
        }, exc_info=True)

    def log_security_event(self, event_type: str, user_id: str = None, ip_address: str = None, details: dict = None):
        """Log security-related events"""
        self.logger.warning(f"Security Event: {event_type}", extra={
            'event': 'security',
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'details': details or {}
        })

    def log_api_request(self, endpoint: str, method: str, user_id: str = None, ip_address: str = None):
        """Log API request"""
        self.logger.info(f"API Request: {method} {endpoint}", extra={
            'event': 'api_request',
            'endpoint': endpoint,
            'method': method,
            'user_id': user_id,
            'ip_address': ip_address
        })

    def log_api_response(self, endpoint: str, status_code: int, user_id: str = None, response_time: float = None):
        """Log API response"""
        self.logger.info(f"API Response: {endpoint} - {status_code}", extra={
            'event': 'api_response',
            'endpoint': endpoint,
            'status_code': status_code,
            'user_id': user_id,
            'response_time': response_time
        })

    def log_user_action(self, action: str, user_id: str, details: dict = None):
        """Log user action"""
        self.logger.info(f"User Action: {action}", extra={
            'event': 'user_action',
            'action': action,
            'user_id': user_id,
            'details': details or {}
        })

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    return logging.getLogger(name)

# Performance monitoring

# Performance monitoring
class PerformanceMonitor:
    """Monitor application performance"""
    
    @staticmethod
    def log_slow_query(logger: logging.Logger, query_type: str, duration: float, details: dict = None):
        """Log slow database queries or operations"""
        if duration > 1.0:  # Log queries taking more than 1 second
            logger.warning(f"Slow Query: {query_type} took {duration:.2f}s", extra={
                'event': 'slow_query',
                'query_type': query_type,
                'duration': duration,
                'details': details or {}
            })
    
    @staticmethod
    def log_memory_usage(logger: logging.Logger, usage_mb: float):
        """Log memory usage"""
        if usage_mb > 500:  # Log if using more than 500MB
            logger.warning(f"High Memory Usage: {usage_mb:.2f}MB", extra={
                'event': 'high_memory',
                'memory_mb': usage_mb
            })

# Audit logging
def log_data_change(logger: logging.Logger, table: str, operation: str, record_id: str, user_id: str, changes: dict = None):
    """Log data changes for audit trail"""
    logger.info(f"Data Change: {operation} on {table}", extra={
        'event': 'data_change',
        'table': table,
        'operation': operation,
        'record_id': record_id,
        'user_id': user_id,
        'changes': changes or {}
    })