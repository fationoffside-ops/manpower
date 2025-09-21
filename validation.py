"""
Validation utilities for Manpower Platform
Provides comprehensive input validation and error handling
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional

class ValidationError(Exception):
    """Custom validation error"""
    def __init__(self, message: str, field: str = None):
        self.message = message
        self.field = field
        super().__init__(self.message)

class Validator:
    """Comprehensive validation class"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        if not email or not isinstance(email, str):
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email.strip()) is not None
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """Validate phone number format"""
        if not phone or not isinstance(phone, str):
            return False
        # Remove all non-digit characters
        digits = re.sub(r'\D', '', phone)
        # Check if it's 10 digits (Indian format) or 10-15 digits (international)
        return 10 <= len(digits) <= 15
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if not password or not isinstance(password, str):
            return False, "Password is required"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) > 128:
            return False, "Password must be less than 128 characters"
        
        # Check for at least one letter, digit, and special character
        if not re.search(r'[a-zA-Z]', password):
            return False, "Password must contain at least one letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is valid"
    
    @staticmethod
    def validate_required_fields(data: Dict[str, Any], required_fields: List[str]) -> List[str]:
        """Validate that required fields are present and not empty"""
        missing_fields = []
        
        for field in required_fields:
            if field not in data or not data[field] or (isinstance(data[field], str) and not data[field].strip()):
                missing_fields.append(field)
        
        return missing_fields
    
    @staticmethod
    def validate_numeric_range(value: Any, min_val: float = None, max_val: float = None, field_name: str = "value") -> Tuple[bool, str]:
        """Validate numeric value within range"""
        try:
            num_value = float(value)
        except (ValueError, TypeError):
            return False, f"{field_name} must be a valid number"
        
        if min_val is not None and num_value < min_val:
            return False, f"{field_name} must be at least {min_val}"
        
        if max_val is not None and num_value > max_val:
            return False, f"{field_name} must be at most {max_val}"
        
        return True, "Valid"
    
    @staticmethod
    def validate_string_length(value: str, min_len: int = None, max_len: int = None, field_name: str = "field") -> Tuple[bool, str]:
        """Validate string length"""
        if not isinstance(value, str):
            return False, f"{field_name} must be a string"
        
        length = len(value.strip())
        
        if min_len is not None and length < min_len:
            return False, f"{field_name} must be at least {min_len} characters long"
        
        if max_len is not None and length > max_len:
            return False, f"{field_name} must be at most {max_len} characters long"
        
        return True, "Valid"
    
    @staticmethod
    def validate_choice(value: str, choices: List[str], field_name: str = "field") -> Tuple[bool, str]:
        """Validate that value is in allowed choices"""
        if value not in choices:
            return False, f"{field_name} must be one of: {', '.join(choices)}"
        return True, "Valid"
    
    @staticmethod
    def sanitize_input(value: str) -> str:
        """Sanitize input string"""
        if not isinstance(value, str):
            return str(value)
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', value)
        return sanitized.strip()

class ContractValidator:
    """Validator for contract data"""
    
    @staticmethod
    def validate_contract_data(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate contract creation data"""
        errors = []
        
        # Required fields
        required_fields = ['title', 'location', 'workers', 'description']
        missing_fields = Validator.validate_required_fields(data, required_fields)
        if missing_fields:
            errors.extend([f"{field} is required" for field in missing_fields])
        
        # Title validation
        if 'title' in data:
            is_valid, msg = Validator.validate_string_length(data['title'], 3, 100, "Title")
            if not is_valid:
                errors.append(msg)
        
        # Workers validation
        if 'workers' in data:
            is_valid, msg = Validator.validate_numeric_range(data['workers'], 1, 1000, "Number of workers")
            if not is_valid:
                errors.append(msg)
        
        # Budget validation
        if 'budget' in data and data['budget']:
            is_valid, msg = Validator.validate_numeric_range(data['budget'], 0, 10000000, "Budget")
            if not is_valid:
                errors.append(msg)
        
        # Urgency validation
        if 'urgency' in data:
            is_valid, msg = Validator.validate_choice(data['urgency'], ['normal', 'urgent', 'critical'], "Urgency")
            if not is_valid:
                errors.append(msg)
        
        return len(errors) == 0, errors

class UserValidator:
    """Validator for user data"""
    
    @staticmethod
    def validate_signup_data(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate user signup data"""
        errors = []
        
        # Email validation
        if 'email' not in data or not Validator.validate_email(data['email']):
            errors.append("Valid email address is required")
        
        # Password validation
        if 'password' in data:
            is_valid, msg = Validator.validate_password(data['password'])
            if not is_valid:
                errors.append(msg)
        
        # Phone validation
        if 'phone' in data and data['phone']:
            if not Validator.validate_phone(data['phone']):
                errors.append("Valid phone number is required")
        
        # Role-specific validation
        role = data.get('signupRole', '')
        
        if role == 'individual':
            # Last name is NOT required for individual accounts
            required_fields = ['email', 'password', 'city', 'experience']
            missing_fields = Validator.validate_required_fields(data, required_fields)
            if missing_fields:
                errors.extend([f"{field} is required for individual accounts" for field in missing_fields])
        
        elif role == 'contractors':
            # Contact person is optional for contractor accounts - allow company-only signups
            required_fields = ['email', 'password', 'company', 'city']
            missing_fields = Validator.validate_required_fields(data, required_fields)
            if missing_fields:
                errors.extend([f"{field} is required for contractor accounts" for field in missing_fields])
        
        elif role == 'agency':
            # Contact person optional for agencies as well
            required_fields = ['email', 'password', 'company', 'specializations', 'city']
            missing_fields = Validator.validate_required_fields(data, required_fields)
            if missing_fields:
                errors.extend([f"{field} is required for agency accounts" for field in missing_fields])
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_rating_data(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate rating/review data"""
        errors = []
        
        # Rating validation
        if 'rating' not in data:
            errors.append("Rating is required")
        else:
            is_valid, msg = Validator.validate_numeric_range(data['rating'], 1, 5, "Rating")
            if not is_valid:
                errors.append(msg)
        
        # Review validation
        if 'review' in data and data['review']:
            is_valid, msg = Validator.validate_string_length(data['review'], 1, 1000, "Review")
            if not is_valid:
                errors.append(msg)
        
        return len(errors) == 0, errors

class PaymentValidator:
    """Validator for payment data"""
    
    @staticmethod
    def validate_payment_data(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate payment creation data"""
        errors = []
        
        # Required fields
        required_fields = ['amount', 'contract_id']
        missing_fields = Validator.validate_required_fields(data, required_fields)
        if missing_fields:
            errors.extend([f"{field} is required" for field in missing_fields])
        
        # Amount validation
        if 'amount' in data:
            is_valid, msg = Validator.validate_numeric_range(data['amount'], 1, 10000000, "Amount")
            if not is_valid:
                errors.append(msg)
        
        # Payment type validation
        if 'payment_type' in data:
            is_valid, msg = Validator.validate_choice(data['payment_type'], ['escrow', 'direct', 'milestone'], "Payment type")
            if not is_valid:
                errors.append(msg)
        
        # Payment method validation
        if 'payment_method' in data:
            is_valid, msg = Validator.validate_choice(data['payment_method'], ['card', 'bank', 'upi', 'wallet'], "Payment method")
            if not is_valid:
                errors.append(msg)
        
        return len(errors) == 0, errors

def validate_file_upload(file) -> Tuple[bool, str]:
    """Validate uploaded file"""
    if not file:
        return False, "No file provided"
    
    if file.filename == '':
        return False, "No file selected"
    
    # Check file extension
    allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    if '.' not in file.filename:
        return False, "File must have an extension"
    
    ext = file.filename.rsplit('.', 1)[1].lower()
    if ext not in allowed_extensions:
        return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
    
    # Check file size (this would be handled by Flask config, but good to double-check)
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset to beginning
    
    max_size = 16 * 1024 * 1024  # 16MB
    if size > max_size:
        return False, f"File too large. Maximum size: {max_size // (1024*1024)}MB"
    
    return True, "File is valid"

def create_error_response(message: str, status_code: int = 400, field: str = None) -> Dict[str, Any]:
    """Create standardized error response"""
    error_response = {
        'success': False,
        'message': message,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    if field:
        error_response['field'] = field
    
    return error_response

def create_success_response(data: Any = None, message: str = "Success") -> Dict[str, Any]:
    """Create standardized success response"""
    response = {
        'success': True,
        'message': message,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    if data is not None:
        response['data'] = data
    
    return response