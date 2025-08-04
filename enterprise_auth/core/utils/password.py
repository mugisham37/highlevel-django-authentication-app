"""
Password management utilities for enterprise authentication system.

This module provides comprehensive password management functionality including
Argon2 hashing, strength validation, secure token generation, and password
policy enforcement.
"""

import secrets
import string
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .encryption import encrypt_sensitive_data, decrypt_sensitive_data


class PasswordStrengthValidator:
    """
    Configurable password strength validator with enterprise-grade policies.
    
    Validates passwords against configurable policies including length,
    character requirements, dictionary checks, and user attribute similarity.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize password validator with configuration.
        
        Args:
            config: Password policy configuration dictionary
        """
        self.config = config or self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """
        Get default password policy configuration.
        
        Returns:
            Default password policy settings
        """
        return {
            'min_length': getattr(settings, 'PASSWORD_MIN_LENGTH', 12),
            'max_length': getattr(settings, 'PASSWORD_MAX_LENGTH', 128),
            'require_uppercase': getattr(settings, 'PASSWORD_REQUIRE_UPPERCASE', True),
            'require_lowercase': getattr(settings, 'PASSWORD_REQUIRE_LOWERCASE', True),
            'require_digits': getattr(settings, 'PASSWORD_REQUIRE_DIGITS', True),
            'require_special_chars': getattr(settings, 'PASSWORD_REQUIRE_SPECIAL_CHARS', True),
            'min_uppercase': getattr(settings, 'PASSWORD_MIN_UPPERCASE', 1),
            'min_lowercase': getattr(settings, 'PASSWORD_MIN_LOWERCASE', 1),
            'min_digits': getattr(settings, 'PASSWORD_MIN_DIGITS', 1),
            'min_special_chars': getattr(settings, 'PASSWORD_MIN_SPECIAL_CHARS', 1),
            'special_chars': getattr(settings, 'PASSWORD_SPECIAL_CHARS', '!@#$%^&*()_+-=[]{}|;:,.<>?'),
            'max_consecutive_chars': getattr(settings, 'PASSWORD_MAX_CONSECUTIVE_CHARS', 3),
            'max_repeated_chars': getattr(settings, 'PASSWORD_MAX_REPEATED_CHARS', 3),
            'check_common_passwords': getattr(settings, 'PASSWORD_CHECK_COMMON_PASSWORDS', True),
            'check_user_attributes': getattr(settings, 'PASSWORD_CHECK_USER_ATTRIBUTES', True),
            'min_unique_chars': getattr(settings, 'PASSWORD_MIN_UNIQUE_CHARS', 8),
            'entropy_threshold': getattr(settings, 'PASSWORD_ENTROPY_THRESHOLD', 50),
        }
    
    def validate(self, password: str, user=None) -> Tuple[bool, List[str]]:
        """
        Validate password against all configured policies.
        
        Args:
            password: Password to validate
            user: User object for attribute similarity checking
            
        Returns:
            Tuple of (is_valid, list_of_error_messages)
        """
        errors = []
        
        # Length validation
        if len(password) < self.config['min_length']:
            errors.append(
                _('Password must be at least {min_length} characters long.').format(
                    min_length=self.config['min_length']
                )
            )
        
        if len(password) > self.config['max_length']:
            errors.append(
                _('Password must be no more than {max_length} characters long.').format(
                    max_length=self.config['max_length']
                )
            )
        
        # Character type requirements
        uppercase_count = sum(1 for c in password if c.isupper())
        lowercase_count = sum(1 for c in password if c.islower())
        digit_count = sum(1 for c in password if c.isdigit())
        special_count = sum(1 for c in password if c in self.config['special_chars'])
        
        if self.config['require_uppercase'] and uppercase_count < self.config['min_uppercase']:
            errors.append(
                _('Password must contain at least {count} uppercase letter(s).').format(
                    count=self.config['min_uppercase']
                )
            )
        
        if self.config['require_lowercase'] and lowercase_count < self.config['min_lowercase']:
            errors.append(
                _('Password must contain at least {count} lowercase letter(s).').format(
                    count=self.config['min_lowercase']
                )
            )
        
        if self.config['require_digits'] and digit_count < self.config['min_digits']:
            errors.append(
                _('Password must contain at least {count} digit(s).').format(
                    count=self.config['min_digits']
                )
            )
        
        if self.config['require_special_chars'] and special_count < self.config['min_special_chars']:
            errors.append(
                _('Password must contain at least {count} special character(s) from: {chars}').format(
                    count=self.config['min_special_chars'],
                    chars=self.config['special_chars']
                )
            )
        
        # Pattern validation
        errors.extend(self._validate_patterns(password))
        
        # Uniqueness validation
        unique_chars = len(set(password))
        if unique_chars < self.config['min_unique_chars']:
            errors.append(
                _('Password must contain at least {count} unique characters.').format(
                    count=self.config['min_unique_chars']
                )
            )
        
        # Entropy validation
        entropy = self._calculate_entropy(password)
        if entropy < self.config['entropy_threshold']:
            errors.append(
                _('Password is too predictable. Please use a more complex password.')
            )
        
        # Common password check
        if self.config['check_common_passwords'] and self._is_common_password(password):
            errors.append(_('This password is too common. Please choose a different password.'))
        
        # User attribute similarity check
        if self.config['check_user_attributes'] and user:
            errors.extend(self._check_user_attribute_similarity(password, user))
        
        return len(errors) == 0, errors
    
    def _validate_patterns(self, password: str) -> List[str]:
        """
        Validate password against pattern-based rules.
        
        Args:
            password: Password to validate
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Check for consecutive characters
        consecutive_count = 1
        max_consecutive = 1
        for i in range(1, len(password)):
            if ord(password[i]) == ord(password[i-1]) + 1:
                consecutive_count += 1
                max_consecutive = max(max_consecutive, consecutive_count)
            else:
                consecutive_count = 1
        
        if max_consecutive > self.config['max_consecutive_chars']:
            errors.append(
                _('Password cannot contain more than {count} consecutive characters.').format(
                    count=self.config['max_consecutive_chars']
                )
            )
        
        # Check for repeated characters
        char_counts = {}
        for char in password:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        max_repeated = max(char_counts.values()) if char_counts else 0
        if max_repeated > self.config['max_repeated_chars']:
            errors.append(
                _('Password cannot contain more than {count} repeated characters.').format(
                    count=self.config['max_repeated_chars']
                )
            )
        
        # Check for keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '1234', 'abcd',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1234567890', 'abcdefghij'
        ]
        
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                errors.append(_('Password cannot contain keyboard patterns.'))
                break
        
        return errors
    
    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy in bits.
        
        Args:
            password: Password to analyze
            
        Returns:
            Entropy value in bits
        """
        if not password:
            return 0.0
        
        # Character set size calculation
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in self.config['special_chars'] for c in password):
            charset_size += len(self.config['special_chars'])
        
        # Basic entropy calculation
        import math
        if charset_size == 0:
            return 0.0
        
        entropy = len(password) * math.log2(charset_size)
        
        # Adjust for patterns and repetition
        unique_chars = len(set(password))
        repetition_factor = unique_chars / len(password)
        entropy *= repetition_factor
        
        return entropy
    
    def _is_common_password(self, password: str) -> bool:
        """
        Check if password is in common password list.
        
        Args:
            password: Password to check
            
        Returns:
            True if password is common, False otherwise
        """
        # Common passwords list (subset for demonstration)
        common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'shadow', 'superman', 'michael',
            'football', 'baseball', 'liverpool', 'jordan', 'princess',
            'charlie', 'aa123456', 'donald', 'password1', 'qwerty123'
        }
        
        return password.lower() in common_passwords
    
    def _check_user_attribute_similarity(self, password: str, user) -> List[str]:
        """
        Check password similarity to user attributes.
        
        Args:
            password: Password to check
            user: User object with attributes
            
        Returns:
            List of validation error messages
        """
        errors = []
        password_lower = password.lower()
        
        # Attributes to check
        attributes = []
        if hasattr(user, 'email') and user.email:
            attributes.extend([
                user.email.lower(),
                user.email.split('@')[0].lower()
            ])
        
        if hasattr(user, 'first_name') and user.first_name:
            attributes.append(user.first_name.lower())
        
        if hasattr(user, 'last_name') and user.last_name:
            attributes.append(user.last_name.lower())
        
        if hasattr(user, 'username') and user.username:
            attributes.append(user.username.lower())
        
        if hasattr(user, 'organization') and user.organization:
            attributes.append(user.organization.lower())
        
        # Check for similarity
        for attr in attributes:
            if len(attr) >= 3:  # Only check attributes with 3+ characters
                if attr in password_lower or password_lower in attr:
                    errors.append(
                        _('Password cannot be similar to your personal information.')
                    )
                    break
        
        return errors
    
    def get_strength_score(self, password: str) -> Dict:
        """
        Calculate password strength score and feedback.
        
        Args:
            password: Password to analyze
            
        Returns:
            Dictionary with score, level, and feedback
        """
        if not password:
            return {
                'score': 0,
                'level': 'Very Weak',
                'feedback': ['Password is required']
            }
        
        score = 0
        feedback = []
        
        # Length scoring
        length_score = min(len(password) / self.config['min_length'], 1.0) * 25
        score += length_score
        
        if len(password) < self.config['min_length']:
            feedback.append(f'Use at least {self.config["min_length"]} characters')
        
        # Character diversity scoring
        char_types = 0
        if any(c.islower() for c in password):
            char_types += 1
        if any(c.isupper() for c in password):
            char_types += 1
        if any(c.isdigit() for c in password):
            char_types += 1
        if any(c in self.config['special_chars'] for c in password):
            char_types += 1
        
        diversity_score = (char_types / 4) * 25
        score += diversity_score
        
        if char_types < 3:
            feedback.append('Use a mix of letters, numbers, and symbols')
        
        # Uniqueness scoring
        unique_chars = len(set(password))
        uniqueness_score = min(unique_chars / len(password), 1.0) * 25
        score += uniqueness_score
        
        if unique_chars < len(password) * 0.7:
            feedback.append('Avoid repeated characters')
        
        # Entropy scoring
        entropy = self._calculate_entropy(password)
        entropy_score = min(entropy / self.config['entropy_threshold'], 1.0) * 25
        score += entropy_score
        
        if entropy < self.config['entropy_threshold']:
            feedback.append('Make your password less predictable')
        
        # Determine strength level
        if score >= 90:
            level = 'Very Strong'
        elif score >= 75:
            level = 'Strong'
        elif score >= 50:
            level = 'Moderate'
        elif score >= 25:
            level = 'Weak'
        else:
            level = 'Very Weak'
        
        return {
            'score': int(score),
            'level': level,
            'feedback': feedback if feedback else ['Password strength is good']
        }


class PasswordHasher:
    """
    Enterprise-grade password hashing using Argon2 with optimal parameters.
    
    Provides secure password hashing and verification with configurable
    Argon2 parameters optimized for security and performance.
    """
    
    def __init__(self):
        """Initialize password hasher with optimal Argon2 parameters."""
        self.time_cost = getattr(settings, 'ARGON2_TIME_COST', 3)
        self.memory_cost = getattr(settings, 'ARGON2_MEMORY_COST', 65536)  # 64 MB
        self.parallelism = getattr(settings, 'ARGON2_PARALLELISM', 2)
        self.hash_len = getattr(settings, 'ARGON2_HASH_LEN', 32)
        self.salt_len = getattr(settings, 'ARGON2_SALT_LEN', 16)
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using Argon2 with optimal parameters.
        
        Args:
            password: Plain text password to hash
            
        Returns:
            Hashed password string
        """
        return make_password(password, hasher='argon2')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plain text password to verify
            hashed_password: Stored password hash
            
        Returns:
            True if password matches hash, False otherwise
        """
        return check_password(password, hashed_password)
    
    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if password hash needs to be updated.
        
        Args:
            hashed_password: Stored password hash
            
        Returns:
            True if hash should be updated, False otherwise
        """
        # Check if hash uses current algorithm and parameters
        if not hashed_password.startswith('argon2'):
            return True
        
        # Additional checks for parameter updates could be added here
        return False


class PasswordResetTokenGenerator:
    """
    Secure token generator for password reset functionality.
    
    Generates cryptographically secure tokens for password reset workflows
    with configurable expiration and validation.
    """
    
    def __init__(self):
        """Initialize token generator with default settings."""
        self.token_length = getattr(settings, 'PASSWORD_RESET_TOKEN_LENGTH', 32)
        self.token_expiry_hours = getattr(settings, 'PASSWORD_RESET_TOKEN_EXPIRY_HOURS', 1)
    
    def generate_token(self) -> str:
        """
        Generate a cryptographically secure reset token.
        
        Returns:
            URL-safe random token string
        """
        return secrets.token_urlsafe(self.token_length)
    
    def create_reset_token_data(self, user) -> Dict:
        """
        Create password reset token data for a user.
        
        Args:
            user: User requesting password reset
            
        Returns:
            Dictionary with token, expiry, and metadata
        """
        token = self.generate_token()
        expires_at = timezone.now() + timedelta(hours=self.token_expiry_hours)
        
        return {
            'token': token,
            'expires_at': expires_at,
            'user_id': str(user.id),
            'email': user.email,
            'created_at': timezone.now(),
        }
    
    def validate_token(self, token: str, stored_token_data: Dict) -> bool:
        """
        Validate a password reset token.
        
        Args:
            token: Token to validate
            stored_token_data: Stored token data from database
            
        Returns:
            True if token is valid and not expired, False otherwise
        """
        if not token or not stored_token_data:
            return False
        
        # Check token match
        if token != stored_token_data.get('token'):
            return False
        
        # Check expiration
        expires_at = stored_token_data.get('expires_at')
        if not expires_at or timezone.now() > expires_at:
            return False
        
        return True
    
    def is_token_expired(self, stored_token_data: Dict) -> bool:
        """
        Check if a token is expired.
        
        Args:
            stored_token_data: Stored token data from database
            
        Returns:
            True if token is expired, False otherwise
        """
        expires_at = stored_token_data.get('expires_at')
        if not expires_at:
            return True
        
        return timezone.now() > expires_at


class PasswordPolicyManager:
    """
    Manager for password policies and enforcement.
    
    Handles password policy configuration, validation, and enforcement
    across the enterprise authentication system.
    """
    
    def __init__(self):
        """Initialize password policy manager."""
        self.validator = PasswordStrengthValidator()
        self.hasher = PasswordHasher()
        self.token_generator = PasswordResetTokenGenerator()
    
    def validate_password(self, password: str, user=None) -> Dict:
        """
        Validate password against current policy.
        
        Args:
            password: Password to validate
            user: User object for context
            
        Returns:
            Dictionary with validation results
        """
        is_valid, errors = self.validator.validate(password, user)
        strength = self.validator.get_strength_score(password)
        
        return {
            'is_valid': is_valid,
            'errors': errors,
            'strength': strength,
        }
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using current policy.
        
        Args:
            password: Password to hash
            
        Returns:
            Hashed password
        """
        return self.hasher.hash_password(password)
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plain text password
            hashed_password: Stored hash
            
        Returns:
            True if password is correct
        """
        return self.hasher.verify_password(password, hashed_password)
    
    def create_reset_token(self, user) -> Dict:
        """
        Create password reset token for user.
        
        Args:
            user: User requesting reset
            
        Returns:
            Token data dictionary
        """
        return self.token_generator.create_reset_token_data(user)
    
    def validate_reset_token(self, token: str, stored_data: Dict) -> bool:
        """
        Validate password reset token.
        
        Args:
            token: Token to validate
            stored_data: Stored token data
            
        Returns:
            True if token is valid
        """
        return self.token_generator.validate_token(token, stored_data)
    
    def check_password_history(self, user, new_password: str, history_count: int = 5) -> bool:
        """
        Check if password was used recently.
        
        Args:
            user: User object
            new_password: New password to check
            history_count: Number of previous passwords to check
            
        Returns:
            True if password is acceptable (not in recent history)
        """
        # This would typically check against a password history table
        # For now, we'll implement a basic check
        
        # Check against current password
        if hasattr(user, 'password') and user.password:
            if self.verify_password(new_password, user.password):
                return False
        
        # Additional history checking would be implemented here
        # with a separate PasswordHistory model
        
        return True
    
    def get_policy_info(self) -> Dict:
        """
        Get current password policy information.
        
        Returns:
            Dictionary with policy requirements
        """
        config = self.validator.config
        
        return {
            'min_length': config['min_length'],
            'max_length': config['max_length'],
            'require_uppercase': config['require_uppercase'],
            'require_lowercase': config['require_lowercase'],
            'require_digits': config['require_digits'],
            'require_special_chars': config['require_special_chars'],
            'special_chars': config['special_chars'],
            'max_consecutive_chars': config['max_consecutive_chars'],
            'max_repeated_chars': config['max_repeated_chars'],
            'min_unique_chars': config['min_unique_chars'],
            'entropy_threshold': config['entropy_threshold'],
        }


# Global password policy manager instance
password_policy = PasswordPolicyManager()