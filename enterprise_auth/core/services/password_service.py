"""
Password management service for enterprise authentication system.

This service provides high-level password management functionality including
password changes, resets, validation, and security enforcement.
"""

import logging
from typing import Dict, Optional, Tuple
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from ..models import UserProfile
from ..utils.password import password_policy
from ..utils.encryption import encrypt_sensitive_data, decrypt_sensitive_data
from ..exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    AccountLockedError,
    PasswordPolicyError,
    TokenExpiredError,
    TokenInvalidError,
)

logger = logging.getLogger(__name__)


class PasswordService:
    """
    Service for managing password operations with enterprise security features.
    
    Handles password changes, resets, validation, and security enforcement
    with comprehensive audit logging and threat detection.
    """
    
    def __init__(self):
        """Initialize password service with default settings."""
        self.max_failed_attempts = getattr(settings, 'PASSWORD_MAX_FAILED_ATTEMPTS', 5)
        self.lockout_duration_minutes = getattr(settings, 'PASSWORD_LOCKOUT_DURATION_MINUTES', 30)
        self.reset_token_expiry_hours = getattr(settings, 'PASSWORD_RESET_TOKEN_EXPIRY_HOURS', 1)
        self.password_history_count = getattr(settings, 'PASSWORD_HISTORY_COUNT', 5)
        self.min_password_age_hours = getattr(settings, 'PASSWORD_MIN_AGE_HOURS', 1)
    
    def validate_password_strength(self, password: str, user: Optional[UserProfile] = None) -> Dict:
        """
        Validate password strength against enterprise policies.
        
        Args:
            password: Password to validate
            user: User context for validation
            
        Returns:
            Dictionary with validation results
        """
        return password_policy.validate_password(password, user)
    
    @transaction.atomic
    def change_password(self, user: UserProfile, current_password: str, new_password: str) -> Dict:
        """
        Change user's password with comprehensive security checks.
        
        Args:
            user: User whose password is being changed
            current_password: Current password for verification
            new_password: New password to set
            
        Returns:
            Dictionary with change status and metadata
            
        Raises:
            InvalidCredentialsError: If current password is incorrect
            AccountLockedError: If account is locked
            PasswordPolicyError: If new password doesn't meet policy
        """
        # Check if account is locked
        if user.is_account_locked:
            raise AccountLockedError(
                message=_("Account is temporarily locked due to failed login attempts"),
                locked_until=user.account_locked_until.isoformat() if user.account_locked_until else None
            )
        
        # Verify current password
        if not password_policy.verify_password(current_password, user.password):
            user.increment_failed_login_attempts()
            
            # Lock account if too many failed attempts
            if user.failed_login_attempts >= self.max_failed_attempts:
                user.lock_account(self.lockout_duration_minutes)
                logger.warning(f"Account locked for user {user.email} due to failed password change attempts")
                
                raise AccountLockedError(
                    message=_("Account locked due to too many failed attempts"),
                    locked_until=user.account_locked_until.isoformat()
                )
            
            raise InvalidCredentialsError(_("Current password is incorrect"))
        
        # Check minimum password age
        if user.last_password_change:
            time_since_change = timezone.now() - user.last_password_change
            min_age = timezone.timedelta(hours=self.min_password_age_hours)
            
            if time_since_change < min_age:
                raise PasswordPolicyError(
                    message=_("Password was changed too recently"),
                    details={
                        'min_age_hours': self.min_password_age_hours,
                        'time_remaining_minutes': int((min_age - time_since_change).total_seconds() / 60)
                    }
                )
        
        # Validate new password strength
        validation_result = self.validate_password_strength(new_password, user)
        if not validation_result['is_valid']:
            raise PasswordPolicyError(
                message=_("New password does not meet security requirements"),
                validation_errors=validation_result['errors']
            )
        
        # Check password history
        if not password_policy.check_password_history(user, new_password, self.password_history_count):
            raise PasswordPolicyError(
                message=_("Password was used recently and cannot be reused"),
                details={'history_count': self.password_history_count}
            )
        
        # Check if new password is same as current
        if password_policy.verify_password(new_password, user.password):
            raise PasswordPolicyError(_("New password must be different from current password"))
        
        # Hash and set new password
        hashed_password = password_policy.hash_password(new_password)
        user.password = hashed_password
        user.last_password_change = timezone.now()
        user.reset_failed_login_attempts()
        user.clear_password_reset_token()
        user.save(update_fields=['password', 'last_password_change', 'failed_login_attempts', 
                                'password_reset_token', 'password_reset_sent_at'])
        
        # Log password change
        logger.info(f"Password changed successfully for user {user.email}")
        
        # TODO: Add password history record
        # TODO: Send notification email
        # TODO: Invalidate all sessions except current
        
        return {
            'success': True,
            'message': _('Password changed successfully'),
            'changed_at': user.last_password_change.isoformat(),
            'strength_score': validation_result['strength']['score']
        }
    
    @transaction.atomic
    def initiate_password_reset(self, email: str) -> Dict:
        """
        Initiate password reset workflow for a user.
        
        Args:
            email: Email address of user requesting reset
            
        Returns:
            Dictionary with reset initiation status
            
        Raises:
            ValidationError: If email is invalid or user not found
        """
        try:
            user = UserProfile.objects.get(email=email, is_deleted=False)
        except UserProfile.DoesNotExist:
            # Don't reveal if email exists or not for security
            logger.warning(f"Password reset requested for non-existent email: {email}")
            return {
                'success': True,
                'message': _('If the email address exists, a reset link has been sent'),
                'email_sent': False
            }
        
        # Check if account is active
        if not user.is_active:
            logger.warning(f"Password reset requested for inactive user: {email}")
            return {
                'success': True,
                'message': _('If the email address exists, a reset link has been sent'),
                'email_sent': False
            }
        
        # Check rate limiting for password reset requests
        if user.password_reset_sent_at:
            time_since_last = timezone.now() - user.password_reset_sent_at
            min_interval = timezone.timedelta(minutes=5)  # 5 minute cooldown
            
            if time_since_last < min_interval:
                logger.warning(f"Password reset rate limited for user: {email}")
                return {
                    'success': False,
                    'message': _('Please wait before requesting another password reset'),
                    'retry_after_minutes': int((min_interval - time_since_last).total_seconds() / 60)
                }
        
        # Generate reset token
        token_data = password_policy.create_reset_token(user)
        user.set_password_reset_token(token_data['token'])
        
        # Send reset email asynchronously
        from ..tasks.email_tasks import send_password_reset_email
        send_password_reset_email.delay(str(user.id), token_data['token'])
        
        logger.info(f"Password reset initiated for user: {email}")
        
        return {
            'success': True,
            'message': _('If the email address exists, a reset link has been sent'),
            'email_sent': True,
            'expires_at': token_data['expires_at'].isoformat()
        }
    
    @transaction.atomic
    def reset_password(self, token: str, new_password: str) -> Dict:
        """
        Reset user's password using a valid reset token.
        
        Args:
            token: Password reset token
            new_password: New password to set
            
        Returns:
            Dictionary with reset status
            
        Raises:
            TokenInvalidError: If token is invalid
            TokenExpiredError: If token is expired
            PasswordPolicyError: If new password doesn't meet policy
        """
        # Find user with this token
        users_with_token = UserProfile.objects.filter(
            password_reset_token__isnull=False,
            is_deleted=False,
            is_active=True
        )
        
        user = None
        for candidate_user in users_with_token:
            if candidate_user.verify_password_reset_token(token):
                user = candidate_user
                break
        
        if not user:
            raise TokenInvalidError(_("Invalid or expired password reset token"))
        
        # Validate new password strength
        validation_result = self.validate_password_strength(new_password, user)
        if not validation_result['is_valid']:
            raise PasswordPolicyError(
                message=_("New password does not meet security requirements"),
                validation_errors=validation_result['errors']
            )
        
        # Check password history
        if not password_policy.check_password_history(user, new_password, self.password_history_count):
            raise PasswordPolicyError(
                message=_("Password was used recently and cannot be reused"),
                details={'history_count': self.password_history_count}
            )
        
        # Hash and set new password
        hashed_password = password_policy.hash_password(new_password)
        user.password = hashed_password
        user.clear_password_reset_token()
        user.reset_failed_login_attempts()
        user.unlock_account()  # Unlock account if it was locked
        user.save(update_fields=['password', 'last_password_change', 'password_reset_token', 
                                'password_reset_sent_at', 'failed_login_attempts', 'account_locked_until'])
        
        # Log password reset
        logger.info(f"Password reset completed for user {user.email}")
        
        # TODO: Add password history record
        # TODO: Send confirmation email
        # TODO: Invalidate all sessions
        
        return {
            'success': True,
            'message': _('Password reset successfully'),
            'user_id': str(user.id),
            'reset_at': timezone.now().isoformat(),
            'strength_score': validation_result['strength']['score']
        }
    
    def validate_reset_token(self, token: str) -> Dict:
        """
        Validate a password reset token without consuming it.
        
        Args:
            token: Password reset token to validate
            
        Returns:
            Dictionary with validation status
        """
        # Find user with this token
        users_with_token = UserProfile.objects.filter(
            password_reset_token__isnull=False,
            is_deleted=False,
            is_active=True
        )
        
        for user in users_with_token:
            if user.verify_password_reset_token(token):
                return {
                    'valid': True,
                    'user_email': user.email,
                    'expires_at': (user.password_reset_sent_at + 
                                 timezone.timedelta(hours=self.reset_token_expiry_hours)).isoformat()
                }
        
        return {
            'valid': False,
            'message': _('Invalid or expired token')
        }
    
    def get_password_policy_info(self) -> Dict:
        """
        Get current password policy information for client applications.
        
        Returns:
            Dictionary with password policy requirements
        """
        return password_policy.get_policy_info()
    
    def check_password_strength(self, password: str, user: Optional[UserProfile] = None) -> Dict:
        """
        Check password strength without validation (for real-time feedback).
        
        Args:
            password: Password to analyze
            user: User context for analysis
            
        Returns:
            Dictionary with strength analysis
        """
        validation_result = password_policy.validate_password(password, user)
        
        return {
            'strength': validation_result['strength'],
            'is_valid': validation_result['is_valid'],
            'feedback': validation_result['errors'] if validation_result['errors'] else []
        }