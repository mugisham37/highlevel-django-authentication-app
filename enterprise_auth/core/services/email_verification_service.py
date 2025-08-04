"""
Email verification service for enterprise authentication system.

This service provides comprehensive email verification functionality including
token generation, validation, resending, and security features.
"""

import logging
import secrets
from typing import Dict, Optional, Tuple
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from ..models import UserProfile
from ..utils.encryption import encrypt_sensitive_data, decrypt_sensitive_data
from ..exceptions import (
    AuthenticationError,
    TokenExpiredError,
    TokenInvalidError,
    RateLimitExceededError,
)

logger = logging.getLogger(__name__)


class EmailVerificationService:
    """
    Service for managing email verification operations with enterprise security features.
    
    Handles email verification token generation, validation, resending,
    and comprehensive audit logging.
    """
    
    def __init__(self):
        """Initialize email verification service with default settings."""
        self.token_expiry_hours = getattr(settings, 'EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS', 24)
        self.resend_cooldown_minutes = getattr(settings, 'EMAIL_VERIFICATION_RESEND_COOLDOWN_MINUTES', 5)
        self.max_resend_attempts = getattr(settings, 'EMAIL_VERIFICATION_MAX_RESEND_ATTEMPTS', 5)
        self.token_length = getattr(settings, 'EMAIL_VERIFICATION_TOKEN_LENGTH', 64)
    
    def generate_verification_token(self) -> str:
        """
        Generate a cryptographically secure verification token.
        
        Returns:
            Secure random token string
        """
        return secrets.token_urlsafe(self.token_length)
    
    @transaction.atomic
    def send_verification_email(self, user: UserProfile, resend: bool = False) -> Dict:
        """
        Send email verification email to user.
        
        Args:
            user: User to send verification email to
            resend: Whether this is a resend request
            
        Returns:
            Dictionary with send status and metadata
            
        Raises:
            RateLimitExceededError: If resend rate limit is exceeded
            ValidationError: If user is already verified or invalid
        """
        # Check if user is already verified
        if user.is_email_verified:
            logger.warning(f"Attempted to send verification email to already verified user: {user.email}")
            return {
                'success': False,
                'message': _('Email address is already verified'),
                'status': 'already_verified'
            }
        
        # Check if user account is active
        if not user.is_active:
            logger.warning(f"Attempted to send verification email to inactive user: {user.email}")
            return {
                'success': False,
                'message': _('Account is not active'),
                'status': 'account_inactive'
            }
        
        # Check rate limiting for resend requests
        if resend and user.email_verification_sent_at:
            time_since_last = timezone.now() - user.email_verification_sent_at
            cooldown = timezone.timedelta(minutes=self.resend_cooldown_minutes)
            
            if time_since_last < cooldown:
                remaining_minutes = int((cooldown - time_since_last).total_seconds() / 60)
                logger.warning(f"Email verification resend rate limited for user: {user.email}")
                
                raise RateLimitExceededError(
                    message=_('Please wait before requesting another verification email'),
                    retry_after_minutes=remaining_minutes
                )
        
        # Generate new verification token
        token = self.generate_verification_token()
        
        # Set token on user (encrypted)
        user.set_email_verification_token(token)
        
        # Send verification email asynchronously
        from ..tasks.email_tasks import send_verification_email
        task_result = send_verification_email.delay(str(user.id), token)
        
        # Log verification email sent
        logger.info(f"Email verification {'resent' if resend else 'sent'} for user: {user.email}")
        
        # Calculate expiry time
        expires_at = timezone.now() + timezone.timedelta(hours=self.token_expiry_hours)
        
        return {
            'success': True,
            'message': _('Verification email sent successfully. Please check your inbox.'),
            'status': 'sent',
            'expires_at': expires_at.isoformat(),
            'task_id': task_result.id,
            'resend': resend
        }
    
    @transaction.atomic
    def verify_email(self, user_id: str, token: str) -> Dict:
        """
        Verify user's email address using verification token.
        
        Args:
            user_id: User's ID
            token: Verification token
            
        Returns:
            Dictionary with verification status
            
        Raises:
            TokenInvalidError: If token is invalid
            TokenExpiredError: If token is expired
        """
        try:
            # Get user
            user = UserProfile.objects.get(id=user_id, is_deleted=False)
        except UserProfile.DoesNotExist:
            logger.warning(f"Email verification attempted for non-existent user: {user_id}")
            raise TokenInvalidError(_("Invalid verification token"))
        
        # Check if already verified
        if user.is_email_verified:
            logger.info(f"Email verification attempted for already verified user: {user.email}")
            return {
                'success': True,
                'message': _('Email address is already verified'),
                'status': 'already_verified',
                'user_id': str(user.id),
                'verified_at': user.updated_at.isoformat() if user.updated_at else None
            }
        
        # Verify token
        if not user.verify_email_token(token):
            logger.warning(f"Invalid email verification token for user: {user.email}")
            raise TokenInvalidError(_("Invalid or expired verification token"))
        
        # Mark email as verified
        user.mark_email_verified()
        
        # Send welcome email asynchronously
        from ..tasks.email_tasks import send_welcome_email
        send_welcome_email.delay(str(user.id))
        
        # Log successful verification
        logger.info(f"Email verified successfully for user: {user.email}")
        
        return {
            'success': True,
            'message': _('Email verified successfully. Your account is now active.'),
            'status': 'verified',
            'user_id': str(user.id),
            'verified_at': timezone.now().isoformat()
        }
    
    def resend_verification_email(self, email: str) -> Dict:
        """
        Resend verification email to user.
        
        Args:
            email: Email address to resend verification to
            
        Returns:
            Dictionary with resend status
            
        Raises:
            RateLimitExceededError: If resend rate limit is exceeded
        """
        try:
            # Get user by email
            user = UserProfile.objects.get(
                email=email.lower().strip(),
                is_deleted=False,
                is_active=True
            )
        except UserProfile.DoesNotExist:
            # Don't reveal if email exists or not for security
            logger.warning(f"Verification resend requested for non-existent email: {email}")
            return {
                'success': True,
                'message': _('If the email address exists and is unverified, a verification email has been sent.'),
                'status': 'sent',
                'email_sent': False
            }
        
        # Check if already verified
        if user.is_email_verified:
            logger.info(f"Verification resend requested for already verified user: {email}")
            return {
                'success': True,
                'message': _('If the email address exists and is unverified, a verification email has been sent.'),
                'status': 'already_verified',
                'email_sent': False
            }
        
        try:
            # Send verification email
            result = self.send_verification_email(user, resend=True)
            
            return {
                'success': result['success'],
                'message': result['message'],
                'status': result['status'],
                'expires_at': result.get('expires_at'),
                'email_sent': result['success']
            }
            
        except RateLimitExceededError as e:
            return {
                'success': False,
                'message': str(e),
                'status': 'rate_limited',
                'retry_after_minutes': e.details.get('retry_after_minutes'),
                'email_sent': False
            }
    
    def validate_verification_token(self, user_id: str, token: str) -> Dict:
        """
        Validate verification token without consuming it.
        
        Args:
            user_id: User's ID
            token: Verification token to validate
            
        Returns:
            Dictionary with validation status
        """
        try:
            # Get user
            user = UserProfile.objects.get(id=user_id, is_deleted=False)
        except UserProfile.DoesNotExist:
            return {
                'valid': False,
                'message': _('Invalid token'),
                'status': 'invalid_user'
            }
        
        # Check if already verified
        if user.is_email_verified:
            return {
                'valid': False,
                'message': _('Email address is already verified'),
                'status': 'already_verified'
            }
        
        # Validate token
        if user.verify_email_token(token):
            expires_at = None
            if user.email_verification_sent_at:
                expires_at = (user.email_verification_sent_at + 
                            timezone.timedelta(hours=self.token_expiry_hours)).isoformat()
            
            return {
                'valid': True,
                'user_email': user.email,
                'expires_at': expires_at,
                'status': 'valid'
            }
        else:
            return {
                'valid': False,
                'message': _('Invalid or expired token'),
                'status': 'invalid_token'
            }
    
    def get_verification_status(self, user: UserProfile) -> Dict:
        """
        Get email verification status for a user.
        
        Args:
            user: User to check verification status for
            
        Returns:
            Dictionary with verification status information
        """
        status_info = {
            'user_id': str(user.id),
            'email': user.email,
            'is_verified': user.is_email_verified,
            'verification_sent_at': user.email_verification_sent_at.isoformat() if user.email_verification_sent_at else None,
            'can_resend': True,
            'resend_cooldown_minutes': self.resend_cooldown_minutes,
            'token_expiry_hours': self.token_expiry_hours
        }
        
        # Check if resend is available (not rate limited)
        if user.email_verification_sent_at:
            time_since_last = timezone.now() - user.email_verification_sent_at
            cooldown = timezone.timedelta(minutes=self.resend_cooldown_minutes)
            
            if time_since_last < cooldown:
                status_info['can_resend'] = False
                status_info['resend_available_at'] = (
                    user.email_verification_sent_at + cooldown
                ).isoformat()
                status_info['minutes_until_resend'] = int(
                    (cooldown - time_since_last).total_seconds() / 60
                )
        
        # Check if token is expired
        if user.email_verification_sent_at and not user.is_email_verified:
            expiry_time = user.email_verification_sent_at + timezone.timedelta(hours=self.token_expiry_hours)
            status_info['token_expires_at'] = expiry_time.isoformat()
            status_info['is_token_expired'] = timezone.now() > expiry_time
        
        return status_info
    
    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired verification tokens.
        
        Returns:
            Number of tokens cleaned up
        """
        try:
            # Calculate cutoff time
            cutoff_time = timezone.now() - timezone.timedelta(hours=self.token_expiry_hours)
            
            # Find users with expired tokens
            users_with_expired_tokens = UserProfile.objects.filter(
                email_verification_token__isnull=False,
                email_verification_sent_at__lt=cutoff_time,
                is_email_verified=False,
                is_deleted=False
            )
            
            count = 0
            for user in users_with_expired_tokens:
                user.email_verification_token = None
                user.email_verification_sent_at = None
                user.save(update_fields=['email_verification_token', 'email_verification_sent_at'])
                count += 1
            
            logger.info(f"Cleaned up {count} expired email verification tokens")
            return count
            
        except Exception as exc:
            logger.error(f"Failed to cleanup expired verification tokens: {exc}")
            return 0
    
    def get_verification_statistics(self) -> Dict:
        """
        Get email verification statistics for monitoring.
        
        Returns:
            Dictionary with verification statistics
        """
        try:
            from django.db.models import Count, Q
            
            # Get verification statistics
            stats = UserProfile.objects.aggregate(
                total_users=Count('id', filter=Q(is_deleted=False)),
                verified_users=Count('id', filter=Q(is_email_verified=True, is_deleted=False)),
                unverified_users=Count('id', filter=Q(is_email_verified=False, is_deleted=False)),
                pending_verification=Count('id', filter=Q(
                    email_verification_token__isnull=False,
                    is_email_verified=False,
                    is_deleted=False
                ))
            )
            
            # Calculate verification rate
            verification_rate = 0.0
            if stats['total_users'] > 0:
                verification_rate = (stats['verified_users'] / stats['total_users']) * 100
            
            return {
                'total_users': stats['total_users'],
                'verified_users': stats['verified_users'],
                'unverified_users': stats['unverified_users'],
                'pending_verification': stats['pending_verification'],
                'verification_rate_percent': round(verification_rate, 2),
                'token_expiry_hours': self.token_expiry_hours,
                'resend_cooldown_minutes': self.resend_cooldown_minutes,
                'generated_at': timezone.now().isoformat()
            }
            
        except Exception as exc:
            logger.error(f"Failed to generate verification statistics: {exc}")
            return {
                'error': 'Failed to generate statistics',
                'generated_at': timezone.now().isoformat()
            }