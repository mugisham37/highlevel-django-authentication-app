"""
Email tasks for enterprise authentication system.

This module contains Celery tasks for sending various types of emails
including verification emails, password reset emails, and notifications.
"""

import logging
from typing import Optional

from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.translation import gettext as _

from ..models import UserProfile

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_verification_email(self, user_id: str, token: str) -> bool:
    """
    Send email verification email to user.
    
    Args:
        user_id: User's ID
        token: Verification token
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        # Get user
        user = UserProfile.objects.get(id=user_id)
        
        # Prepare email context
        context = {
            'user': user,
            'token': token,
            'verification_url': f"{settings.FRONTEND_URL}/verify-email?user_id={user_id}&token={token}",
            'site_name': getattr(settings, 'SITE_NAME', 'Enterprise Auth'),
            'support_email': getattr(settings, 'SUPPORT_EMAIL', settings.DEFAULT_FROM_EMAIL),
        }
        
        # Render email templates
        subject = _('Verify your email address')
        html_message = render_to_string('emails/verification_email.html', context)
        plain_message = strip_tags(html_message)
        
        # Send email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Verification email sent successfully to {user.email}")
        return True
        
    except UserProfile.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return False
        
    except Exception as exc:
        logger.error(f"Failed to send verification email to user {user_id}: {exc}")
        
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        
        return False


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_password_reset_email(self, user_id: str, token: str) -> bool:
    """
    Send password reset email to user.
    
    Args:
        user_id: User's ID
        token: Password reset token
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        # Get user
        user = UserProfile.objects.get(id=user_id)
        
        # Prepare email context
        context = {
            'user': user,
            'token': token,
            'reset_url': f"{settings.FRONTEND_URL}/reset-password?user_id={user_id}&token={token}",
            'site_name': getattr(settings, 'SITE_NAME', 'Enterprise Auth'),
            'support_email': getattr(settings, 'SUPPORT_EMAIL', settings.DEFAULT_FROM_EMAIL),
        }
        
        # Render email templates
        subject = _('Reset your password')
        html_message = render_to_string('emails/password_reset_email.html', context)
        plain_message = strip_tags(html_message)
        
        # Send email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Password reset email sent successfully to {user.email}")
        return True
        
    except UserProfile.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return False
        
    except Exception as exc:
        logger.error(f"Failed to send password reset email to user {user_id}: {exc}")
        
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        
        return False


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_welcome_email(self, user_id: str) -> bool:
    """
    Send welcome email to newly verified user.
    
    Args:
        user_id: User's ID
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        # Get user
        user = UserProfile.objects.get(id=user_id)
        
        # Only send if email is verified
        if not user.is_email_verified:
            logger.warning(f"Attempted to send welcome email to unverified user {user.email}")
            return False
        
        # Prepare email context
        context = {
            'user': user,
            'site_name': getattr(settings, 'SITE_NAME', 'Enterprise Auth'),
            'dashboard_url': f"{settings.FRONTEND_URL}/dashboard",
            'support_email': getattr(settings, 'SUPPORT_EMAIL', settings.DEFAULT_FROM_EMAIL),
        }
        
        # Render email templates
        subject = _('Welcome to Enterprise Auth!')
        html_message = render_to_string('emails/welcome_email.html', context)
        plain_message = strip_tags(html_message)
        
        # Send email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Welcome email sent successfully to {user.email}")
        return True
        
    except UserProfile.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return False
        
    except Exception as exc:
        logger.error(f"Failed to send welcome email to user {user_id}: {exc}")
        
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        
        return False


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_security_alert_email(
    self, 
    user_id: str, 
    alert_type: str, 
    context_data: Optional[dict] = None
) -> bool:
    """
    Send security alert email to user.
    
    Args:
        user_id: User's ID
        alert_type: Type of security alert
        context_data: Additional context data for the alert
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        # Get user
        user = UserProfile.objects.get(id=user_id)
        
        # Prepare email context
        context = {
            'user': user,
            'alert_type': alert_type,
            'context_data': context_data or {},
            'site_name': getattr(settings, 'SITE_NAME', 'Enterprise Auth'),
            'support_email': getattr(settings, 'SUPPORT_EMAIL', settings.DEFAULT_FROM_EMAIL),
            'security_url': f"{settings.FRONTEND_URL}/security",
        }
        
        # Determine subject based on alert type
        subject_map = {
            'login_from_new_device': _('New device login detected'),
            'password_changed': _('Password changed successfully'),
            'account_locked': _('Account temporarily locked'),
            'suspicious_activity': _('Suspicious activity detected'),
            'mfa_enabled': _('Multi-factor authentication enabled'),
            'mfa_disabled': _('Multi-factor authentication disabled'),
        }
        
        subject = subject_map.get(alert_type, _('Security alert'))
        
        # Render email templates
        html_message = render_to_string('emails/security_alert_email.html', context)
        plain_message = strip_tags(html_message)
        
        # Send email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Security alert email ({alert_type}) sent successfully to {user.email}")
        return True
        
    except UserProfile.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return False
        
    except Exception as exc:
        logger.error(f"Failed to send security alert email to user {user_id}: {exc}")
        
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        
        return False


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_social_linking_verification_email(
    self, 
    user_id: str, 
    provider_name: str, 
    linking_token: str,
    provider_email: str = '',
    provider_username: str = ''
) -> bool:
    """
    Send social account linking verification email to user.
    
    Args:
        user_id: User's ID
        provider_name: OAuth provider name
        linking_token: Linking verification token
        provider_email: Email from OAuth provider
        provider_username: Username from OAuth provider
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        # Get user
        user = UserProfile.objects.get(id=user_id)
        
        # Prepare email context
        context = {
            'user': user,
            'provider_name': provider_name.title(),
            'provider_email': provider_email,
            'provider_username': provider_username,
            'linking_token': linking_token,
            'verification_url': f"{settings.FRONTEND_URL}/verify-social-linking?user_id={user_id}&token={linking_token}",
            'site_name': getattr(settings, 'SITE_NAME', 'Enterprise Auth'),
            'support_email': getattr(settings, 'SUPPORT_EMAIL', settings.DEFAULT_FROM_EMAIL),
        }
        
        # Render email templates
        subject = _('Verify social account linking')
        html_message = render_to_string('emails/social_linking_verification_email.html', context)
        plain_message = strip_tags(html_message)
        
        # Send email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Social linking verification email sent successfully to {user.email} for {provider_name}")
        return True
        
    except UserProfile.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return False
        
    except Exception as exc:
        logger.error(f"Failed to send social linking verification email to user {user_id}: {exc}")
        
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        
        return False


@shared_task
def cleanup_unverified_users() -> int:
    """
    Clean up unverified user accounts older than 7 days.
    
    Returns:
        Number of accounts cleaned up
    """
    try:
        count = UserProfile.objects.cleanup_unverified_users(days=7)
        logger.info(f"Cleaned up {count} unverified user accounts")
        return count
        
    except Exception as exc:
        logger.error(f"Failed to cleanup unverified users: {exc}")
        return 0


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_mfa_verification_email(
    self,
    user_id: str,
    device_id: str,
    email_address: str,
    verification_code: str,
    purpose: str = 'verification'
) -> bool:
    """
    Send MFA verification email to user.
    
    Args:
        user_id: User's ID
        device_id: MFA device ID
        email_address: Email address to send to
        verification_code: Verification code
        purpose: Purpose of the email (setup, verification, resend)
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        # Get user and device
        user = UserProfile.objects.get(id=user_id)
        
        # Import here to avoid circular imports
        from ..models import MFADevice
        device = MFADevice.objects.get(id=device_id)
        
        # Determine subject and message based on purpose
        if purpose == 'setup':
            subject = _('Set up your email authentication')
            message_intro = _('You are setting up email-based multi-factor authentication.')
        elif purpose == 'resend':
            subject = _('Your new verification code')
            message_intro = _('Here is your new verification code.')
        else:
            subject = _('Your verification code')
            message_intro = _('Please use this code to complete your authentication.')
        
        # Prepare email context
        context = {
            'user': user,
            'device': device,
            'verification_code': verification_code,
            'purpose': purpose,
            'message_intro': message_intro,
            'expires_in_minutes': getattr(settings, 'MFA_EMAIL_CODE_EXPIRY_MINUTES', 10),
            'site_name': getattr(settings, 'SITE_NAME', 'Enterprise Auth'),
            'support_email': getattr(settings, 'SUPPORT_EMAIL', settings.DEFAULT_FROM_EMAIL),
            'security_url': f"{getattr(settings, 'FRONTEND_URL', '')}/security",
        }
        
        # Render email templates
        html_message = render_to_string('emails/mfa_verification_email.html', context)
        plain_message = strip_tags(html_message)
        
        # Send email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email_address],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"MFA verification email sent successfully to {email_address} for user {user.email}")
        return True
        
    except UserProfile.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return False
        
    except Exception as exc:
        logger.error(f"Failed to send MFA verification email to {email_address}: {exc}")
        
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        
        return False


@shared_task
def send_bulk_notification_email(
    user_ids: list, 
    subject: str, 
    template_name: str, 
    context_data: dict
) -> dict:
    """
    Send bulk notification emails to multiple users.
    
    Args:
        user_ids: List of user IDs
        subject: Email subject
        template_name: Template name for the email
        context_data: Context data for the template
        
    Returns:
        Dictionary with success and failure counts
    """
    success_count = 0
    failure_count = 0
    
    for user_id in user_ids:
        try:
            user = UserProfile.objects.get(id=user_id)
            
            # Prepare email context
            context = {
                'user': user,
                'site_name': getattr(settings, 'SITE_NAME', 'Enterprise Auth'),
                'support_email': getattr(settings, 'SUPPORT_EMAIL', settings.DEFAULT_FROM_EMAIL),
                **context_data
            }
            
            # Render email templates
            html_message = render_to_string(f'emails/{template_name}.html', context)
            plain_message = strip_tags(html_message)
            
            # Send email
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )
            
            success_count += 1
            
        except UserProfile.DoesNotExist:
            logger.error(f"User with ID {user_id} not found")
            failure_count += 1
            
        except Exception as exc:
            logger.error(f"Failed to send bulk email to user {user_id}: {exc}")
            failure_count += 1
    
    logger.info(f"Bulk email sent: {success_count} successful, {failure_count} failed")
    
    return {
        'success_count': success_count,
        'failure_count': failure_count,
        'total_count': len(user_ids)
    }