"""
API Signals

Django signals for triggering webhook events and API logging.
"""
import logging
from typing import Dict, Any, Optional
from django.db.models.signals import post_save, post_delete, pre_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.utils import timezone

from .models import WebhookEventType
from .tasks import queue_webhook_delivery

User = get_user_model()
logger = logging.getLogger(__name__)


def trigger_webhook_event(
    event_type: str,
    event_data: Dict[str, Any],
    user_id: Optional[str] = None,
    organization: Optional[str] = None
):
    """
    Trigger a webhook event asynchronously.
    
    Args:
        event_type: Type of event from WebhookEventType
        event_data: Event payload data
        user_id: Optional user ID associated with the event
        organization: Optional organization filter
    """
    try:
        # Queue webhook delivery task
        queue_webhook_delivery.delay(
            event_type=event_type,
            event_data=event_data,
            user_id=user_id,
            organization=organization
        )
        
        logger.info(f"Webhook event queued: {event_type}")
        
    except Exception as e:
        logger.error(f"Failed to queue webhook event {event_type}: {str(e)}")


# User-related webhook events
@receiver(post_save, sender=User)
def user_created_or_updated(sender, instance, created, **kwargs):
    """Trigger webhook when user is created or updated."""
    try:
        event_data = {
            'user_id': str(instance.id),
            'email': instance.email,
            'first_name': instance.first_name,
            'last_name': instance.last_name,
            'organization': getattr(instance, 'organization', None),
            'department': getattr(instance, 'department', None),
            'is_email_verified': getattr(instance, 'is_email_verified', False),
            'timestamp': timezone.now().isoformat()
        }
        
        if created:
            trigger_webhook_event(
                event_type=WebhookEventType.USER_CREATED,
                event_data=event_data,
                user_id=str(instance.id),
                organization=getattr(instance, 'organization', None)
            )
        else:
            trigger_webhook_event(
                event_type=WebhookEventType.USER_UPDATED,
                event_data=event_data,
                user_id=str(instance.id),
                organization=getattr(instance, 'organization', None)
            )
            
    except Exception as e:
        logger.error(f"Failed to trigger user webhook: {str(e)}")


@receiver(pre_delete, sender=User)
def user_deleted(sender, instance, **kwargs):
    """Trigger webhook when user is deleted."""
    try:
        event_data = {
            'user_id': str(instance.id),
            'email': instance.email,
            'first_name': instance.first_name,
            'last_name': instance.last_name,
            'organization': getattr(instance, 'organization', None),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.USER_DELETED,
            event_data=event_data,
            user_id=str(instance.id),
            organization=getattr(instance, 'organization', None)
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger user deletion webhook: {str(e)}")


# Session-related webhook events
def trigger_session_created_event(session_data: Dict[str, Any]):
    """Trigger session created webhook event."""
    try:
        event_data = {
            'session_id': session_data.get('session_id'),
            'user_id': session_data.get('user_id'),
            'device_type': session_data.get('device_type'),
            'ip_address': session_data.get('ip_address'),
            'location': {
                'country': session_data.get('country'),
                'city': session_data.get('city')
            },
            'login_method': session_data.get('login_method'),
            'risk_score': session_data.get('risk_score', 0.0),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.SESSION_CREATED,
            event_data=event_data,
            user_id=session_data.get('user_id'),
            organization=session_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger session created webhook: {str(e)}")


def trigger_session_terminated_event(session_data: Dict[str, Any]):
    """Trigger session terminated webhook event."""
    try:
        event_data = {
            'session_id': session_data.get('session_id'),
            'user_id': session_data.get('user_id'),
            'termination_reason': session_data.get('termination_reason', 'user_logout'),
            'duration_minutes': session_data.get('duration_minutes'),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.SESSION_TERMINATED,
            event_data=event_data,
            user_id=session_data.get('user_id'),
            organization=session_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger session terminated webhook: {str(e)}")


# Authentication-related webhook events
def trigger_user_login_event(user_id: str, login_data: Dict[str, Any]):
    """Trigger user login webhook event."""
    try:
        event_data = {
            'user_id': user_id,
            'login_method': login_data.get('login_method', 'password'),
            'ip_address': login_data.get('ip_address'),
            'user_agent': login_data.get('user_agent'),
            'device_type': login_data.get('device_type'),
            'location': {
                'country': login_data.get('country'),
                'city': login_data.get('city')
            },
            'mfa_used': login_data.get('mfa_used', False),
            'risk_score': login_data.get('risk_score', 0.0),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.USER_LOGIN,
            event_data=event_data,
            user_id=user_id,
            organization=login_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger user login webhook: {str(e)}")


def trigger_user_logout_event(user_id: str, logout_data: Dict[str, Any]):
    """Trigger user logout webhook event."""
    try:
        event_data = {
            'user_id': user_id,
            'session_id': logout_data.get('session_id'),
            'logout_method': logout_data.get('logout_method', 'manual'),
            'session_duration_minutes': logout_data.get('session_duration_minutes'),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.USER_LOGOUT,
            event_data=event_data,
            user_id=user_id,
            organization=logout_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger user logout webhook: {str(e)}")


# Security-related webhook events
def trigger_security_alert_event(alert_data: Dict[str, Any]):
    """Trigger security alert webhook event."""
    try:
        event_data = {
            'alert_type': alert_data.get('alert_type'),
            'severity': alert_data.get('severity', 'medium'),
            'user_id': alert_data.get('user_id'),
            'ip_address': alert_data.get('ip_address'),
            'description': alert_data.get('description'),
            'threat_indicators': alert_data.get('threat_indicators', []),
            'risk_score': alert_data.get('risk_score', 0.0),
            'response_taken': alert_data.get('response_taken', False),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.SECURITY_ALERT,
            event_data=event_data,
            user_id=alert_data.get('user_id'),
            organization=alert_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger security alert webhook: {str(e)}")


# MFA-related webhook events
def trigger_mfa_enabled_event(user_id: str, mfa_data: Dict[str, Any]):
    """Trigger MFA enabled webhook event."""
    try:
        event_data = {
            'user_id': user_id,
            'mfa_method': mfa_data.get('mfa_method', 'totp'),
            'device_name': mfa_data.get('device_name'),
            'backup_codes_generated': mfa_data.get('backup_codes_generated', False),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.USER_MFA_ENABLED,
            event_data=event_data,
            user_id=user_id,
            organization=mfa_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger MFA enabled webhook: {str(e)}")


def trigger_mfa_disabled_event(user_id: str, mfa_data: Dict[str, Any]):
    """Trigger MFA disabled webhook event."""
    try:
        event_data = {
            'user_id': user_id,
            'mfa_method': mfa_data.get('mfa_method', 'totp'),
            'disabled_by': mfa_data.get('disabled_by', 'user'),
            'reason': mfa_data.get('reason', 'user_request'),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.USER_MFA_DISABLED,
            event_data=event_data,
            user_id=user_id,
            organization=mfa_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger MFA disabled webhook: {str(e)}")


# Password-related webhook events
def trigger_password_changed_event(user_id: str, password_data: Dict[str, Any]):
    """Trigger password changed webhook event."""
    try:
        event_data = {
            'user_id': user_id,
            'change_method': password_data.get('change_method', 'user_initiated'),
            'ip_address': password_data.get('ip_address'),
            'user_agent': password_data.get('user_agent'),
            'forced_change': password_data.get('forced_change', False),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.USER_PASSWORD_CHANGED,
            event_data=event_data,
            user_id=user_id,
            organization=password_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger password changed webhook: {str(e)}")


# Email verification webhook events
def trigger_email_verified_event(user_id: str, verification_data: Dict[str, Any]):
    """Trigger email verified webhook event."""
    try:
        event_data = {
            'user_id': user_id,
            'email': verification_data.get('email'),
            'verification_method': verification_data.get('verification_method', 'email_link'),
            'ip_address': verification_data.get('ip_address'),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.USER_EMAIL_VERIFIED,
            event_data=event_data,
            user_id=user_id,
            organization=verification_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger email verified webhook: {str(e)}")


# Role-related webhook events
def trigger_role_assigned_event(user_id: str, role_data: Dict[str, Any]):
    """Trigger role assigned webhook event."""
    try:
        event_data = {
            'user_id': user_id,
            'role_name': role_data.get('role_name'),
            'role_id': role_data.get('role_id'),
            'assigned_by': role_data.get('assigned_by'),
            'permissions': role_data.get('permissions', []),
            'expires_at': role_data.get('expires_at'),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.ROLE_ASSIGNED,
            event_data=event_data,
            user_id=user_id,
            organization=role_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger role assigned webhook: {str(e)}")


def trigger_role_revoked_event(user_id: str, role_data: Dict[str, Any]):
    """Trigger role revoked webhook event."""
    try:
        event_data = {
            'user_id': user_id,
            'role_name': role_data.get('role_name'),
            'role_id': role_data.get('role_id'),
            'revoked_by': role_data.get('revoked_by'),
            'reason': role_data.get('reason', 'manual'),
            'timestamp': timezone.now().isoformat()
        }
        
        trigger_webhook_event(
            event_type=WebhookEventType.ROLE_REVOKED,
            event_data=event_data,
            user_id=user_id,
            organization=role_data.get('organization')
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger role revoked webhook: {str(e)}")


# Utility functions for external use
def send_webhook_event(event_type: str, event_data: Dict[str, Any], user_id: Optional[str] = None, organization: Optional[str] = None):
    """
    Public function to send webhook events from other parts of the application.
    
    Args:
        event_type: Event type from WebhookEventType
        event_data: Event payload data
        user_id: Optional user ID
        organization: Optional organization
    """
    trigger_webhook_event(event_type, event_data, user_id, organization)