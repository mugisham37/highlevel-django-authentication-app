"""
Celery tasks for SMS delivery and processing.

This module provides asynchronous tasks for SMS operations including
code delivery, status tracking, and retry logic with Twilio integration.
"""

import logging
from typing import Dict, Any, Optional
from celery import shared_task
from celery.exceptions import Retry
from django.conf import settings
from django.utils import timezone

from twilio.rest import Client as TwilioClient
from twilio.base.exceptions import TwilioException

from ..models import UserProfile, MFADevice
from ..services.audit_service import AuditService

logger = logging.getLogger(__name__)


@shared_task(
    bind=True,
    autoretry_for=(TwilioException,),
    retry_kwargs={'max_retries': 3, 'countdown': 30},
    retry_backoff=True,
    retry_jitter=True
)
def send_sms_code_async(
    self,
    device_id: str,
    phone_number: str,
    verification_code: str,
    purpose: str = 'verification',
    user_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Send SMS verification code asynchronously with retry logic.
    
    Args:
        device_id: MFA device ID
        phone_number: Phone number to send to
        verification_code: Verification code
        purpose: Purpose of the SMS (setup, verification, resend)
        user_id: User ID for logging purposes
        
    Returns:
        Dictionary containing delivery result
        
    Raises:
        Retry: If delivery fails and retries are available
    """
    audit_service = AuditService()
    
    try:
        # Initialize Twilio client
        if not all([
            getattr(settings, 'TWILIO_ACCOUNT_SID', None),
            getattr(settings, 'TWILIO_AUTH_TOKEN', None),
            getattr(settings, 'TWILIO_PHONE_NUMBER', None)
        ]):
            raise Exception("Twilio configuration is missing")
        
        twilio_client = TwilioClient(
            settings.TWILIO_ACCOUNT_SID,
            settings.TWILIO_AUTH_TOKEN
        )
        
        # Create message body
        expiry_minutes = getattr(settings, 'MFA_SMS_CODE_EXPIRY_MINUTES', 5)
        
        if purpose == 'setup':
            message_body = f"Your verification code for setting up SMS authentication is: {verification_code}. This code expires in {expiry_minutes} minutes."
        elif purpose == 'resend':
            message_body = f"Your new verification code is: {verification_code}. This code expires in {expiry_minutes} minutes."
        else:
            message_body = f"Your verification code is: {verification_code}. This code expires in {expiry_minutes} minutes."
        
        # Send SMS
        message = twilio_client.messages.create(
            body=message_body,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        
        # Update device configuration with delivery information
        try:
            device = MFADevice.objects.get(id=device_id)
            device.configuration.update({
                'last_sms_sent': timezone.now().isoformat(),
                'last_message_sid': message.sid,
                'last_delivery_status': message.status,
                'last_task_id': self.request.id
            })
            device.save(update_fields=['configuration'])
        except MFADevice.DoesNotExist:
            logger.warning(f"MFA device {device_id} not found during SMS delivery update")
        
        # Log successful delivery
        if user_id:
            try:
                user = UserProfile.objects.get(id=user_id)
                audit_service.log_authentication_event(
                    event_type='sms_delivery_success',
                    user=user,
                    description=f'SMS code delivered successfully via Celery task',
                    metadata={
                        'device_id': device_id,
                        'message_sid': message.sid,
                        'status': message.status,
                        'purpose': purpose,
                        'task_id': self.request.id,
                        'retry_count': self.request.retries
                    }
                )
            except UserProfile.DoesNotExist:
                pass
        
        return {
            'success': True,
            'message_sid': message.sid,
            'status': message.status,
            'task_id': self.request.id,
            'retry_count': self.request.retries,
            'delivered_at': timezone.now().isoformat()
        }
        
    except TwilioException as e:
        logger.error(f"Twilio error in SMS delivery task: {str(e)}")
        
        # Log failed delivery attempt
        if user_id:
            try:
                user = UserProfile.objects.get(id=user_id)
                audit_service.log_authentication_event(
                    event_type='sms_delivery_failed',
                    user=user,
                    description=f'SMS delivery failed: {str(e)}',
                    severity='medium',
                    metadata={
                        'device_id': device_id,
                        'error': str(e),
                        'purpose': purpose,
                        'task_id': self.request.id,
                        'retry_count': self.request.retries,
                        'max_retries': self.max_retries
                    }
                )
            except UserProfile.DoesNotExist:
                pass
        
        # Update device configuration with error information
        try:
            device = MFADevice.objects.get(id=device_id)
            device.configuration.update({
                'last_sms_error': str(e),
                'last_sms_error_at': timezone.now().isoformat(),
                'last_task_id': self.request.id,
                'retry_count': self.request.retries
            })
            device.save(update_fields=['configuration'])
        except MFADevice.DoesNotExist:
            pass
        
        # Retry if we haven't exceeded max retries
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=30 * (2 ** self.request.retries))
        else:
            # Final failure
            return {
                'success': False,
                'error': str(e),
                'task_id': self.request.id,
                'retry_count': self.request.retries,
                'failed_at': timezone.now().isoformat()
            }
    
    except Exception as e:
        logger.error(f"Unexpected error in SMS delivery task: {str(e)}")
        
        # Log unexpected error
        if user_id:
            try:
                user = UserProfile.objects.get(id=user_id)
                audit_service.log_authentication_event(
                    event_type='sms_delivery_error',
                    user=user,
                    description=f'Unexpected SMS delivery error: {str(e)}',
                    severity='high',
                    metadata={
                        'device_id': device_id,
                        'error': str(e),
                        'purpose': purpose,
                        'task_id': self.request.id
                    }
                )
            except UserProfile.DoesNotExist:
                pass
        
        return {
            'success': False,
            'error': str(e),
            'task_id': self.request.id,
            'failed_at': timezone.now().isoformat()
        }


@shared_task
def check_sms_delivery_status(message_sid: str, device_id: str) -> Dict[str, Any]:
    """
    Check SMS delivery status from Twilio.
    
    Args:
        message_sid: Twilio message SID
        device_id: MFA device ID
        
    Returns:
        Dictionary containing delivery status
    """
    audit_service = AuditService()
    
    try:
        # Initialize Twilio client
        if not all([
            getattr(settings, 'TWILIO_ACCOUNT_SID', None),
            getattr(settings, 'TWILIO_AUTH_TOKEN', None)
        ]):
            raise Exception("Twilio configuration is missing")
        
        twilio_client = TwilioClient(
            settings.TWILIO_ACCOUNT_SID,
            settings.TWILIO_AUTH_TOKEN
        )
        
        # Fetch message status
        message = twilio_client.messages(message_sid).fetch()
        
        # Update device configuration with status
        try:
            device = MFADevice.objects.get(id=device_id)
            device.configuration.update({
                'delivery_status': message.status,
                'delivery_status_updated': timezone.now().isoformat(),
                'error_code': message.error_code,
                'error_message': message.error_message,
                'price': message.price,
                'price_unit': message.price_unit
            })
            device.save(update_fields=['configuration'])
            
            # Log status check
            audit_service.log_authentication_event(
                event_type='sms_status_checked',
                user=device.user,
                description=f'SMS delivery status checked: {message.status}',
                metadata={
                    'device_id': device_id,
                    'message_sid': message_sid,
                    'status': message.status,
                    'error_code': message.error_code,
                    'price': message.price
                }
            )
            
        except MFADevice.DoesNotExist:
            logger.warning(f"MFA device {device_id} not found during status check")
        
        return {
            'success': True,
            'message_sid': message_sid,
            'status': message.status,
            'error_code': message.error_code,
            'error_message': message.error_message,
            'date_sent': message.date_sent.isoformat() if message.date_sent else None,
            'date_updated': message.date_updated.isoformat() if message.date_updated else None,
            'price': message.price,
            'price_unit': message.price_unit,
            'checked_at': timezone.now().isoformat()
        }
        
    except TwilioException as e:
        logger.error(f"Twilio error checking SMS status: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'message_sid': message_sid,
            'checked_at': timezone.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Unexpected error checking SMS status: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'message_sid': message_sid,
            'checked_at': timezone.now().isoformat()
        }


@shared_task
def cleanup_expired_sms_codes() -> Dict[str, Any]:
    """
    Clean up expired SMS verification codes from cache.
    
    Returns:
        Dictionary containing cleanup statistics
    """
    from django.core.cache import cache
    
    try:
        # This is a maintenance task that would typically scan for expired codes
        # Since we're using cache timeouts, expired codes are automatically cleaned up
        # This task can be used for additional cleanup or statistics
        
        logger.info("SMS code cleanup task completed")
        
        return {
            'success': True,
            'cleaned_at': timezone.now().isoformat(),
            'message': 'SMS codes are automatically cleaned up by cache expiration'
        }
        
    except Exception as e:
        logger.error(f"Error in SMS code cleanup task: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'cleaned_at': timezone.now().isoformat()
        }


@shared_task
def send_sms_delivery_report(device_id: str, report_data: Dict[str, Any]) -> None:
    """
    Send SMS delivery report to administrators.
    
    Args:
        device_id: MFA device ID
        report_data: Delivery report data
    """
    try:
        # This task can be used to send delivery reports to administrators
        # or integrate with monitoring systems
        
        logger.info(f"SMS delivery report for device {device_id}: {report_data}")
        
        # Here you could integrate with monitoring systems like:
        # - Send to Slack/Teams
        # - Update monitoring dashboards
        # - Send email alerts for failed deliveries
        # - Update metrics in Prometheus/Grafana
        
    except Exception as e:
        logger.error(f"Error sending SMS delivery report: {str(e)}")


@shared_task
def bulk_sms_delivery_status_check() -> Dict[str, Any]:
    """
    Check delivery status for recent SMS messages in bulk.
    
    Returns:
        Dictionary containing bulk check results
    """
    try:
        from datetime import timedelta
        
        # Find devices with recent SMS deliveries that need status updates
        recent_cutoff = timezone.now() - timedelta(hours=1)
        
        devices_to_check = MFADevice.objects.filter(
            device_type='sms',
            configuration__last_sms_sent__gte=recent_cutoff.isoformat(),
            configuration__last_message_sid__isnull=False
        ).exclude(
            configuration__delivery_status__in=['delivered', 'failed', 'undelivered']
        )
        
        checked_count = 0
        error_count = 0
        
        for device in devices_to_check:
            message_sid = device.configuration.get('last_message_sid')
            if message_sid:
                try:
                    # Schedule individual status check
                    check_sms_delivery_status.delay(message_sid, str(device.id))
                    checked_count += 1
                except Exception as e:
                    logger.error(f"Error scheduling status check for device {device.id}: {str(e)}")
                    error_count += 1
        
        return {
            'success': True,
            'devices_checked': checked_count,
            'errors': error_count,
            'checked_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in bulk SMS status check: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'checked_at': timezone.now().isoformat()
        }