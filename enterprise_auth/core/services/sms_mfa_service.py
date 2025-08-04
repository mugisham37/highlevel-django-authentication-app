"""
SMS Multi-Factor Authentication service for enterprise authentication system.

This module provides SMS MFA functionality including SMS code generation,
delivery, verification, rate limiting, and abuse prevention using Twilio.
"""

import re
import secrets
import string
from typing import Optional, Dict, Any, List
from datetime import timedelta

from twilio.rest import Client as TwilioClient
from twilio.base.exceptions import TwilioException
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from ..models import UserProfile, MFADevice, MFAAttempt
from ..exceptions import (
    MFAError, 
    MFADeviceNotFoundError, 
    MFAVerificationError,
    MFARateLimitError,
    MFADeviceDisabledError
)
from .audit_service import AuditService


class SMSMFAService:
    """
    Service for managing SMS-based Multi-Factor Authentication operations.
    
    Provides SMS code generation, delivery, verification, rate limiting,
    and comprehensive security features with Twilio integration.
    """
    
    def __init__(self):
        """Initialize the SMS MFA service."""
        self.audit_service = AuditService()
        
        # SMS Configuration
        self.sms_code_length = getattr(settings, 'MFA_SMS_CODE_LENGTH', 6)
        self.sms_code_expiry_minutes = getattr(settings, 'MFA_SMS_CODE_EXPIRY_MINUTES', 5)
        self.sms_rate_limit_window = getattr(settings, 'MFA_SMS_RATE_LIMIT_WINDOW', 3600)  # 1 hour
        self.max_sms_per_window = getattr(settings, 'MFA_MAX_SMS_PER_WINDOW', 5)
        self.sms_retry_attempts = getattr(settings, 'MFA_SMS_RETRY_ATTEMPTS', 3)
        self.sms_retry_delay_seconds = getattr(settings, 'MFA_SMS_RETRY_DELAY_SECONDS', 30)
        
        # General MFA rate limiting
        self.rate_limit_window = getattr(settings, 'MFA_RATE_LIMIT_WINDOW', 300)  # 5 minutes
        self.max_attempts_per_window = getattr(settings, 'MFA_MAX_ATTEMPTS_PER_WINDOW', 5)
        
        # Initialize Twilio client
        self.twilio_client = None
        self.twilio_phone_number = None
        
        if all([
            getattr(settings, 'TWILIO_ACCOUNT_SID', None),
            getattr(settings, 'TWILIO_AUTH_TOKEN', None),
            getattr(settings, 'TWILIO_PHONE_NUMBER', None)
        ]):
            try:
                self.twilio_client = TwilioClient(
                    settings.TWILIO_ACCOUNT_SID,
                    settings.TWILIO_AUTH_TOKEN
                )
                self.twilio_phone_number = settings.TWILIO_PHONE_NUMBER
            except Exception as e:
                # Log error but don't fail initialization
                self.audit_service.log_authentication_event(
                    event_type='twilio_initialization_failed',
                    description=f'Failed to initialize Twilio client: {str(e)}',
                    severity='high',
                    metadata={'error': str(e)}
                )
    
    def setup_sms(
        self,
        user: UserProfile,
        device_name: str,
        phone_number: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Set up SMS MFA for a user.
        
        Args:
            user: User to set up SMS MFA for
            device_name: User-friendly name for the device
            phone_number: Phone number for SMS delivery
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing setup information
            
        Raises:
            MFAError: If setup fails
            MFARateLimitError: If SMS rate limit exceeded
        """
        try:
            # Validate phone number format
            if not self._validate_phone_number(phone_number):
                raise MFAError("Invalid phone number format")
            
            # Check SMS rate limiting
            self._check_sms_rate_limit(user, ip_address)
            
            # Check if Twilio is configured
            if not self.twilio_client:
                raise MFAError("SMS service is not configured")
            
            # Create the MFA device
            device = MFADevice.objects.create_sms_device(
                user=user,
                device_name=device_name,
                phone_number=phone_number,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Send verification code
            verification_code = self._generate_sms_code()
            self._store_sms_code(device, verification_code)
            
            delivery_result = self._send_sms_code(
                phone_number=phone_number,
                code=verification_code,
                device=device,
                purpose='setup'
            )
            
            # Log the setup attempt
            self.audit_service.log_authentication_event(
                event_type='mfa_sms_setup_initiated',
                user=user,
                description=f'SMS MFA setup initiated for device: {device_name}',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_id': str(device.id),
                    'device_name': device_name,
                    'phone_number_masked': self._mask_phone_number(phone_number),
                    'delivery_status': delivery_result.get('status', 'unknown')
                }
            )
            
            return {
                'device_id': str(device.id),
                'phone_number_masked': self._mask_phone_number(phone_number),
                'code_sent': delivery_result.get('success', False),
                'delivery_status': delivery_result.get('status', 'unknown'),
                'message_sid': delivery_result.get('message_sid'),
                'expires_in_minutes': self.sms_code_expiry_minutes,
                'retry_available': True
            }
            
        except MFARateLimitError:
            raise
        except Exception as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_sms_setup_failed',
                user=user,
                description=f'SMS MFA setup failed for device: {device_name}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'error': str(e),
                    'device_name': device_name,
                    'phone_number_masked': self._mask_phone_number(phone_number)
                }
            )
            raise MFAError(f"Failed to set up SMS MFA: {str(e)}")
    
    def confirm_sms_setup(
        self,
        user: UserProfile,
        device_id: str,
        verification_code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Confirm SMS MFA setup by verifying the code.
        
        Args:
            user: User confirming the setup
            device_id: ID of the MFA device
            verification_code: SMS code to verify
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing confirmation result
            
        Raises:
            MFADeviceNotFoundError: If device not found
            MFAVerificationError: If verification fails
        """
        try:
            # Get the device
            device = MFADevice.objects.get(
                id=device_id,
                user=user,
                device_type='sms',
                status='pending'
            )
        except MFADevice.DoesNotExist:
            raise MFADeviceNotFoundError("SMS device not found or already confirmed")
        
        # Verify the SMS code
        if not self._verify_sms_code(device, verification_code):
            self._record_failed_attempt(device, ip_address, user_agent, 'invalid_sms_code')
            raise MFAVerificationError("Invalid or expired SMS code")
        
        # Confirm the device
        device.confirm_device(ip_address)
        
        # Record successful setup
        self._record_successful_attempt(device, ip_address, user_agent)
        
        self.audit_service.log_authentication_event(
            event_type='mfa_sms_setup_completed',
            user=user,
            description=f'SMS MFA setup completed for device: {device.device_name}',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'device_id': str(device.id),
                'device_name': device.device_name,
                'phone_number_masked': self._mask_phone_number(device.get_phone_number() or '')
            }
        )
        
        return {
            'device_id': str(device.id),
            'device_name': device.device_name,
            'phone_number_masked': self._mask_phone_number(device.get_phone_number() or ''),
            'confirmed_at': device.created_at.isoformat(),
            'status': 'active'
        }
    
    def send_sms_code(
        self,
        user: UserProfile,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send SMS verification code to user's device.
        
        Args:
            user: User to send SMS code to
            device_id: Specific device ID (optional)
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing send result
            
        Raises:
            MFARateLimitError: If rate limit exceeded
            MFADeviceNotFoundError: If no active SMS devices found
            MFAError: If sending fails
        """
        # Check rate limiting
        self._check_rate_limit(user, ip_address)
        self._check_sms_rate_limit(user, ip_address)
        
        # Get SMS device
        if device_id:
            try:
                device = MFADevice.objects.get(
                    id=device_id,
                    user=user,
                    device_type='sms',
                    status='active',
                    is_confirmed=True
                )
            except MFADevice.DoesNotExist:
                raise MFADeviceNotFoundError("SMS device not found")
        else:
            devices = list(MFADevice.objects.filter(
                user=user,
                device_type='sms',
                status='active',
                is_confirmed=True
            ))
            if not devices:
                raise MFADeviceNotFoundError("No active SMS devices found")
            device = devices[0]  # Use the first active device
        
        # Check if Twilio is configured
        if not self.twilio_client:
            raise MFAError("SMS service is not configured")
        
        phone_number = device.get_phone_number()
        if not phone_number:
            raise MFAError("Phone number not found for device")
        
        # Generate and store verification code
        verification_code = self._generate_sms_code()
        self._store_sms_code(device, verification_code)
        
        # Send SMS
        delivery_result = self._send_sms_code(
            phone_number=phone_number,
            code=verification_code,
            device=device,
            purpose='verification'
        )
        
        self.audit_service.log_authentication_event(
            event_type='mfa_sms_code_sent',
            user=user,
            description=f'SMS verification code sent to device: {device.device_name}',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'device_id': str(device.id),
                'device_name': device.device_name,
                'phone_number_masked': self._mask_phone_number(phone_number),
                'delivery_status': delivery_result.get('status', 'unknown'),
                'message_sid': delivery_result.get('message_sid')
            }
        )
        
        return {
            'device_id': str(device.id),
            'device_name': device.device_name,
            'phone_number_masked': self._mask_phone_number(phone_number),
            'code_sent': delivery_result.get('success', False),
            'delivery_status': delivery_result.get('status', 'unknown'),
            'message_sid': delivery_result.get('message_sid'),
            'expires_in_minutes': self.sms_code_expiry_minutes,
            'sent_at': timezone.now().isoformat()
        }
    
    def verify_sms(
        self,
        user: UserProfile,
        verification_code: str,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify an SMS code.
        
        Args:
            user: User to verify SMS for
            verification_code: SMS code to verify
            device_id: Specific device ID (optional)
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing verification result
            
        Raises:
            MFARateLimitError: If rate limit exceeded
            MFADeviceNotFoundError: If no active SMS devices found
            MFAVerificationError: If verification fails
        """
        # Check rate limiting
        self._check_rate_limit(user, ip_address)
        
        # Get SMS devices
        if device_id:
            try:
                devices = [MFADevice.objects.get(
                    id=device_id,
                    user=user,
                    device_type='sms',
                    status='active',
                    is_confirmed=True
                )]
            except MFADevice.DoesNotExist:
                raise MFADeviceNotFoundError("SMS device not found")
        else:
            devices = list(MFADevice.objects.filter(
                user=user,
                device_type='sms',
                status='active',
                is_confirmed=True
            ))
        
        if not devices:
            raise MFADeviceNotFoundError("No active SMS devices found")
        
        # Try to verify with each device
        for device in devices:
            if self._verify_sms_code(device, verification_code):
                # Record successful verification
                self._record_successful_attempt(device, ip_address, user_agent)
                
                # Clear the stored code
                self._clear_sms_code(device)
                
                self.audit_service.log_authentication_event(
                    event_type='mfa_sms_verification_success',
                    user=user,
                    description=f'SMS verification successful for device: {device.device_name}',
                    request_info={
                        'ip_address': ip_address,
                        'user_agent': user_agent
                    },
                    metadata={
                        'device_id': str(device.id),
                        'device_name': device.device_name,
                        'phone_number_masked': self._mask_phone_number(device.get_phone_number() or '')
                    }
                )
                
                return {
                    'verified': True,
                    'device_id': str(device.id),
                    'device_name': device.device_name,
                    'verified_at': timezone.now().isoformat()
                }
        
        # Record failed attempts for all devices
        for device in devices:
            self._record_failed_attempt(device, ip_address, user_agent, 'invalid_sms_code')
        
        self.audit_service.log_authentication_event(
            event_type='mfa_sms_verification_failed',
            user=user,
            description=f'SMS verification failed for {len(devices)} devices',
            severity='medium',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'devices_tried': len(devices),
                'verification_code_length': len(verification_code)
            }
        )
        
        raise MFAVerificationError("Invalid or expired SMS code")
    
    def resend_sms_code(
        self,
        user: UserProfile,
        device_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Resend SMS verification code.
        
        Args:
            user: User to resend SMS code to
            device_id: ID of the SMS device
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing resend result
            
        Raises:
            MFARateLimitError: If rate limit exceeded
            MFADeviceNotFoundError: If device not found
            MFAError: If resending fails
        """
        # Check rate limiting
        self._check_sms_rate_limit(user, ip_address)
        
        try:
            device = MFADevice.objects.get(
                id=device_id,
                user=user,
                device_type='sms'
            )
        except MFADevice.DoesNotExist:
            raise MFADeviceNotFoundError("SMS device not found")
        
        # Check if device is active (for confirmed devices) or pending (for setup)
        if device.status not in ['active', 'pending']:
            raise MFADeviceDisabledError("SMS device is disabled")
        
        phone_number = device.get_phone_number()
        if not phone_number:
            raise MFAError("Phone number not found for device")
        
        # Generate and store new verification code
        verification_code = self._generate_sms_code()
        self._store_sms_code(device, verification_code)
        
        # Send SMS
        delivery_result = self._send_sms_code(
            phone_number=phone_number,
            code=verification_code,
            device=device,
            purpose='resend'
        )
        
        self.audit_service.log_authentication_event(
            event_type='mfa_sms_code_resent',
            user=user,
            description=f'SMS verification code resent to device: {device.device_name}',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'device_id': str(device.id),
                'device_name': device.device_name,
                'phone_number_masked': self._mask_phone_number(phone_number),
                'delivery_status': delivery_result.get('status', 'unknown'),
                'message_sid': delivery_result.get('message_sid')
            }
        )
        
        return {
            'device_id': str(device.id),
            'device_name': device.device_name,
            'phone_number_masked': self._mask_phone_number(phone_number),
            'code_sent': delivery_result.get('success', False),
            'delivery_status': delivery_result.get('status', 'unknown'),
            'message_sid': delivery_result.get('message_sid'),
            'expires_in_minutes': self.sms_code_expiry_minutes,
            'resent_at': timezone.now().isoformat()
        }
    
    def get_sms_delivery_status(
        self,
        user: UserProfile,
        message_sid: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get SMS delivery status from Twilio.
        
        Args:
            user: User requesting the status
            message_sid: Twilio message SID
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing delivery status
            
        Raises:
            MFAError: If status check fails
        """
        if not self.twilio_client:
            raise MFAError("SMS service is not configured")
        
        try:
            message = self.twilio_client.messages(message_sid).fetch()
            
            status_info = {
                'message_sid': message_sid,
                'status': message.status,
                'error_code': message.error_code,
                'error_message': message.error_message,
                'date_sent': message.date_sent.isoformat() if message.date_sent else None,
                'date_updated': message.date_updated.isoformat() if message.date_updated else None,
                'price': message.price,
                'price_unit': message.price_unit,
                'direction': message.direction,
                'num_segments': message.num_segments
            }
            
            self.audit_service.log_authentication_event(
                event_type='mfa_sms_status_checked',
                user=user,
                description=f'SMS delivery status checked: {message.status}',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'message_sid': message_sid,
                    'status': message.status,
                    'error_code': message.error_code
                }
            )
            
            return status_info
            
        except TwilioException as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_sms_status_check_failed',
                user=user,
                description=f'Failed to check SMS delivery status: {str(e)}',
                severity='medium',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'message_sid': message_sid,
                    'error': str(e)
                }
            )
            raise MFAError(f"Failed to check SMS delivery status: {str(e)}")
    
    # Private helper methods
    
    def _validate_phone_number(self, phone_number: str) -> bool:
        """
        Validate phone number format.
        
        Args:
            phone_number: Phone number to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Remove all non-digit characters except +
        cleaned = re.sub(r'[^\d+]', '', phone_number)
        
        # Check if it matches international format
        if re.match(r'^\+?1?\d{10,15}$', cleaned):
            return True
        
        return False
    
    def _generate_sms_code(self) -> str:
        """
        Generate a secure SMS verification code.
        
        Returns:
            Random numeric verification code
        """
        # Generate numeric code
        digits = string.digits
        return ''.join(secrets.choice(digits) for _ in range(self.sms_code_length))
    
    def _store_sms_code(self, device: MFADevice, code: str) -> None:
        """
        Store SMS verification code in cache.
        
        Args:
            device: MFA device
            code: Verification code to store
        """
        cache_key = f"sms_code:{device.id}"
        cache_data = {
            'code': code,
            'created_at': timezone.now().isoformat(),
            'attempts': 0
        }
        cache.set(cache_key, cache_data, timeout=self.sms_code_expiry_minutes * 60)
    
    def _verify_sms_code(self, device: MFADevice, code: str) -> bool:
        """
        Verify SMS code against stored code.
        
        Args:
            device: MFA device
            code: Code to verify
            
        Returns:
            True if code is valid, False otherwise
        """
        cache_key = f"sms_code:{device.id}"
        cache_data = cache.get(cache_key)
        
        if not cache_data:
            return False
        
        # Check if code matches
        if cache_data['code'] != code:
            # Increment attempt counter
            cache_data['attempts'] += 1
            cache.set(cache_key, cache_data, timeout=self.sms_code_expiry_minutes * 60)
            return False
        
        # Check if too many attempts
        if cache_data['attempts'] >= 3:
            return False
        
        return True
    
    def _clear_sms_code(self, device: MFADevice) -> None:
        """
        Clear stored SMS code from cache.
        
        Args:
            device: MFA device
        """
        cache_key = f"sms_code:{device.id}"
        cache.delete(cache_key)
    
    def _send_sms_code(
        self,
        phone_number: str,
        code: str,
        device: MFADevice,
        purpose: str = 'verification'
    ) -> Dict[str, Any]:
        """
        Send SMS code using Twilio with retry logic.
        
        Args:
            phone_number: Phone number to send to
            code: Verification code
            device: MFA device
            purpose: Purpose of the SMS (setup, verification, resend)
            
        Returns:
            Dictionary containing delivery result
        """
        if not self.twilio_client:
            return {
                'success': False,
                'status': 'service_unavailable',
                'error': 'SMS service is not configured'
            }
        
        # Create message body
        if purpose == 'setup':
            message_body = f"Your verification code for setting up SMS authentication is: {code}. This code expires in {self.sms_code_expiry_minutes} minutes."
        elif purpose == 'resend':
            message_body = f"Your new verification code is: {code}. This code expires in {self.sms_code_expiry_minutes} minutes."
        else:
            message_body = f"Your verification code is: {code}. This code expires in {self.sms_code_expiry_minutes} minutes."
        
        # Attempt to send SMS with retry logic
        for attempt in range(self.sms_retry_attempts):
            try:
                message = self.twilio_client.messages.create(
                    body=message_body,
                    from_=self.twilio_phone_number,
                    to=phone_number
                )
                
                # Store delivery information in device configuration
                device.configuration.update({
                    'last_sms_sent': timezone.now().isoformat(),
                    'last_message_sid': message.sid,
                    'last_delivery_status': message.status
                })
                device.save(update_fields=['configuration'])
                
                return {
                    'success': True,
                    'status': message.status,
                    'message_sid': message.sid,
                    'attempt': attempt + 1
                }
                
            except TwilioException as e:
                if attempt < self.sms_retry_attempts - 1:
                    # Wait before retry
                    import time
                    time.sleep(self.sms_retry_delay_seconds)
                    continue
                else:
                    # Final attempt failed
                    return {
                        'success': False,
                        'status': 'failed',
                        'error': str(e),
                        'attempts': self.sms_retry_attempts
                    }
            except Exception as e:
                return {
                    'success': False,
                    'status': 'error',
                    'error': str(e),
                    'attempt': attempt + 1
                }
        
        return {
            'success': False,
            'status': 'failed',
            'error': 'All retry attempts failed'
        }
    
    def _mask_phone_number(self, phone_number: str) -> str:
        """
        Mask phone number for display purposes.
        
        Args:
            phone_number: Phone number to mask
            
        Returns:
            Masked phone number
        """
        if not phone_number:
            return ''
        
        # Remove non-digit characters except +
        cleaned = re.sub(r'[^\d+]', '', phone_number)
        
        if len(cleaned) >= 4:
            return f"***-***-{cleaned[-4:]}"
        else:
            return "***-***-****"
    
    def _check_rate_limit(self, user: UserProfile, ip_address: Optional[str]) -> None:
        """
        Check general MFA rate limiting.
        
        Args:
            user: User making the attempt
            ip_address: IP address of the attempt
            
        Raises:
            MFARateLimitError: If rate limit exceeded
        """
        # Check user-based rate limiting
        user_key = f"mfa_attempts:user:{user.id}"
        user_attempts = cache.get(user_key, 0)
        
        if user_attempts >= self.max_attempts_per_window:
            raise MFARateLimitError("Too many MFA attempts. Please try again later.")
        
        # Check IP-based rate limiting if IP is provided
        if ip_address:
            ip_key = f"mfa_attempts:ip:{ip_address}"
            ip_attempts = cache.get(ip_key, 0)
            
            if ip_attempts >= self.max_attempts_per_window * 2:  # Higher limit for IP
                raise MFARateLimitError("Too many MFA attempts from this IP. Please try again later.")
    
    def _check_sms_rate_limit(self, user: UserProfile, ip_address: Optional[str]) -> None:
        """
        Check SMS-specific rate limiting.
        
        Args:
            user: User making the attempt
            ip_address: IP address of the attempt
            
        Raises:
            MFARateLimitError: If SMS rate limit exceeded
        """
        # Check user-based SMS rate limiting
        user_key = f"sms_attempts:user:{user.id}"
        user_attempts = cache.get(user_key, 0)
        
        if user_attempts >= self.max_sms_per_window:
            raise MFARateLimitError(f"Too many SMS requests. Please try again in {self.sms_rate_limit_window // 60} minutes.")
        
        # Check IP-based SMS rate limiting if IP is provided
        if ip_address:
            ip_key = f"sms_attempts:ip:{ip_address}"
            ip_attempts = cache.get(ip_key, 0)
            
            if ip_attempts >= self.max_sms_per_window * 3:  # Higher limit for IP
                raise MFARateLimitError(f"Too many SMS requests from this IP. Please try again in {self.sms_rate_limit_window // 60} minutes.")
    
    def _record_failed_attempt(
        self,
        device: MFADevice,
        ip_address: Optional[str],
        user_agent: Optional[str],
        failure_reason: str
    ) -> None:
        """
        Record a failed MFA attempt.
        
        Args:
            device: MFA device used
            ip_address: IP address of the attempt
            user_agent: User agent string
            failure_reason: Reason for failure
        """
        # Record in database
        MFAAttempt.objects.create(
            user=device.user,
            device=device,
            result='failure',
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent,
            failure_reason=failure_reason
        )
        
        # Update rate limiting counters
        user_key = f"mfa_attempts:user:{device.user.id}"
        cache.set(user_key, cache.get(user_key, 0) + 1, self.rate_limit_window)
        
        if ip_address:
            ip_key = f"mfa_attempts:ip:{ip_address}"
            cache.set(ip_key, cache.get(ip_key, 0) + 1, self.rate_limit_window)
        
        # Update SMS-specific rate limiting counters
        if device.device_type == 'sms':
            sms_user_key = f"sms_attempts:user:{device.user.id}"
            cache.set(sms_user_key, cache.get(sms_user_key, 0) + 1, self.sms_rate_limit_window)
            
            if ip_address:
                sms_ip_key = f"sms_attempts:ip:{ip_address}"
                cache.set(sms_ip_key, cache.get(sms_ip_key, 0) + 1, self.sms_rate_limit_window)
    
    def _record_successful_attempt(
        self,
        device: MFADevice,
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> None:
        """
        Record a successful MFA attempt.
        
        Args:
            device: MFA device used
            ip_address: IP address of the attempt
            user_agent: User agent string
        """
        # Record in database
        MFAAttempt.objects.create(
            user=device.user,
            device=device,
            result='success',
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent
        )
        
        # Mark device as used
        device.mark_as_used(ip_address)
        
        # Clear rate limiting counters on success
        user_key = f"mfa_attempts:user:{device.user.id}"
        cache.delete(user_key)
        
        # Clear SMS-specific rate limiting counters on success
        if device.device_type == 'sms':
            sms_user_key = f"sms_attempts:user:{device.user.id}"
            cache.delete(sms_user_key)


# Create a singleton instance
sms_mfa_service = SMSMFAService()