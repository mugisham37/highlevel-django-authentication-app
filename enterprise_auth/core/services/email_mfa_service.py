"""
Email Multi-Factor Authentication service for enterprise authentication system.

This module provides email MFA functionality including email code generation,
delivery, verification, rate limiting, and abuse prevention with fallback support.
"""

import re
import secrets
import string
from typing import Optional, Dict, Any, List
from datetime import timedelta

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


class EmailMFAService:
    """
    Service for managing Email-based Multi-Factor Authentication operations.
    
    Provides email code generation, delivery, verification, rate limiting,
    and comprehensive security features with fallback support for SMS failures.
    """
    
    def __init__(self):
        """Initialize the Email MFA service."""
        self.audit_service = AuditService()
        
        # Email MFA Configuration
        self.email_code_length = getattr(settings, 'MFA_EMAIL_CODE_LENGTH', 6)
        self.email_code_expiry_minutes = getattr(settings, 'MFA_EMAIL_CODE_EXPIRY_MINUTES', 10)
        self.email_rate_limit_window = getattr(settings, 'MFA_EMAIL_RATE_LIMIT_WINDOW', 3600)  # 1 hour
        self.max_emails_per_window = getattr(settings, 'MFA_MAX_EMAILS_PER_WINDOW', 10)
        self.email_retry_attempts = getattr(settings, 'MFA_EMAIL_RETRY_ATTEMPTS', 3)
        self.email_retry_delay_seconds = getattr(settings, 'MFA_EMAIL_RETRY_DELAY_SECONDS', 30)
        
        # General MFA rate limiting
        self.rate_limit_window = getattr(settings, 'MFA_RATE_LIMIT_WINDOW', 300)  # 5 minutes
        self.max_attempts_per_window = getattr(settings, 'MFA_MAX_ATTEMPTS_PER_WINDOW', 5)
        
        # Email MFA specific settings
        self.email_template_name = getattr(settings, 'MFA_EMAIL_TEMPLATE_NAME', 'emails/mfa_verification_email.html')
        self.email_subject_template = getattr(settings, 'MFA_EMAIL_SUBJECT_TEMPLATE', 'Your verification code: {code}')
        self.use_html_email = getattr(settings, 'MFA_EMAIL_USE_HTML', True)
        
        # Fallback configuration
        self.enable_sms_fallback = getattr(settings, 'MFA_EMAIL_ENABLE_SMS_FALLBACK', True)
        self.fallback_threshold_failures = getattr(settings, 'MFA_EMAIL_FALLBACK_THRESHOLD', 3)
    
    def setup_email_mfa(
        self,
        user: UserProfile,
        device_name: str,
        email_address: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Set up Email MFA for a user.
        
        Args:
            user: User to set up Email MFA for
            device_name: User-friendly name for the device
            email_address: Email address for MFA delivery (defaults to user's primary email)
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing setup information
            
        Raises:
            MFAError: If setup fails
            MFARateLimitError: If email rate limit exceeded
        """
        try:
            # Use user's primary email if no specific email provided
            if not email_address:
                email_address = user.email
            
            # Validate email address format
            if not self._validate_email_address(email_address):
                raise MFAError("Invalid email address format")
            
            # Check email rate limiting
            self._check_email_rate_limit(user, ip_address)
            
            # Create the MFA device
            device = MFADevice.objects.create_email_device(
                user=user,
                device_name=device_name,
                email_address=email_address,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Send verification code
            verification_code = self._generate_email_code()
            self._store_email_code(device, verification_code)
            
            delivery_result = self._send_email_code(
                email_address=email_address,
                code=verification_code,
                device=device,
                purpose='setup'
            )
            
            # Log the setup attempt
            self.audit_service.log_authentication_event(
                event_type='mfa_email_setup_initiated',
                user=user,
                description=f'Email MFA setup initiated for device: {device_name}',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_id': str(device.id),
                    'device_name': device_name,
                    'email_address_masked': self._mask_email_address(email_address),
                    'delivery_status': delivery_result.get('status', 'unknown')
                }
            )
            
            return {
                'device_id': str(device.id),
                'email_address_masked': self._mask_email_address(email_address),
                'code_sent': delivery_result.get('success', False),
                'delivery_status': delivery_result.get('status', 'unknown'),
                'task_id': delivery_result.get('task_id'),
                'expires_in_minutes': self.email_code_expiry_minutes,
                'retry_available': True
            }
            
        except MFARateLimitError:
            raise
        except Exception as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_email_setup_failed',
                user=user,
                description=f'Email MFA setup failed for device: {device_name}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'error': str(e),
                    'device_name': device_name,
                    'email_address_masked': self._mask_email_address(email_address or user.email)
                }
            )
            raise MFAError(f"Failed to set up Email MFA: {str(e)}")
    
    def confirm_email_setup(
        self,
        user: UserProfile,
        device_id: str,
        verification_code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Confirm Email MFA setup by verifying the code.
        
        Args:
            user: User confirming the setup
            device_id: ID of the MFA device
            verification_code: Email code to verify
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
                device_type='email',
                status='pending'
            )
        except MFADevice.DoesNotExist:
            raise MFADeviceNotFoundError("Email device not found or already confirmed")
        
        # Verify the email code
        if not self._verify_email_code(device, verification_code):
            self._record_failed_attempt(device, ip_address, user_agent, 'invalid_email_code')
            raise MFAVerificationError("Invalid or expired email code")
        
        # Confirm the device
        device.confirm_device(ip_address)
        
        # Record successful setup
        self._record_successful_attempt(device, ip_address, user_agent)
        
        self.audit_service.log_authentication_event(
            event_type='mfa_email_setup_completed',
            user=user,
            description=f'Email MFA setup completed for device: {device.device_name}',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'device_id': str(device.id),
                'device_name': device.device_name,
                'email_address_masked': self._mask_email_address(device.email_address or '')
            }
        )
        
        return {
            'device_id': str(device.id),
            'device_name': device.device_name,
            'email_address_masked': self._mask_email_address(device.email_address or ''),
            'confirmed_at': device.created_at.isoformat(),
            'status': 'active'
        }
    
    def send_email_code(
        self,
        user: UserProfile,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send email verification code to user's device.
        
        Args:
            user: User to send email code to
            device_id: Specific device ID (optional)
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing send result
            
        Raises:
            MFARateLimitError: If rate limit exceeded
            MFADeviceNotFoundError: If no active email devices found
            MFAError: If sending fails
        """
        # Check rate limiting
        self._check_rate_limit(user, ip_address)
        self._check_email_rate_limit(user, ip_address)
        
        # Get email device
        if device_id:
            try:
                device = MFADevice.objects.get(
                    id=device_id,
                    user=user,
                    device_type='email',
                    status='active',
                    is_confirmed=True
                )
            except MFADevice.DoesNotExist:
                raise MFADeviceNotFoundError("Email device not found")
        else:
            devices = list(MFADevice.objects.filter(
                user=user,
                device_type='email',
                status='active',
                is_confirmed=True
            ))
            if not devices:
                raise MFADeviceNotFoundError("No active email devices found")
            device = devices[0]  # Use the first active device
        
        email_address = device.email_address or user.email
        if not email_address:
            raise MFAError("Email address not found for device")
        
        # Generate and store verification code
        verification_code = self._generate_email_code()
        self._store_email_code(device, verification_code)
        
        # Send email
        delivery_result = self._send_email_code(
            email_address=email_address,
            code=verification_code,
            device=device,
            purpose='verification'
        )
        
        self.audit_service.log_authentication_event(
            event_type='mfa_email_code_sent',
            user=user,
            description=f'Email verification code sent to device: {device.device_name}',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'device_id': str(device.id),
                'device_name': device.device_name,
                'email_address_masked': self._mask_email_address(email_address),
                'delivery_status': delivery_result.get('status', 'unknown'),
                'task_id': delivery_result.get('task_id')
            }
        )
        
        return {
            'device_id': str(device.id),
            'device_name': device.device_name,
            'email_address_masked': self._mask_email_address(email_address),
            'code_sent': delivery_result.get('success', False),
            'delivery_status': delivery_result.get('status', 'unknown'),
            'task_id': delivery_result.get('task_id'),
            'expires_in_minutes': self.email_code_expiry_minutes,
            'sent_at': timezone.now().isoformat()
        }
    
    def verify_email(
        self,
        user: UserProfile,
        verification_code: str,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify an email code.
        
        Args:
            user: User to verify email for
            verification_code: Email code to verify
            device_id: Specific device ID (optional)
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing verification result
            
        Raises:
            MFARateLimitError: If rate limit exceeded
            MFADeviceNotFoundError: If no active email devices found
            MFAVerificationError: If verification fails
        """
        # Check rate limiting
        self._check_rate_limit(user, ip_address)
        
        # Get email devices
        if device_id:
            try:
                devices = [MFADevice.objects.get(
                    id=device_id,
                    user=user,
                    device_type='email',
                    status='active',
                    is_confirmed=True
                )]
            except MFADevice.DoesNotExist:
                raise MFADeviceNotFoundError("Email device not found")
        else:
            devices = list(MFADevice.objects.filter(
                user=user,
                device_type='email',
                status='active',
                is_confirmed=True
            ))
        
        if not devices:
            raise MFADeviceNotFoundError("No active email devices found")
        
        # Try to verify with each device
        for device in devices:
            if self._verify_email_code(device, verification_code):
                # Record successful verification
                self._record_successful_attempt(device, ip_address, user_agent)
                
                # Clear the stored code
                self._clear_email_code(device)
                
                self.audit_service.log_authentication_event(
                    event_type='mfa_email_verification_success',
                    user=user,
                    description=f'Email verification successful for device: {device.device_name}',
                    request_info={
                        'ip_address': ip_address,
                        'user_agent': user_agent
                    },
                    metadata={
                        'device_id': str(device.id),
                        'device_name': device.device_name,
                        'email_address_masked': self._mask_email_address(device.email_address or '')
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
            self._record_failed_attempt(device, ip_address, user_agent, 'invalid_email_code')
        
        self.audit_service.log_authentication_event(
            event_type='mfa_email_verification_failed',
            user=user,
            description=f'Email verification failed for {len(devices)} devices',
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
        
        raise MFAVerificationError("Invalid or expired email code")
    
    def resend_email_code(
        self,
        user: UserProfile,
        device_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Resend email verification code.
        
        Args:
            user: User to resend email code to
            device_id: ID of the email device
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
        self._check_email_rate_limit(user, ip_address)
        
        try:
            device = MFADevice.objects.get(
                id=device_id,
                user=user,
                device_type='email'
            )
        except MFADevice.DoesNotExist:
            raise MFADeviceNotFoundError("Email device not found")
        
        # Check if device is active (for confirmed devices) or pending (for setup)
        if device.status not in ['active', 'pending']:
            raise MFADeviceDisabledError("Email device is disabled")
        
        email_address = device.email_address or user.email
        if not email_address:
            raise MFAError("Email address not found for device")
        
        # Generate and store new verification code
        verification_code = self._generate_email_code()
        self._store_email_code(device, verification_code)
        
        # Send email
        delivery_result = self._send_email_code(
            email_address=email_address,
            code=verification_code,
            device=device,
            purpose='resend'
        )
        
        self.audit_service.log_authentication_event(
            event_type='mfa_email_code_resent',
            user=user,
            description=f'Email verification code resent to device: {device.device_name}',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'device_id': str(device.id),
                'device_name': device.device_name,
                'email_address_masked': self._mask_email_address(email_address),
                'delivery_status': delivery_result.get('status', 'unknown'),
                'task_id': delivery_result.get('task_id')
            }
        )
        
        return {
            'device_id': str(device.id),
            'device_name': device.device_name,
            'email_address_masked': self._mask_email_address(email_address),
            'code_sent': delivery_result.get('success', False),
            'delivery_status': delivery_result.get('status', 'unknown'),
            'task_id': delivery_result.get('task_id'),
            'expires_in_minutes': self.email_code_expiry_minutes,
            'resent_at': timezone.now().isoformat()
        }
    
    def trigger_sms_fallback(
        self,
        user: UserProfile,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Trigger SMS fallback when email MFA fails repeatedly.
        
        Args:
            user: User to trigger SMS fallback for
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing fallback result
            
        Raises:
            MFAError: If SMS fallback is not available or fails
        """
        if not self.enable_sms_fallback:
            raise MFAError("SMS fallback is not enabled")
        
        # Check if user has SMS devices available
        sms_devices = list(MFADevice.objects.filter(
            user=user,
            device_type='sms',
            status='active',
            is_confirmed=True
        ))
        
        if not sms_devices:
            raise MFAError("No SMS devices available for fallback")
        
        # Import SMS MFA service
        from .sms_mfa_service import SMSMFAService
        sms_service = SMSMFAService()
        
        try:
            # Send SMS code using the first available SMS device
            sms_device = sms_devices[0]
            result = sms_service.send_sms_code(
                user=user,
                device_id=str(sms_device.id),
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            self.audit_service.log_authentication_event(
                event_type='mfa_email_sms_fallback_triggered',
                user=user,
                description='SMS fallback triggered due to email MFA failures',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'sms_device_id': str(sms_device.id),
                    'sms_device_name': sms_device.device_name,
                    'fallback_reason': 'email_delivery_failures'
                }
            )
            
            return {
                'fallback_triggered': True,
                'fallback_method': 'sms',
                'sms_device_id': str(sms_device.id),
                'sms_device_name': sms_device.device_name,
                'sms_result': result
            }
            
        except Exception as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_email_sms_fallback_failed',
                user=user,
                description=f'SMS fallback failed: {str(e)}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'error': str(e),
                    'fallback_reason': 'email_delivery_failures'
                }
            )
            raise MFAError(f"SMS fallback failed: {str(e)}")
    
    # Private helper methods
    
    def _validate_email_address(self, email_address: str) -> bool:
        """
        Validate email address format.
        
        Args:
            email_address: Email address to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Basic email validation regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern, email_address) is not None
    
    def _generate_email_code(self) -> str:
        """
        Generate a secure email verification code.
        
        Returns:
            Random numeric verification code
        """
        # Generate numeric code
        digits = string.digits
        return ''.join(secrets.choice(digits) for _ in range(self.email_code_length))
    
    def _store_email_code(self, device: MFADevice, code: str) -> None:
        """
        Store email verification code in cache.
        
        Args:
            device: MFA device
            code: Verification code to store
        """
        cache_key = f"email_code:{device.id}"
        cache_data = {
            'code': code,
            'created_at': timezone.now().isoformat(),
            'attempts': 0
        }
        cache.set(cache_key, cache_data, timeout=self.email_code_expiry_minutes * 60)
    
    def _verify_email_code(self, device: MFADevice, code: str) -> bool:
        """
        Verify email code against stored code.
        
        Args:
            device: MFA device
            code: Code to verify
            
        Returns:
            True if code is valid, False otherwise
        """
        cache_key = f"email_code:{device.id}"
        cache_data = cache.get(cache_key)
        
        if not cache_data:
            return False
        
        # Check if code matches
        if cache_data['code'] != code:
            # Increment attempt counter
            cache_data['attempts'] += 1
            cache.set(cache_key, cache_data, timeout=self.email_code_expiry_minutes * 60)
            return False
        
        # Check if too many attempts
        if cache_data['attempts'] >= 3:
            return False
        
        return True
    
    def _clear_email_code(self, device: MFADevice) -> None:
        """
        Clear stored email code from cache.
        
        Args:
            device: MFA device
        """
        cache_key = f"email_code:{device.id}"
        cache.delete(cache_key)
    
    def _send_email_code(
        self,
        email_address: str,
        code: str,
        device: MFADevice,
        purpose: str = 'verification'
    ) -> Dict[str, Any]:
        """
        Send email code using Django's email system with retry logic.
        
        Args:
            email_address: Email address to send to
            code: Verification code
            device: MFA device
            purpose: Purpose of the email (setup, verification, resend)
            
        Returns:
            Dictionary containing delivery result
        """
        try:
            # Import email task
            from ..tasks.email_tasks import send_mfa_verification_email
            
            # Send email asynchronously
            task_result = send_mfa_verification_email.delay(
                user_id=str(device.user.id),
                device_id=str(device.id),
                email_address=email_address,
                verification_code=code,
                purpose=purpose
            )
            
            # Store delivery information in device configuration
            device.configuration.update({
                'last_email_sent': timezone.now().isoformat(),
                'last_task_id': task_result.id,
                'last_delivery_purpose': purpose
            })
            device.save(update_fields=['configuration'])
            
            return {
                'success': True,
                'status': 'queued',
                'task_id': task_result.id,
                'purpose': purpose
            }
            
        except Exception as e:
            return {
                'success': False,
                'status': 'failed',
                'error': str(e),
                'purpose': purpose
            }
    
    def _mask_email_address(self, email_address: str) -> str:
        """
        Mask email address for display purposes.
        
        Args:
            email_address: Email address to mask
            
        Returns:
            Masked email address
        """
        if not email_address or '@' not in email_address:
            return '***@***.***'
        
        local, domain = email_address.split('@', 1)
        
        if len(local) <= 2:
            masked_local = local + '*' * max(1, len(local))
        else:
            masked_local = local[:2] + '*' * (len(local) - 2)
        
        return f"{masked_local}@{domain}"
    
    def _check_rate_limit(self, user: UserProfile, ip_address: Optional[str]) -> None:
        """
        Check general MFA rate limiting.
        
        Args:
            user: User making the attempt
            ip_address: IP address of the request
            
        Raises:
            MFARateLimitError: If rate limit exceeded
        """
        # Check user-based rate limiting
        user_cache_key = f"mfa_rate_limit:user:{user.id}"
        user_attempts = cache.get(user_cache_key, 0)
        
        if user_attempts >= self.max_attempts_per_window:
            raise MFARateLimitError(
                f"Too many MFA attempts. Try again in {self.rate_limit_window // 60} minutes."
            )
        
        # Check IP-based rate limiting if IP is provided
        if ip_address:
            ip_cache_key = f"mfa_rate_limit:ip:{ip_address}"
            ip_attempts = cache.get(ip_cache_key, 0)
            
            if ip_attempts >= self.max_attempts_per_window * 2:  # More lenient for IP
                raise MFARateLimitError(
                    f"Too many MFA attempts from this IP. Try again in {self.rate_limit_window // 60} minutes."
                )
        
        # Increment counters
        cache.set(user_cache_key, user_attempts + 1, timeout=self.rate_limit_window)
        if ip_address:
            cache.set(ip_cache_key, cache.get(ip_cache_key, 0) + 1, timeout=self.rate_limit_window)
    
    def _check_email_rate_limit(self, user: UserProfile, ip_address: Optional[str]) -> None:
        """
        Check email-specific rate limiting.
        
        Args:
            user: User making the attempt
            ip_address: IP address of the request
            
        Raises:
            MFARateLimitError: If email rate limit exceeded
        """
        # Check user-based email rate limiting
        user_cache_key = f"email_mfa_rate_limit:user:{user.id}"
        user_emails = cache.get(user_cache_key, 0)
        
        if user_emails >= self.max_emails_per_window:
            raise MFARateLimitError(
                f"Too many email MFA requests. Try again in {self.email_rate_limit_window // 60} minutes."
            )
        
        # Check IP-based email rate limiting if IP is provided
        if ip_address:
            ip_cache_key = f"email_mfa_rate_limit:ip:{ip_address}"
            ip_emails = cache.get(ip_cache_key, 0)
            
            if ip_emails >= self.max_emails_per_window * 3:  # More lenient for IP
                raise MFARateLimitError(
                    f"Too many email MFA requests from this IP. Try again in {self.email_rate_limit_window // 60} minutes."
                )
        
        # Increment counters
        cache.set(user_cache_key, user_emails + 1, timeout=self.email_rate_limit_window)
        if ip_address:
            cache.set(ip_cache_key, cache.get(ip_cache_key, 0) + 1, timeout=self.email_rate_limit_window)
    
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
        MFAAttempt.objects.create(
            user=device.user,
            device=device,
            result='success',
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent or '',
            response_time_ms=100  # Placeholder for email response time
        )
        
        # Update device usage
        device.mark_as_used(ip_address)
    
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
        MFAAttempt.objects.create(
            user=device.user,
            device=device,
            result='failure',
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent or '',
            failure_reason=failure_reason,
            response_time_ms=100  # Placeholder for email response time
        )


# Create service instance
email_mfa_service = EmailMFAService()