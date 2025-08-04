"""
Backup Codes MFA service for enterprise authentication system.

This module provides comprehensive backup codes functionality including
generation, validation, single-use enforcement, regeneration, and monitoring.
"""

import secrets
import string
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

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
)
from .audit_service import AuditService


class BackupCodesService:
    """
    Service for managing MFA backup codes with comprehensive security features.
    
    Provides cryptographically secure backup code generation, validation with
    single-use enforcement, regeneration functionality, and usage monitoring.
    """
    
    def __init__(self):
        """Initialize the backup codes service."""
        self.audit_service = AuditService()
        
        # Configuration from settings
        self.backup_codes_count = getattr(settings, 'MFA_BACKUP_CODES_COUNT', 10)
        self.backup_code_length = getattr(settings, 'MFA_BACKUP_CODE_LENGTH', 8)
        self.backup_code_format = getattr(settings, 'MFA_BACKUP_CODE_FORMAT', 'alphanumeric')
        self.rate_limit_window = getattr(settings, 'MFA_RATE_LIMIT_WINDOW', 300)  # 5 minutes
        self.max_attempts_per_window = getattr(settings, 'MFA_MAX_ATTEMPTS_PER_WINDOW', 5)
        self.low_codes_threshold = getattr(settings, 'MFA_LOW_CODES_THRESHOLD', 3)
        
        # Character sets for different formats
        self.character_sets = {
            'alphanumeric': string.ascii_uppercase + string.digits,
            'numeric': string.digits,
            'alphabetic': string.ascii_uppercase,
            'hex': string.hexdigits.upper()[:16],  # 0-9, A-F
        }
    
    def generate_backup_codes(
        self,
        user: UserProfile,
        count: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        force_regenerate: bool = False
    ) -> Dict[str, Any]:
        """
        Generate cryptographically secure backup codes for a user.
        
        Args:
            user: User to generate backup codes for
            count: Number of backup codes to generate (defaults to configured count)
            ip_address: IP address of the request
            user_agent: User agent string
            force_regenerate: Whether to force regeneration even if codes exist
            
        Returns:
            Dictionary containing generated backup codes and metadata
            
        Raises:
            MFAError: If backup codes generation fails
        """
        try:
            count = count or self.backup_codes_count
            
            # Check if device already exists
            device = self._get_backup_codes_device(user)
            existing_codes = []
            
            # Check if codes already exist and force_regenerate is False
            if device:
                existing_codes = device.get_backup_codes()
                if existing_codes and not force_regenerate:
                    self.audit_service.log_authentication_event(
                    event_type='mfa_backup_codes_generation_skipped',
                    user=user,
                    description=f'Backup codes generation skipped - {len(existing_codes)} codes already exist',
                    request_info={
                        'ip_address': ip_address,
                        'user_agent': user_agent
                    },
                    metadata={
                        'device_id': str(device.id),
                        'existing_codes_count': len(existing_codes),
                        'force_regenerate': force_regenerate
                    }
                )
                
                return {
                    'codes': existing_codes,
                    'device_id': str(device.id),
                    'generated_at': device.updated_at.isoformat(),
                    'codes_count': len(existing_codes),
                    'regenerated': False,
                    'warning': 'Backup codes already exist. Use force_regenerate=True to create new ones.'
                }
            
            # Create device if it doesn't exist
            if not device:
                device = self._create_backup_codes_device(user, ip_address, user_agent)
            
            # Generate new cryptographically secure backup codes
            new_codes = self._generate_secure_codes(count)
            
            # Store the codes in the device
            device.set_backup_codes(new_codes)
            
            # Mark device as confirmed if not already
            if not device.is_confirmed:
                device.confirm_device(ip_address)
            
            # Log the generation
            self.audit_service.log_authentication_event(
                event_type='mfa_backup_codes_generated',
                user=user,
                description=f'Backup codes generated: {count} new codes',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_id': str(device.id),
                    'codes_generated': count,
                    'regenerated': force_regenerate,
                    'previous_codes_count': len(existing_codes) if existing_codes else 0
                }
            )
            
            return {
                'codes': new_codes,
                'device_id': str(device.id),
                'generated_at': timezone.now().isoformat(),
                'codes_count': count,
                'regenerated': force_regenerate,
                'warning': None
            }
            
        except Exception as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_backup_codes_generation_failed',
                user=user,
                description=f'Backup codes generation failed: {str(e)}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'error': str(e),
                    'count': count,
                    'force_regenerate': force_regenerate
                }
            )
            raise MFAError(f"Failed to generate backup codes: {str(e)}")
    
    def validate_backup_code(
        self,
        user: UserProfile,
        backup_code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate a backup code with single-use enforcement.
        
        Args:
            user: User attempting to use the backup code
            backup_code: Backup code to validate
            ip_address: IP address of the request
            user_agent: User agent string
            session_id: Session ID for tracking
            
        Returns:
            Dictionary containing validation result and remaining codes info
            
        Raises:
            MFARateLimitError: If rate limit exceeded
            MFADeviceNotFoundError: If no backup codes device found
            MFAVerificationError: If validation fails
        """
        start_time = timezone.now()
        
        try:
            # Check rate limiting
            self._check_rate_limit(user, ip_address)
            
            # Get backup codes device
            device = self._get_backup_codes_device(user)
            if not device:
                raise MFADeviceNotFoundError("No backup codes device found")
            
            # Normalize the backup code (remove spaces, convert to uppercase)
            normalized_code = self._normalize_backup_code(backup_code)
            
            # Validate and use the backup code (single-use enforcement)
            if device.use_backup_code(normalized_code):
                # Record successful attempt
                response_time = (timezone.now() - start_time).total_seconds() * 1000
                self._record_successful_attempt(
                    device, ip_address, user_agent, session_id, response_time
                )
                
                remaining_codes = len(device.get_backup_codes())
                
                # Check if running low on codes
                warning = None
                if remaining_codes <= self.low_codes_threshold:
                    warning = f"Only {remaining_codes} backup codes remaining. Generate new ones soon."
                
                self.audit_service.log_authentication_event(
                    event_type='mfa_backup_code_used_successfully',
                    user=user,
                    description=f'Backup code used successfully, {remaining_codes} codes remaining',
                    request_info={
                        'ip_address': ip_address,
                        'user_agent': user_agent,
                        'session_id': session_id
                    },
                    metadata={
                        'device_id': str(device.id),
                        'remaining_codes': remaining_codes,
                        'response_time_ms': response_time,
                        'low_codes_warning': warning is not None
                    }
                )
                
                return {
                    'valid': True,
                    'device_id': str(device.id),
                    'remaining_codes': remaining_codes,
                    'warning': warning,
                    'used_at': timezone.now().isoformat(),
                    'response_time_ms': response_time
                }
            else:
                # Record failed attempt
                response_time = (timezone.now() - start_time).total_seconds() * 1000
                self._record_failed_attempt(
                    device, ip_address, user_agent, session_id, 
                    'invalid_backup_code', response_time
                )
                
                self.audit_service.log_authentication_event(
                    event_type='mfa_backup_code_validation_failed',
                    user=user,
                    description='Backup code validation failed - invalid code',
                    severity='medium',
                    request_info={
                        'ip_address': ip_address,
                        'user_agent': user_agent,
                        'session_id': session_id
                    },
                    metadata={
                        'device_id': str(device.id),
                        'code_length': len(normalized_code),
                        'response_time_ms': response_time
                    }
                )
                
                raise MFAVerificationError("Invalid backup code")
                
        except (MFARateLimitError, MFADeviceNotFoundError, MFAVerificationError):
            # Re-raise known exceptions
            raise
        except Exception as e:
            response_time = (timezone.now() - start_time).total_seconds() * 1000
            
            self.audit_service.log_authentication_event(
                event_type='mfa_backup_code_validation_error',
                user=user,
                description=f'Backup code validation error: {str(e)}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'session_id': session_id
                },
                metadata={
                    'error': str(e),
                    'response_time_ms': response_time
                }
            )
            raise MFAError(f"Backup code validation failed: {str(e)}")
    
    def regenerate_backup_codes(
        self,
        user: UserProfile,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        reason: str = 'user_request'
    ) -> Dict[str, Any]:
        """
        Regenerate backup codes for a user, invalidating all existing codes.
        
        Args:
            user: User to regenerate backup codes for
            ip_address: IP address of the request
            user_agent: User agent string
            reason: Reason for regeneration
            
        Returns:
            Dictionary containing new backup codes and metadata
            
        Raises:
            MFADeviceNotFoundError: If no backup codes device found
            MFAError: If regeneration fails
        """
        try:
            # Get existing backup codes device
            device = self._get_backup_codes_device(user)
            if not device:
                raise MFADeviceNotFoundError("No backup codes device found")
            
            # Get count of existing codes for logging
            existing_codes = device.get_backup_codes()
            existing_count = len(existing_codes)
            
            # Generate new backup codes (this will replace existing ones)
            result = self.generate_backup_codes(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                force_regenerate=True
            )
            
            self.audit_service.log_authentication_event(
                event_type='mfa_backup_codes_regenerated',
                user=user,
                description=f'Backup codes regenerated: {result["codes_count"]} new codes (replaced {existing_count} existing codes)',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_id': result['device_id'],
                    'new_codes_count': result['codes_count'],
                    'previous_codes_count': existing_count,
                    'reason': reason
                }
            )
            
            # Add regeneration-specific metadata
            result.update({
                'regenerated': True,
                'previous_codes_count': existing_count,
                'reason': reason
            })
            
            return result
            
        except MFADeviceNotFoundError:
            # Re-raise known exceptions
            raise
        except Exception as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_backup_codes_regeneration_failed',
                user=user,
                description=f'Backup codes regeneration failed: {str(e)}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'error': str(e),
                    'reason': reason
                }
            )
            raise MFAError(f"Failed to regenerate backup codes: {str(e)}")
    
    def get_backup_codes_status(self, user: UserProfile) -> Dict[str, Any]:
        """
        Get the status of backup codes for a user.
        
        Args:
            user: User to get backup codes status for
            
        Returns:
            Dictionary containing backup codes status information
        """
        device = self._get_backup_codes_device(user)
        
        if not device:
            return {
                'has_backup_codes': False,
                'device_id': None,
                'remaining_codes': 0,
                'created_at': None,
                'last_used': None,
                'usage_count': 0,
                'status': 'not_configured'
            }
        
        remaining_codes = len(device.get_backup_codes())
        
        return {
            'has_backup_codes': True,
            'device_id': str(device.id),
            'remaining_codes': remaining_codes,
            'created_at': device.created_at.isoformat(),
            'last_used': device.last_used.isoformat() if device.last_used else None,
            'usage_count': device.usage_count,
            'status': device.status,
            'is_confirmed': device.is_confirmed,
            'low_codes_warning': remaining_codes <= self.low_codes_threshold
        }
    
    def get_usage_statistics(
        self,
        user: UserProfile,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get backup codes usage statistics for monitoring.
        
        Args:
            user: User to get statistics for
            days: Number of days to look back for statistics
            
        Returns:
            Dictionary containing usage statistics
        """
        device = self._get_backup_codes_device(user)
        
        if not device:
            return {
                'has_backup_codes': False,
                'statistics': None
            }
        
        # Get usage statistics from MFAAttempt records
        cutoff_date = timezone.now() - timedelta(days=days)
        
        attempts = MFAAttempt.objects.filter(
            device=device,
            created_at__gte=cutoff_date
        )
        
        total_attempts = attempts.count()
        successful_attempts = attempts.filter(result='success').count()
        failed_attempts = attempts.filter(result='failure').count()
        
        # Get recent usage patterns
        recent_usage = list(
            attempts.filter(result='success')
            .order_by('-created_at')[:10]
            .values('created_at', 'ip_address', 'user_agent')
        )
        
        return {
            'has_backup_codes': True,
            'device_id': str(device.id),
            'statistics': {
                'period_days': days,
                'total_attempts': total_attempts,
                'successful_attempts': successful_attempts,
                'failed_attempts': failed_attempts,
                'success_rate': (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0,
                'remaining_codes': len(device.get_backup_codes()),
                'total_usage_count': device.usage_count,
                'last_used': device.last_used.isoformat() if device.last_used else None,
                'recent_usage': [
                    {
                        'used_at': usage['created_at'].isoformat(),
                        'ip_address': usage['ip_address'],
                        'user_agent': usage['user_agent'][:100] if usage['user_agent'] else None
                    }
                    for usage in recent_usage
                ]
            }
        }
    
    def _generate_secure_codes(self, count: int) -> List[str]:
        """
        Generate cryptographically secure backup codes.
        
        Args:
            count: Number of codes to generate
            
        Returns:
            List of generated backup codes
        """
        character_set = self.character_sets.get(
            self.backup_code_format, 
            self.character_sets['alphanumeric']
        )
        
        codes = []
        for _ in range(count):
            # Generate cryptographically secure random code
            code = ''.join(
                secrets.choice(character_set) 
                for _ in range(self.backup_code_length)
            )
            codes.append(code)
        
        return codes
    
    def _normalize_backup_code(self, code: str) -> str:
        """
        Normalize a backup code for validation.
        
        Args:
            code: Raw backup code from user input
            
        Returns:
            Normalized backup code
        """
        # Remove whitespace and convert to uppercase
        return code.replace(' ', '').replace('-', '').upper().strip()
    
    def _create_backup_codes_device(
        self,
        user: UserProfile,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> MFADevice:
        """
        Create a backup codes device for a user without generating codes.
        
        Args:
            user: User to create device for
            ip_address: IP address for device creation
            user_agent: User agent for device creation
            
        Returns:
            MFADevice instance for backup codes
        """
        device = MFADevice.objects.create(
            user=user,
            device_type='backup_codes',
            device_name='Backup Codes',
            created_ip=ip_address,
            created_user_agent=user_agent
        )
        return device
    
    def _get_backup_codes_device(self, user: UserProfile) -> Optional[MFADevice]:
        """
        Get the backup codes device for a user.
        
        Args:
            user: User to get device for
            
        Returns:
            MFADevice instance or None if not found
        """
        return MFADevice.objects.get_backup_codes_device(user)
    
    def _check_rate_limit(self, user: UserProfile, ip_address: Optional[str]) -> None:
        """
        Check rate limiting for backup code attempts.
        
        Args:
            user: User making the attempt
            ip_address: IP address of the attempt
            
        Raises:
            MFARateLimitError: If rate limit exceeded
        """
        # Check user-based rate limiting
        user_key = f"backup_codes_attempts:user:{user.id}"
        user_attempts = cache.get(user_key, 0)
        
        if user_attempts >= self.max_attempts_per_window:
            raise MFARateLimitError("Too many backup code attempts. Please try again later.")
        
        # Check IP-based rate limiting if IP is provided
        if ip_address:
            ip_key = f"backup_codes_attempts:ip:{ip_address}"
            ip_attempts = cache.get(ip_key, 0)
            
            if ip_attempts >= self.max_attempts_per_window * 2:  # Higher limit for IP
                raise MFARateLimitError("Too many backup code attempts from this IP. Please try again later.")
    
    def _record_successful_attempt(
        self,
        device: MFADevice,
        ip_address: Optional[str],
        user_agent: Optional[str],
        session_id: Optional[str],
        response_time_ms: float
    ) -> None:
        """
        Record a successful backup code attempt.
        
        Args:
            device: MFA device used
            ip_address: IP address of the attempt
            user_agent: User agent string
            session_id: Session ID
            response_time_ms: Response time in milliseconds
        """
        # Record in database
        MFAAttempt.objects.create(
            user=device.user,
            device=device,
            result='success',
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent,
            session_id=session_id,
            response_time_ms=int(response_time_ms)
        )
        
        # Mark device as used
        device.mark_as_used(ip_address)
        
        # Clear rate limiting counters on success
        user_key = f"backup_codes_attempts:user:{device.user.id}"
        cache.delete(user_key)
        
        if ip_address:
            ip_key = f"backup_codes_attempts:ip:{ip_address}"
            cache.delete(ip_key)
    
    def _record_failed_attempt(
        self,
        device: MFADevice,
        ip_address: Optional[str],
        user_agent: Optional[str],
        session_id: Optional[str],
        failure_reason: str,
        response_time_ms: float
    ) -> None:
        """
        Record a failed backup code attempt.
        
        Args:
            device: MFA device used
            ip_address: IP address of the attempt
            user_agent: User agent string
            session_id: Session ID
            failure_reason: Reason for failure
            response_time_ms: Response time in milliseconds
        """
        # Record in database
        MFAAttempt.objects.create(
            user=device.user,
            device=device,
            result='failure',
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent,
            session_id=session_id,
            failure_reason=failure_reason,
            response_time_ms=int(response_time_ms)
        )
        
        # Update rate limiting counters
        user_key = f"backup_codes_attempts:user:{device.user.id}"
        cache.set(user_key, cache.get(user_key, 0) + 1, self.rate_limit_window)
        
        if ip_address:
            ip_key = f"backup_codes_attempts:ip:{ip_address}"
            cache.set(ip_key, cache.get(ip_key, 0) + 1, self.rate_limit_window)


# Global service instance
backup_codes_service = BackupCodesService()