"""
Monitoring utilities for OAuth and authentication metrics.

This module provides utilities for recording and tracking OAuth authentication
metrics, errors, and security events for monitoring and alerting.
"""

import logging
from typing import Any, Dict, Optional
from datetime import datetime, timedelta

from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

logger = logging.getLogger(__name__)


class OAuthMetrics:
    """
    OAuth metrics collection and monitoring service.
    
    This service collects and tracks OAuth authentication metrics,
    errors, and security events for monitoring and alerting purposes.
    """
    
    def __init__(self):
        """Initialize the OAuth metrics service."""
        self.cache_prefix = 'oauth_metrics'
        self.cache_timeout = 3600  # 1 hour
    
    def record_provider_error(
        self,
        provider: str,
        error_code: str,
        error_description: str
    ) -> None:
        """
        Record OAuth provider error for monitoring.
        
        Args:
            provider: OAuth provider name
            error_code: OAuth error code
            error_description: Error description
        """
        try:
            # Increment error counter
            error_key = f"{self.cache_prefix}:provider_errors:{provider}:{error_code}"
            current_count = cache.get(error_key, 0)
            cache.set(error_key, current_count + 1, self.cache_timeout)
            
            # Record error details
            error_details = {
                'provider': provider,
                'error_code': error_code,
                'error_description': error_description,
                'timestamp': timezone.now().isoformat(),
            }
            
            # Store recent errors for debugging
            recent_errors_key = f"{self.cache_prefix}:recent_errors:{provider}"
            recent_errors = cache.get(recent_errors_key, [])
            recent_errors.append(error_details)
            
            # Keep only last 10 errors
            if len(recent_errors) > 10:
                recent_errors = recent_errors[-10:]
            
            cache.set(recent_errors_key, recent_errors, self.cache_timeout)
            
            # Log structured error
            logger.warning(
                f"OAuth provider error recorded: {provider}",
                extra={
                    'provider': provider,
                    'error_code': error_code,
                    'error_description': error_description,
                    'metric_type': 'oauth_provider_error',
                }
            )
            
            # Check for error rate threshold
            self._check_error_rate_threshold(provider, error_code)
            
        except Exception as e:
            logger.error(f"Failed to record OAuth provider error: {e}")
    
    def record_callback_error(
        self,
        provider: str,
        error_type: str
    ) -> None:
        """
        Record OAuth callback error for monitoring.
        
        Args:
            provider: OAuth provider name
            error_type: Type of callback error
        """
        try:
            # Increment callback error counter
            error_key = f"{self.cache_prefix}:callback_errors:{provider}:{error_type}"
            current_count = cache.get(error_key, 0)
            cache.set(error_key, current_count + 1, self.cache_timeout)
            
            # Record total callback errors
            total_key = f"{self.cache_prefix}:callback_errors:total"
            total_count = cache.get(total_key, 0)
            cache.set(total_key, total_count + 1, self.cache_timeout)
            
            logger.info(
                f"OAuth callback error recorded: {provider}",
                extra={
                    'provider': provider,
                    'error_type': error_type,
                    'metric_type': 'oauth_callback_error',
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to record OAuth callback error: {e}")
    
    def record_security_event(
        self,
        provider: str,
        event_type: str,
        severity: str = 'medium'
    ) -> None:
        """
        Record OAuth security event for monitoring.
        
        Args:
            provider: OAuth provider name
            event_type: Type of security event
            severity: Event severity (low, medium, high, critical)
        """
        try:
            # Increment security event counter
            event_key = f"{self.cache_prefix}:security_events:{provider}:{event_type}"
            current_count = cache.get(event_key, 0)
            cache.set(event_key, current_count + 1, self.cache_timeout)
            
            # Record by severity
            severity_key = f"{self.cache_prefix}:security_events:severity:{severity}"
            severity_count = cache.get(severity_key, 0)
            cache.set(severity_key, severity_count + 1, self.cache_timeout)
            
            logger.warning(
                f"OAuth security event recorded: {provider}",
                extra={
                    'provider': provider,
                    'event_type': event_type,
                    'severity': severity,
                    'metric_type': 'oauth_security_event',
                }
            )
            
            # Alert on high severity events
            if severity in ['high', 'critical']:
                self._trigger_security_alert(provider, event_type, severity)
            
        except Exception as e:
            logger.error(f"Failed to record OAuth security event: {e}")
    
    def record_successful_authentication(
        self,
        provider: str,
        user_id: str,
        is_new_user: bool,
        correlation_id: str
    ) -> None:
        """
        Record successful OAuth authentication for monitoring.
        
        Args:
            provider: OAuth provider name
            user_id: User ID
            is_new_user: Whether this is a new user
            correlation_id: Request correlation ID
        """
        try:
            # Increment success counter
            success_key = f"{self.cache_prefix}:successful_auth:{provider}"
            current_count = cache.get(success_key, 0)
            cache.set(success_key, current_count + 1, self.cache_timeout)
            
            # Track new user registrations
            if is_new_user:
                new_user_key = f"{self.cache_prefix}:new_users:{provider}"
                new_user_count = cache.get(new_user_key, 0)
                cache.set(new_user_key, new_user_count + 1, self.cache_timeout)
            
            # Record total successful authentications
            total_key = f"{self.cache_prefix}:successful_auth:total"
            total_count = cache.get(total_key, 0)
            cache.set(total_key, total_count + 1, self.cache_timeout)
            
            logger.info(
                f"OAuth successful authentication recorded: {provider}",
                extra={
                    'provider': provider,
                    'user_id': user_id,
                    'is_new_user': is_new_user,
                    'correlation_id': correlation_id,
                    'metric_type': 'oauth_successful_auth',
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to record OAuth successful authentication: {e}")
    
    def get_provider_metrics(self, provider: str) -> Dict[str, Any]:
        """
        Get metrics for a specific OAuth provider.
        
        Args:
            provider: OAuth provider name
            
        Returns:
            Dictionary containing provider metrics
        """
        try:
            metrics = {
                'provider': provider,
                'successful_authentications': 0,
                'new_user_registrations': 0,
                'callback_errors': {},
                'provider_errors': {},
                'security_events': {},
                'recent_errors': [],
            }
            
            # Get successful authentications
            success_key = f"{self.cache_prefix}:successful_auth:{provider}"
            metrics['successful_authentications'] = cache.get(success_key, 0)
            
            # Get new user registrations
            new_user_key = f"{self.cache_prefix}:new_users:{provider}"
            metrics['new_user_registrations'] = cache.get(new_user_key, 0)
            
            # Get recent errors
            recent_errors_key = f"{self.cache_prefix}:recent_errors:{provider}"
            metrics['recent_errors'] = cache.get(recent_errors_key, [])
            
            # Get callback error counts
            callback_error_types = [
                'missing_parameters', 'processing_error', 'missing_user_data',
                'user_creation_error', 'token_generation_error', 'provider_not_found',
                'provider_unavailable', 'oauth_error', 'unexpected_error'
            ]
            
            for error_type in callback_error_types:
                error_key = f"{self.cache_prefix}:callback_errors:{provider}:{error_type}"
                count = cache.get(error_key, 0)
                if count > 0:
                    metrics['callback_errors'][error_type] = count
            
            # Calculate success rate
            total_attempts = metrics['successful_authentications'] + sum(metrics['callback_errors'].values())
            if total_attempts > 0:
                metrics['success_rate'] = metrics['successful_authentications'] / total_attempts
            else:
                metrics['success_rate'] = 0.0
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get provider metrics for {provider}: {e}")
            return {'provider': provider, 'error': str(e)}
    
    def get_overall_metrics(self) -> Dict[str, Any]:
        """
        Get overall OAuth metrics across all providers.
        
        Returns:
            Dictionary containing overall metrics
        """
        try:
            metrics = {
                'total_successful_authentications': 0,
                'total_callback_errors': 0,
                'security_events_by_severity': {},
                'timestamp': timezone.now().isoformat(),
            }
            
            # Get total successful authentications
            total_success_key = f"{self.cache_prefix}:successful_auth:total"
            metrics['total_successful_authentications'] = cache.get(total_success_key, 0)
            
            # Get total callback errors
            total_errors_key = f"{self.cache_prefix}:callback_errors:total"
            metrics['total_callback_errors'] = cache.get(total_errors_key, 0)
            
            # Get security events by severity
            severities = ['low', 'medium', 'high', 'critical']
            for severity in severities:
                severity_key = f"{self.cache_prefix}:security_events:severity:{severity}"
                count = cache.get(severity_key, 0)
                if count > 0:
                    metrics['security_events_by_severity'][severity] = count
            
            # Calculate overall success rate
            total_attempts = metrics['total_successful_authentications'] + metrics['total_callback_errors']
            if total_attempts > 0:
                metrics['overall_success_rate'] = metrics['total_successful_authentications'] / total_attempts
            else:
                metrics['overall_success_rate'] = 0.0
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get overall OAuth metrics: {e}")
            return {'error': str(e)}
    
    def _check_error_rate_threshold(self, provider: str, error_code: str) -> None:
        """Check if error rate exceeds threshold and trigger alerts."""
        try:
            # Get error count for the last hour
            error_key = f"{self.cache_prefix}:provider_errors:{provider}:{error_code}"
            error_count = cache.get(error_key, 0)
            
            # Get success count for comparison
            success_key = f"{self.cache_prefix}:successful_auth:{provider}"
            success_count = cache.get(success_key, 0)
            
            # Calculate error rate
            total_attempts = error_count + success_count
            if total_attempts > 0:
                error_rate = error_count / total_attempts
                
                # Check threshold (configurable via settings)
                error_threshold = getattr(settings, 'OAUTH_ERROR_RATE_THRESHOLD', 0.1)  # 10%
                
                if error_rate > error_threshold and total_attempts >= 10:  # Minimum attempts for meaningful rate
                    logger.error(
                        f"OAuth error rate threshold exceeded for {provider}",
                        extra={
                            'provider': provider,
                            'error_code': error_code,
                            'error_rate': error_rate,
                            'threshold': error_threshold,
                            'total_attempts': total_attempts,
                            'alert_type': 'error_rate_threshold',
                        }
                    )
                    
                    # Trigger alert (could integrate with external alerting systems)
                    self._trigger_error_rate_alert(provider, error_code, error_rate)
            
        except Exception as e:
            logger.error(f"Failed to check error rate threshold: {e}")
    
    def _trigger_security_alert(self, provider: str, event_type: str, severity: str) -> None:
        """Trigger security alert for high-severity events."""
        try:
            alert_data = {
                'alert_type': 'oauth_security_event',
                'provider': provider,
                'event_type': event_type,
                'severity': severity,
                'timestamp': timezone.now().isoformat(),
            }
            
            logger.critical(
                f"OAuth security alert triggered for {provider}",
                extra=alert_data
            )
            
            # Here you could integrate with external alerting systems
            # like PagerDuty, Slack, email notifications, etc.
            
        except Exception as e:
            logger.error(f"Failed to trigger security alert: {e}")
    
    def _trigger_error_rate_alert(self, provider: str, error_code: str, error_rate: float) -> None:
        """Trigger error rate alert."""
        try:
            alert_data = {
                'alert_type': 'oauth_error_rate',
                'provider': provider,
                'error_code': error_code,
                'error_rate': error_rate,
                'timestamp': timezone.now().isoformat(),
            }
            
            logger.critical(
                f"OAuth error rate alert triggered for {provider}",
                extra=alert_data
            )
            
            # Here you could integrate with external alerting systems
            
        except Exception as e:
            logger.error(f"Failed to trigger error rate alert: {e}")


# Global OAuth metrics instance
oauth_metrics = OAuthMetrics()