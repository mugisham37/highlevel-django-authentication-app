"""
Monitoring middleware for request tracking and observability.
"""

import time
import uuid
import logging
from typing import Optional
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpRequest, HttpResponse
from django.urls import resolve
from .logging_config import (
    set_correlation_id, 
    set_request_context, 
    clear_request_context,
    get_structured_logger
)
from .performance import performance_collector
from .metrics import business_metrics_collector, security_metrics_collector

logger = get_structured_logger(__name__)


class CorrelationIDMiddleware(MiddlewareMixin):
    """Middleware to add correlation ID to requests and responses."""
    
    def process_request(self, request: HttpRequest) -> None:
        """Process incoming request to set correlation ID."""
        # Check if correlation ID is provided in headers
        correlation_id = request.META.get('HTTP_X_CORRELATION_ID')
        
        if not correlation_id:
            # Generate new correlation ID
            correlation_id = str(uuid.uuid4())
        
        # Set correlation ID in thread local storage
        set_correlation_id(correlation_id)
        
        # Store in request for later use
        request.correlation_id = correlation_id
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Process response to add correlation ID header."""
        if hasattr(request, 'correlation_id'):
            response['X-Correlation-ID'] = request.correlation_id
        
        return response


class RequestContextMiddleware(MiddlewareMixin):
    """Middleware to set request context for logging."""
    
    def process_request(self, request: HttpRequest) -> None:
        """Set request context for structured logging."""
        # Get user ID if authenticated
        user_id = None
        if hasattr(request, 'user') and request.user.is_authenticated:
            user_id = str(request.user.pk)
        
        # Get IP address
        ip_address = self._get_client_ip(request)
        
        # Get user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Get endpoint information
        try:
            resolved = resolve(request.path)
            endpoint = f"{resolved.namespace}:{resolved.url_name}" if resolved.namespace else resolved.url_name
        except:
            endpoint = request.path
        
        # Set request context
        set_request_context(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            method=request.method
        )
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Clear request context after response."""
        clear_request_context()
        return response
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip


class MonitoringMiddleware(MiddlewareMixin):
    """Comprehensive monitoring middleware for performance and business metrics."""
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.excluded_paths = [
            '/health/',
            '/metrics/',
            '/static/',
            '/media/',
            '/admin/jsi18n/',
            '/favicon.ico'
        ]
    
    def process_request(self, request: HttpRequest) -> None:
        """Start request monitoring."""
        # Skip monitoring for excluded paths
        if any(request.path.startswith(path) for path in self.excluded_paths):
            return
        
        # Record request start time
        request._monitoring_start_time = time.time()
        
        # Log request start
        logger.info(
            "Request started",
            method=request.method,
            path=request.path,
            event_type="request_start"
        )
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Process response and record metrics."""
        # Skip monitoring for excluded paths
        if any(request.path.startswith(path) for path in self.excluded_paths):
            return response
        
        # Skip if start time not recorded
        if not hasattr(request, '_monitoring_start_time'):
            return response
        
        # Calculate request duration
        duration = time.time() - request._monitoring_start_time
        duration_ms = duration * 1000
        
        # Get endpoint information
        try:
            resolved = resolve(request.path)
            endpoint = f"{resolved.namespace}:{resolved.url_name}" if resolved.namespace else resolved.url_name
        except:
            endpoint = request.path
        
        # Record performance metrics
        performance_collector.record_request_duration(
            method=request.method,
            endpoint=endpoint,
            status_code=response.status_code,
            duration=duration
        )
        
        # Record business metrics for authentication endpoints
        if self._is_auth_endpoint(endpoint):
            self._record_auth_metrics(request, response, endpoint)
        
        # Record security metrics
        self._record_security_metrics(request, response, duration_ms)
        
        # Log request completion
        logger.info(
            "Request completed",
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            event_type="request_complete"
        )
        
        return response
    
    def _is_auth_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is authentication-related."""
        auth_endpoints = [
            'auth:login',
            'auth:register',
            'auth:logout',
            'auth:refresh',
            'oauth:callback',
            'mfa:verify'
        ]
        return any(auth_endpoint in endpoint for auth_endpoint in auth_endpoints)
    
    def _record_auth_metrics(self, request: HttpRequest, response: HttpResponse, endpoint: str):
        """Record authentication-specific metrics."""
        # Determine authentication method
        auth_method = 'password'  # default
        provider = None
        
        if 'oauth' in endpoint:
            auth_method = 'oauth'
            # Extract provider from path or request data
            if hasattr(request, 'resolver_match') and request.resolver_match.kwargs:
                provider = request.resolver_match.kwargs.get('provider')
        elif 'mfa' in endpoint:
            auth_method = 'mfa'
        
        # Determine success based on status code
        success = 200 <= response.status_code < 400
        
        # Get device type from user agent
        device_type = self._get_device_type(request.META.get('HTTP_USER_AGENT', ''))
        
        # Record authentication attempt
        business_metrics_collector.record_authentication_attempt(
            method=auth_method,
            provider=provider,
            success=success,
            device_type=device_type
        )
        
        # Record OAuth usage if applicable
        if provider:
            business_metrics_collector.record_oauth_usage(
                provider=provider,
                action='authenticate',
                success=success
            )
    
    def _record_security_metrics(self, request: HttpRequest, response: HttpResponse, duration_ms: float):
        """Record security-related metrics."""
        # Record failed authentication attempts
        if response.status_code == 401:
            ip_address = self._get_client_ip(request)
            security_metrics_collector.record_attack_attempt(
                attack_type='failed_auth',
                source_ip=ip_address,
                blocked=False
            )
        
        # Record potential brute force attempts
        if response.status_code == 429:  # Too Many Requests
            ip_address = self._get_client_ip(request)
            security_metrics_collector.record_brute_force_attempt(
                target_type='api_endpoint',
                source_ip=ip_address
            )
    
    def _get_device_type(self, user_agent: str) -> str:
        """Extract device type from user agent."""
        user_agent_lower = user_agent.lower()
        
        if 'mobile' in user_agent_lower or 'android' in user_agent_lower or 'iphone' in user_agent_lower:
            return 'mobile'
        elif 'tablet' in user_agent_lower or 'ipad' in user_agent_lower:
            return 'tablet'
        else:
            return 'desktop'
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip


class SecurityMonitoringMiddleware(MiddlewareMixin):
    """Security-focused monitoring middleware."""
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.suspicious_patterns = [
            'sql injection',
            'xss',
            'script',
            'union select',
            'drop table',
            '../',
            '..\\',
            'eval(',
            'exec(',
            'system(',
            'shell_exec'
        ]
    
    def process_request(self, request: HttpRequest) -> None:
        """Monitor request for security threats."""
        # Check for suspicious patterns in request
        self._check_suspicious_patterns(request)
        
        # Monitor for potential attacks
        self._monitor_attack_patterns(request)
    
    def _check_suspicious_patterns(self, request: HttpRequest):
        """Check request for suspicious patterns."""
        # Check query parameters
        query_string = request.META.get('QUERY_STRING', '').lower()
        
        # Check POST data
        post_data = ''
        if request.method == 'POST' and hasattr(request, 'body'):
            try:
                post_data = request.body.decode('utf-8', errors='ignore').lower()
            except:
                pass
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern in query_string or pattern in post_data:
                self._log_security_event(
                    request,
                    'suspicious_pattern_detected',
                    f"Suspicious pattern detected: {pattern}"
                )
                break
    
    def _monitor_attack_patterns(self, request: HttpRequest):
        """Monitor for common attack patterns."""
        # Check for potential SQL injection
        if self._is_potential_sql_injection(request):
            self._log_security_event(
                request,
                'potential_sql_injection',
                "Potential SQL injection attempt detected"
            )
        
        # Check for potential XSS
        if self._is_potential_xss(request):
            self._log_security_event(
                request,
                'potential_xss',
                "Potential XSS attempt detected"
            )
        
        # Check for directory traversal
        if self._is_potential_directory_traversal(request):
            self._log_security_event(
                request,
                'potential_directory_traversal',
                "Potential directory traversal attempt detected"
            )
    
    def _is_potential_sql_injection(self, request: HttpRequest) -> bool:
        """Check for potential SQL injection patterns."""
        sql_patterns = ['union select', 'drop table', 'insert into', 'delete from', '--', ';--']
        
        query_string = request.META.get('QUERY_STRING', '').lower()
        return any(pattern in query_string for pattern in sql_patterns)
    
    def _is_potential_xss(self, request: HttpRequest) -> bool:
        """Check for potential XSS patterns."""
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'eval(']
        
        query_string = request.META.get('QUERY_STRING', '').lower()
        return any(pattern in query_string for pattern in xss_patterns)
    
    def _is_potential_directory_traversal(self, request: HttpRequest) -> bool:
        """Check for potential directory traversal patterns."""
        traversal_patterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c']
        
        path = request.path.lower()
        query_string = request.META.get('QUERY_STRING', '').lower()
        
        return any(pattern in path or pattern in query_string for pattern in traversal_patterns)
    
    def _log_security_event(self, request: HttpRequest, event_type: str, message: str):
        """Log security event."""
        ip_address = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        logger.warning(
            message,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            path=request.path,
            method=request.method,
            query_string=request.META.get('QUERY_STRING', '')
        )
        
        # Record security metric
        security_metrics_collector.record_threat_detection(
            threat_type=event_type,
            severity='medium',
            source=ip_address
        )
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip