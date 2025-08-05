"""
Comprehensive security middleware for enterprise authentication system.

This middleware integrates threat detection, rate limiting, security event logging,
and automated response capabilities into the request/response cycle.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser

from ..models import UserProfile, UserSession, SecurityEvent
from ..exceptions import (
    RateLimitExceededError, SecurityError, ThreatDetectedError,
    SuspiciousActivityError
)
from ..services.threat_detection_service import (
    threat_detection_service, ThreatDetectionService,
    LoginAttemptContext, ThreatLevel
)
from ..services.rate_limiting_service import (
    rate_limiting_service, RateLimitingService,
    RateLimitContext, RateLimitType, RateLimitAction
)
from ..services.security_event_service import (
    security_event_service, SecurityEventService,
    SecurityEventData, EventSeverity
)


logger = logging.getLogger(__name__)
User = get_user_model()


class SecurityMiddleware(MiddlewareMixin):
    """
    Comprehensive security middleware that provides:
    - Threat detection and analysis
    - Multi-level rate limiting
    - Security event logging
    - Automated threat response
    - Request/response security headers
    """

    def __init__(self, get_response: Callable):
        """Initialize security middleware."""
        self.get_response = get_response
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Service instances
        self.threat_detection = threat_detection_service
        self.rate_limiting = rate_limiting_service
        self.security_events = security_event_service
        
        # Configuration
        self.enabled = getattr(settings, 'SECURITY_MIDDLEWARE_ENABLED', True)
        self.threat_detection_enabled = getattr(
            settings, 'THREAT_DETECTION_ENABLED', True
        )
        self.rate_limiting_enabled = getattr(
            settings, 'RATE_LIMITING_ENABLED', True
        )
        self.security_logging_enabled = getattr(
            settings, 'SECURITY_LOGGING_ENABLED', True
        )
        
        # Excluded paths
        self.excluded_paths = getattr(settings, 'SECURITY_MIDDLEWARE_EXCLUDED_PATHS', [
            '/health/',
            '/metrics/',
            '/static/',
            '/media/',
        ])
        
        # Authentication endpoints
        self.auth_endpoints = getattr(settings, 'AUTHENTICATION_ENDPOINTS', [
            '/api/v1/auth/login',
            '/api/v1/auth/register',
            '/api/v1/auth/refresh',
            '/api/v1/oauth/',
        ])
        
        super().__init__(get_response)
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process request through security middleware."""
        if not self.enabled or self._should_exclude_path(request.path):
            return self.get_response(request)
        
        # Generate correlation ID for request tracking
        correlation_id = str(uuid.uuid4())
        request.correlation_id = correlation_id
        
        # Add security headers to request context
        self._add_security_context(request)
        
        try:
            # Pre-process security checks
            security_result = self._process_request_security(request)
            
            if security_result.get('blocked'):
                return self._create_security_response(
                    security_result, request
                )
            
            # Process request
            response = self.get_response(request)
            
            # Post-process security logging
            self._process_response_security(request, response)
            
            # Add security headers to response
            self._add_security_headers(response)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Security middleware error: {e}")
            
            # Log security error
            if self.security_logging_enabled:
                asyncio.run(self._log_security_error(request, e))
            
            # Continue with request processing
            response = self.get_response(request)
            self._add_security_headers(response)
            return response
    
    def _should_exclude_path(self, path: str) -> bool:
        """Check if path should be excluded from security processing."""
        for excluded_path in self.excluded_paths:
            if path.startswith(excluded_path):
                return True
        return False
    
    def _add_security_context(self, request: HttpRequest) -> None:
        """Add security context to request."""
        # Extract client information
        request.client_ip = self._get_client_ip(request)
        request.user_agent = request.META.get('HTTP_USER_AGENT', '')
        request.device_fingerprint = self._generate_device_fingerprint(request)
        
        # Security flags
        request.is_auth_endpoint = any(
            request.path.startswith(endpoint) 
            for endpoint in self.auth_endpoints
        )
        request.is_trusted_source = self._is_trusted_source(request)
        
        # Request metadata
        request.security_metadata = {
            'timestamp': timezone.now(),
            'method': request.method,
            'path': request.path,
            'query_params': dict(request.GET),
            'content_type': request.content_type,
            'content_length': request.META.get('CONTENT_LENGTH', 0),
        }
    
    def _process_request_security(self, request: HttpRequest) -> Dict[str, Any]:
        """Process request security checks."""
        security_result = {
            'blocked': False,
            'reason': '',
            'actions': [],
            'metadata': {}
        }
        
        try:
            # Rate limiting check
            if self.rate_limiting_enabled:
                rate_limit_result = self._check_rate_limits(request)
                if rate_limit_result['blocked']:
                    security_result.update(rate_limit_result)
                    return security_result
            
            # Threat detection for authentication endpoints
            if (self.threat_detection_enabled and 
                request.is_auth_endpoint and 
                request.method == 'POST'):
                
                threat_result = self._check_threats(request)
                if threat_result['blocked']:
                    security_result.update(threat_result)
                    return security_result
            
            # Additional security checks
            malicious_payload_result = self._check_malicious_payload(request)
            if malicious_payload_result['blocked']:
                security_result.update(malicious_payload_result)
                return security_result
            
        except Exception as e:
            self.logger.error(f"Request security processing failed: {e}")
        
        return security_result
    
    def _check_rate_limits(self, request: HttpRequest) -> Dict[str, Any]:
        """Check rate limits for request."""
        try:
            # Create rate limiting context
            context = RateLimitContext(
                ip_address=request.client_ip,
                user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                endpoint=request.path,
                user_agent=request.user_agent,
                is_trusted_source=request.is_trusted_source,
                correlation_id=request.correlation_id
            )
            
            # Check rate limits
            rate_limit_results = asyncio.run(
                self.rate_limiting.check_rate_limit(context, request.path)
            )
            
            # Find first blocking result
            for result in rate_limit_results:
                if not result.allowed:
                    # Increment counter for this request
                    asyncio.run(
                        self.rate_limiting.increment_counter(context, request.path)
                    )
                    
                    # Log rate limit violation
                    if self.security_logging_enabled:
                        asyncio.run(self._log_rate_limit_violation(request, result))
                    
                    return {
                        'blocked': True,
                        'reason': 'rate_limit_exceeded',
                        'rate_limit_result': result,
                        'retry_after': result.retry_after,
                        'delay_seconds': result.delay_seconds
                    }
            
            # Increment counters for allowed request
            asyncio.run(
                self.rate_limiting.increment_counter(context, request.path)
            )
            
        except Exception as e:
            self.logger.error(f"Rate limit check failed: {e}")
        
        return {'blocked': False}
    
    def _check_threats(self, request: HttpRequest) -> Dict[str, Any]:
        """Check for security threats."""
        try:
            # Create threat detection context
            context = LoginAttemptContext(
                user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                ip_address=request.client_ip,
                user_agent=request.user_agent,
                timestamp=timezone.now(),
                success=False,  # Will be updated after authentication
                device_fingerprint=request.device_fingerprint,
                correlation_id=request.correlation_id
            )
            
            # Perform threat analysis
            threat_analysis = asyncio.run(
                self.threat_detection.analyze_login_attempt(context)
            )
            
            # Check if threat level requires blocking
            if threat_analysis.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                # Check for immediate blocking actions
                if 'block_request' in threat_analysis.recommended_actions:
                    return {
                        'blocked': True,
                        'reason': 'threat_detected',
                        'threat_analysis': threat_analysis,
                        'risk_score': threat_analysis.risk_score
                    }
            
            # Store threat analysis for post-processing
            request.threat_analysis = threat_analysis
            
        except Exception as e:
            self.logger.error(f"Threat detection failed: {e}")
        
        return {'blocked': False}
    
    def _check_malicious_payload(self, request: HttpRequest) -> Dict[str, Any]:
        """Check for malicious payload patterns."""
        try:
            # Check for common attack patterns
            malicious_patterns = [
                # SQL injection patterns
                r"(\bunion\b.*\bselect\b)|(\bselect\b.*\bfrom\b)",
                r"(\bdrop\b.*\btable\b)|(\bdelete\b.*\bfrom\b)",
                r"(\binsert\b.*\binto\b)|(\bupdate\b.*\bset\b)",
                
                # XSS patterns
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                
                # Command injection patterns
                r"(\b(cat|ls|pwd|whoami|id|uname)\b)",
                r"(\||;|&&|\$\(|\`)",
                
                # Path traversal patterns
                r"(\.\./){2,}",
                r"\\\.\\\.\\",
            ]
            
            # Check request body and parameters
            content_to_check = []
            
            # Add query parameters
            for key, value in request.GET.items():
                content_to_check.extend([key, value])
            
            # Add POST data if available
            if hasattr(request, 'POST'):
                for key, value in request.POST.items():
                    content_to_check.extend([key, value])
            
            # Add request body if JSON
            if (request.content_type == 'application/json' and 
                hasattr(request, 'body')):
                try:
                    body_data = json.loads(request.body)
                    content_to_check.append(json.dumps(body_data))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            
            # Check for malicious patterns
            import re
            for content in content_to_check:
                if isinstance(content, str):
                    for pattern in malicious_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            # Log malicious payload detection
                            if self.security_logging_enabled:
                                asyncio.run(self._log_malicious_payload(
                                    request, pattern, content
                                ))
                            
                            return {
                                'blocked': True,
                                'reason': 'malicious_payload',
                                'pattern': pattern,
                                'content_sample': content[:100]
                            }
            
        except Exception as e:
            self.logger.error(f"Malicious payload check failed: {e}")
        
        return {'blocked': False}
    
    def _process_response_security(
        self,
        request: HttpRequest,
        response: HttpResponse
    ) -> None:
        """Process response security logging."""
        try:
            if not self.security_logging_enabled:
                return
            
            # Log authentication attempts
            if request.is_auth_endpoint:
                asyncio.run(self._log_authentication_attempt(request, response))
            
            # Log high-risk requests
            if hasattr(request, 'threat_analysis'):
                threat_analysis = request.threat_analysis
                if threat_analysis.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    asyncio.run(self._log_high_risk_request(request, response))
            
            # Log security events based on response status
            if response.status_code >= 400:
                asyncio.run(self._log_error_response(request, response))
            
        except Exception as e:
            self.logger.error(f"Response security processing failed: {e}")
    
    def _create_security_response(
        self,
        security_result: Dict[str, Any],
        request: HttpRequest
    ) -> HttpResponse:
        """Create security response for blocked requests."""
        reason = security_result.get('reason', 'security_violation')
        
        if reason == 'rate_limit_exceeded':
            rate_limit_result = security_result.get('rate_limit_result')
            
            response_data = {
                'error': {
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'message': 'Rate limit exceeded',
                    'details': {
                        'limit': rate_limit_result.limit,
                        'window_seconds': rate_limit_result.window_seconds,
                        'retry_after': rate_limit_result.retry_after
                    }
                }
            }
            
            response = JsonResponse(response_data, status=429)
            
            if rate_limit_result.retry_after:
                response['Retry-After'] = str(rate_limit_result.retry_after)
            
            # Apply progressive delay if configured
            if rate_limit_result.delay_seconds:
                time.sleep(min(rate_limit_result.delay_seconds, 5.0))  # Cap at 5 seconds
            
            return response
        
        elif reason == 'threat_detected':
            threat_analysis = security_result.get('threat_analysis')
            
            response_data = {
                'error': {
                    'code': 'SECURITY_THREAT_DETECTED',
                    'message': 'Security threat detected',
                    'details': {
                        'risk_score': threat_analysis.risk_score,
                        'threat_level': threat_analysis.threat_level.value
                    }
                }
            }
            
            return JsonResponse(response_data, status=403)
        
        elif reason == 'malicious_payload':
            response_data = {
                'error': {
                    'code': 'MALICIOUS_PAYLOAD_DETECTED',
                    'message': 'Malicious payload detected',
                    'details': {
                        'pattern': security_result.get('pattern', 'unknown')
                    }
                }
            }
            
            return JsonResponse(response_data, status=400)
        
        # Default security response
        response_data = {
            'error': {
                'code': 'SECURITY_VIOLATION',
                'message': 'Security policy violation',
                'details': {}
            }
        }
        
        return JsonResponse(response_data, status=403)
    
    def _add_security_headers(self, response: HttpResponse) -> None:
        """Add security headers to response."""
        # Security headers
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        }
        
        for header, value in security_headers.items():
            if header not in response:
                response[header] = value
    
    # Helper methods
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP address from request."""
        # Check for forwarded headers (in order of preference)
        forwarded_headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CF_CONNECTING_IP',  # Cloudflare
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
        ]
        
        for header in forwarded_headers:
            ip = request.META.get(header)
            if ip:
                # Handle comma-separated IPs (take first one)
                ip = ip.split(',')[0].strip()
                if ip:
                    return ip
        
        # Fallback to REMOTE_ADDR
        return request.META.get('REMOTE_ADDR', '127.0.0.1')
    
    def _generate_device_fingerprint(self, request: HttpRequest) -> str:
        """Generate device fingerprint from request headers."""
        import hashlib
        
        fingerprint_data = [
            request.META.get('HTTP_USER_AGENT', ''),
            request.META.get('HTTP_ACCEPT', ''),
            request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
            request.META.get('HTTP_ACCEPT_ENCODING', ''),
        ]
        
        fingerprint_string = '|'.join(fingerprint_data)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:32]
    
    def _is_trusted_source(self, request: HttpRequest) -> bool:
        """Check if request comes from trusted source."""
        # Check for internal IP ranges
        internal_ranges = [
            '127.0.0.0/8',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
        ]
        
        # Simple check for internal IPs (production should use proper IP validation)
        client_ip = request.client_ip
        
        if client_ip.startswith('127.') or client_ip.startswith('10.'):
            return True
        
        # Check trusted source cache
        cache_key = f"trusted_source:{client_ip}"
        return cache.get(cache_key, False)
    
    # Security event logging methods
    
    async def _log_security_error(
        self,
        request: HttpRequest,
        error: Exception
    ) -> None:
        """Log security middleware error."""
        try:
            event_data = SecurityEventData(
                event_type='security_middleware_error',
                severity=EventSeverity.MEDIUM,
                ip_address=request.client_ip,
                user_agent=request.user_agent,
                request_id=request.correlation_id,
                title='Security middleware error',
                description=f'Security middleware error: {str(error)}',
                risk_score=25.0,
                event_data={
                    'error_type': type(error).__name__,
                    'error_message': str(error),
                    'request_path': request.path,
                    'request_method': request.method
                },
                detection_method='SecurityMiddleware'
            )
            
            await self.security_events.log_security_event(event_data)
            
        except Exception as e:
            self.logger.error(f"Failed to log security error: {e}")
    
    async def _log_rate_limit_violation(
        self,
        request: HttpRequest,
        rate_limit_result
    ) -> None:
        """Log rate limit violation."""
        try:
            event_data = SecurityEventData(
                event_type='rate_limit_exceeded',
                severity=EventSeverity.MEDIUM,
                user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                ip_address=request.client_ip,
                user_agent=request.user_agent,
                request_id=request.correlation_id,
                title=f'Rate limit exceeded: {rate_limit_result.rule_name}',
                description=(
                    f'Rate limit exceeded for rule {rate_limit_result.rule_name}: '
                    f'{rate_limit_result.current_count}/{rate_limit_result.limit} '
                    f'requests in {rate_limit_result.window_seconds}s'
                ),
                risk_score=40.0,
                threat_indicators=['rate_limit_violation'],
                event_data=rate_limit_result.to_dict(),
                detection_method='RateLimitingService'
            )
            
            await self.security_events.log_security_event(event_data)
            
        except Exception as e:
            self.logger.error(f"Failed to log rate limit violation: {e}")
    
    async def _log_malicious_payload(
        self,
        request: HttpRequest,
        pattern: str,
        content: str
    ) -> None:
        """Log malicious payload detection."""
        try:
            event_data = SecurityEventData(
                event_type='malicious_payload',
                severity=EventSeverity.HIGH,
                user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                ip_address=request.client_ip,
                user_agent=request.user_agent,
                request_id=request.correlation_id,
                title='Malicious payload detected',
                description=f'Malicious payload pattern detected: {pattern}',
                risk_score=75.0,
                threat_indicators=['malicious_payload', 'injection_attempt'],
                event_data={
                    'pattern': pattern,
                    'content_sample': content[:200],
                    'request_path': request.path,
                    'request_method': request.method
                },
                detection_method='SecurityMiddleware'
            )
            
            await self.security_events.log_security_event(event_data)
            
        except Exception as e:
            self.logger.error(f"Failed to log malicious payload: {e}")
    
    async def _log_authentication_attempt(
        self,
        request: HttpRequest,
        response: HttpResponse
    ) -> None:
        """Log authentication attempt."""
        try:
            success = response.status_code == 200
            event_type = 'login_success' if success else 'login_failure'
            
            event_data = SecurityEventData(
                event_type=event_type,
                severity=EventSeverity.LOW if success else EventSeverity.MEDIUM,
                user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                ip_address=request.client_ip,
                user_agent=request.user_agent,
                request_id=request.correlation_id,
                title=f'Authentication {"successful" if success else "failed"}',
                description=f'Authentication attempt {"succeeded" if success else "failed"}',
                risk_score=10.0 if success else 30.0,
                event_data={
                    'endpoint': request.path,
                    'method': request.method,
                    'status_code': response.status_code,
                    'success': success
                },
                detection_method='SecurityMiddleware'
            )
            
            await self.security_events.log_security_event(event_data)
            
        except Exception as e:
            self.logger.error(f"Failed to log authentication attempt: {e}")
    
    async def _log_high_risk_request(
        self,
        request: HttpRequest,
        response: HttpResponse
    ) -> None:
        """Log high-risk request."""
        try:
            threat_analysis = request.threat_analysis
            
            event_data = SecurityEventData(
                event_type='high_risk_request',
                severity=EventSeverity.HIGH,
                user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                ip_address=request.client_ip,
                user_agent=request.user_agent,
                request_id=request.correlation_id,
                title=f'High-risk request detected',
                description=f'High-risk request with score {threat_analysis.risk_score}',
                risk_score=threat_analysis.risk_score,
                threat_indicators=[i.type for i in threat_analysis.indicators],
                confidence_score=threat_analysis.confidence,
                event_data=threat_analysis.to_dict(),
                detection_method='ThreatDetectionService'
            )
            
            await self.security_events.log_security_event(event_data)
            
        except Exception as e:
            self.logger.error(f"Failed to log high-risk request: {e}")
    
    async def _log_error_response(
        self,
        request: HttpRequest,
        response: HttpResponse
    ) -> None:
        """Log error response."""
        try:
            # Only log certain error types
            if response.status_code in [401, 403, 429]:
                severity = EventSeverity.MEDIUM
                event_type = 'authentication_error'
                
                if response.status_code == 429:
                    event_type = 'rate_limit_exceeded'
                elif response.status_code == 403:
                    event_type = 'access_denied'
                    severity = EventSeverity.HIGH
                
                event_data = SecurityEventData(
                    event_type=event_type,
                    severity=severity,
                    user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                    ip_address=request.client_ip,
                    user_agent=request.user_agent,
                    request_id=request.correlation_id,
                    title=f'HTTP {response.status_code} error',
                    description=f'Request resulted in {response.status_code} error',
                    risk_score=20.0 if response.status_code == 401 else 40.0,
                    event_data={
                        'status_code': response.status_code,
                        'request_path': request.path,
                        'request_method': request.method
                    },
                    detection_method='SecurityMiddleware'
                )
                
                await self.security_events.log_security_event(event_data)
                
        except Exception as e:
            self.logger.error(f"Failed to log error response: {e}")