"""
Session security monitoring middleware.

This middleware integrates session security monitoring into the request/response
cycle, providing real-time threat detection and automated response capabilities.
"""

import logging
import time
from typing import Optional, Dict, Any

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache

from ..models.session import UserSession, SessionActivity
from ..services.session_security_service import session_security_service
from ..exceptions import SecurityThreatDetectedError


logger = logging.getLogger(__name__)


class SessionSecurityMiddleware(MiddlewareMixin):
    """
    Middleware for real-time session security monitoring.
    
    Monitors session activities, detects anomalies, and takes automated
    security responses during request processing.
    """
    
    def __init__(self, get_response=None):
        """Initialize the middleware."""
        super().__init__(get_response)
        
        # Configuration
        self.monitoring_enabled = getattr(settings, 'SESSION_SECURITY_MONITORING_ENABLED', True)
        self.real_time_monitoring = getattr(settings, 'REAL_TIME_SESSION_MONITORING', True)
        self.monitoring_sample_rate = getattr(settings, 'SESSION_MONITORING_SAMPLE_RATE', 1.0)
        self.block_suspicious_sessions = getattr(settings, 'BLOCK_SUSPICIOUS_SESSIONS', True)
        self.log_all_activities = getattr(settings, 'LOG_ALL_SESSION_ACTIVITIES', False)
        
        # Performance settings
        self.monitoring_cache_timeout = getattr(settings, 'SESSION_MONITORING_CACHE_TIMEOUT', 300)
        self.skip_monitoring_paths = getattr(settings, 'SKIP_MONITORING_PATHS', [
            '/health/', '/metrics/', '/static/', '/media/'
        ])
        
        # Rate limiting for monitoring
        self.monitoring_rate_limit = getattr(settings, 'SESSION_MONITORING_RATE_LIMIT', 10)  # per minute
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming request for session security.
        
        Args:
            request: HTTP request object
            
        Returns:
            HttpResponse if request should be blocked, None otherwise
        """
        if not self.monitoring_enabled:
            return None
        
        # Skip monitoring for certain paths
        if any(request.path.startswith(path) for path in self.skip_monitoring_paths):
            return None
        
        # Get session information
        session = self._get_session_from_request(request)
        if not session:
            return None
        
        try:
            # Check if session is already marked as suspicious
            if session.status == 'suspicious' and self.block_suspicious_sessions:
                logger.warning(
                    f"Blocking request from suspicious session {session.session_id}",
                    extra={
                        'session_id': session.session_id,
                        'user_id': str(session.user.id),
                        'ip_address': self._get_client_ip(request),
                        'path': request.path,
                    }
                )
                
                return JsonResponse({
                    'error': 'Session security violation',
                    'message': 'Your session has been flagged for suspicious activity. Please re-authenticate.',
                    'code': 'SUSPICIOUS_SESSION'
                }, status=403)
            
            # Check if session is terminated
            if session.status == 'terminated':
                return JsonResponse({
                    'error': 'Session terminated',
                    'message': 'Your session has been terminated for security reasons.',
                    'code': 'SESSION_TERMINATED'
                }, status=401)
            
            # Store session in request for later use
            request.session_obj = session
            
            # Perform real-time monitoring if enabled
            if self.real_time_monitoring and self._should_monitor_request(request, session):
                threat_response = self._perform_real_time_monitoring(request, session)
                if threat_response:
                    return threat_response
            
            return None
            
        except Exception as e:
            logger.error(
                f"Error in session security middleware: {str(e)}",
                extra={
                    'session_id': session.session_id if session else None,
                    'path': request.path,
                    'error': str(e),
                }
            )
            # Don't block request on middleware errors
            return None
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Process response and log session activity.
        
        Args:
            request: HTTP request object
            response: HTTP response object
            
        Returns:
            Modified or original response
        """
        if not self.monitoring_enabled:
            return response
        
        # Get session from request
        session = getattr(request, 'session_obj', None)
        if not session:
            return response
        
        try:
            # Log session activity
            self._log_session_activity(request, response, session)
            
            # Update session last activity
            session.update_activity()
            
            # Perform post-request monitoring if needed
            if hasattr(request, '_requires_post_monitoring'):
                self._perform_post_request_monitoring(request, session, response)
            
        except Exception as e:
            logger.error(
                f"Error in session security middleware response processing: {str(e)}",
                extra={
                    'session_id': session.session_id,
                    'path': request.path,
                    'error': str(e),
                }
            )
        
        return response
    
    def _get_session_from_request(self, request: HttpRequest) -> Optional[UserSession]:
        """Extract session from request."""
        # Try to get session ID from various sources
        session_id = None
        
        # Check Authorization header for JWT token
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            # This would need to be integrated with JWT service to extract session ID
            # For now, we'll skip JWT-based session extraction
            pass
        
        # Check session cookie
        if hasattr(request, 'session') and request.session.session_key:
            # This would need to map Django session to UserSession
            # For now, we'll skip cookie-based session extraction
            pass
        
        # Check custom session header
        session_id = request.META.get('HTTP_X_SESSION_ID')
        
        if session_id:
            try:
                return UserSession.objects.select_related('user', 'device_info').get(
                    session_id=session_id,
                    status='active'
                )
            except UserSession.DoesNotExist:
                pass
        
        return None
    
    def _should_monitor_request(self, request: HttpRequest, session: UserSession) -> bool:
        """Determine if request should be monitored."""
        # Check sampling rate
        import random
        if random.random() > self.monitoring_sample_rate:
            return False
        
        # Check rate limiting
        cache_key = f"session_monitoring_rate:{session.session_id}"
        current_count = cache.get(cache_key, 0)
        
        if current_count >= self.monitoring_rate_limit:
            return False
        
        # Increment rate limit counter
        cache.set(cache_key, current_count + 1, 60)  # 1 minute window
        
        # Always monitor high-risk sessions
        if session.risk_score >= 70.0:
            return True
        
        # Monitor suspicious activities
        if request.method in ['POST', 'PUT', 'DELETE']:
            return True
        
        # Monitor admin or sensitive endpoints
        sensitive_paths = ['/admin/', '/api/admin/', '/api/users/', '/api/auth/']
        if any(request.path.startswith(path) for path in sensitive_paths):
            return True
        
        return False
    
    def _perform_real_time_monitoring(self, request: HttpRequest, 
                                    session: UserSession) -> Optional[HttpResponse]:
        """Perform real-time session monitoring."""
        try:
            # Check cache for recent monitoring results
            cache_key = f"session_monitoring:{session.session_id}"
            cached_result = cache.get(cache_key)
            
            if cached_result and cached_result.get('timestamp', 0) > time.time() - 60:
                # Use cached result if less than 1 minute old
                monitoring_result = cached_result
            else:
                # Perform fresh monitoring
                monitoring_result = session_security_service.monitor_session_security(session)
                monitoring_result['timestamp'] = time.time()
                
                # Cache result
                cache.set(cache_key, monitoring_result, self.monitoring_cache_timeout)
            
            # Check if immediate action is required
            if monitoring_result.get('actions_taken'):
                actions = monitoring_result['actions_taken']
                
                if 'session_terminated' in actions:
                    logger.critical(
                        f"Session {session.session_id} terminated during request processing",
                        extra={
                            'session_id': session.session_id,
                            'user_id': str(session.user.id),
                            'path': request.path,
                            'actions': actions,
                        }
                    )
                    
                    return JsonResponse({
                        'error': 'Session terminated',
                        'message': 'Your session has been terminated due to security threats.',
                        'code': 'SESSION_TERMINATED_SECURITY'
                    }, status=401)
                
                if 'session_marked_suspicious' in actions:
                    logger.warning(
                        f"Session {session.session_id} marked suspicious during request",
                        extra={
                            'session_id': session.session_id,
                            'user_id': str(session.user.id),
                            'path': request.path,
                        }
                    )
                    
                    # Mark request for additional monitoring
                    request._requires_post_monitoring = True
            
            # Check for high-risk threshold
            if monitoring_result.get('risk_score', 0) >= 90.0:
                logger.critical(
                    f"Critical risk session detected: {session.session_id}",
                    extra={
                        'session_id': session.session_id,
                        'user_id': str(session.user.id),
                        'risk_score': monitoring_result['risk_score'],
                        'path': request.path,
                    }
                )
                
                # Could implement additional restrictions here
                # For now, we'll allow the request but log it
            
            return None
            
        except Exception as e:
            logger.error(
                f"Error in real-time session monitoring: {str(e)}",
                extra={
                    'session_id': session.session_id,
                    'path': request.path,
                    'error': str(e),
                }
            )
            return None
    
    def _log_session_activity(self, request: HttpRequest, response: HttpResponse, 
                            session: UserSession) -> None:
        """Log session activity."""
        try:
            # Determine activity type
            activity_type = self._determine_activity_type(request, response)
            
            # Skip logging for certain activity types unless configured otherwise
            if not self.log_all_activities and activity_type in ['page_view', 'api_call']:
                # Only log if it's a significant endpoint or high-risk session
                if session.risk_score < 50.0 and not self._is_significant_endpoint(request.path):
                    return
            
            # Collect risk indicators
            risk_indicators = []
            if response.status_code >= 400:
                risk_indicators.append(f'http_error_{response.status_code}')
            
            if request.method in ['POST', 'PUT', 'DELETE']:
                risk_indicators.append('write_operation')
            
            # Create activity record
            SessionActivity.objects.create(
                session=session,
                activity_type=activity_type,
                endpoint=request.path,
                method=request.method,
                status_code=response.status_code,
                response_time_ms=getattr(response, '_response_time_ms', None),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                ip_address=self._get_client_ip(request),
                activity_data={
                    'query_params': dict(request.GET) if request.GET else {},
                    'content_type': request.content_type,
                    'content_length': len(getattr(response, 'content', b'')),
                },
                risk_indicators=risk_indicators,
            )
            
        except Exception as e:
            logger.error(
                f"Error logging session activity: {str(e)}",
                extra={
                    'session_id': session.session_id,
                    'path': request.path,
                    'error': str(e),
                }
            )
    
    def _determine_activity_type(self, request: HttpRequest, response: HttpResponse) -> str:
        """Determine the type of activity based on request/response."""
        path = request.path.lower()
        method = request.method
        
        # Authentication-related activities
        if '/auth/' in path or '/login' in path:
            if method == 'POST':
                return 'login' if response.status_code < 400 else 'login_failure'
            return 'auth_page_view'
        
        if '/logout' in path:
            return 'logout'
        
        # MFA activities
        if '/mfa/' in path:
            if method == 'POST':
                return 'mfa_verify' if response.status_code < 400 else 'mfa_failure'
            return 'mfa_setup'
        
        # Profile activities
        if '/profile' in path or '/user' in path:
            if method in ['PUT', 'PATCH']:
                return 'profile_update'
            return 'profile_view'
        
        # Admin activities
        if '/admin/' in path:
            return 'admin_access'
        
        # API activities
        if path.startswith('/api/'):
            return 'api_call'
        
        # Default to page view
        return 'page_view'
    
    def _is_significant_endpoint(self, path: str) -> bool:
        """Check if endpoint is significant enough to always log."""
        significant_patterns = [
            '/admin/', '/api/admin/', '/api/users/', '/api/auth/',
            '/profile/', '/settings/', '/mfa/', '/oauth/'
        ]
        
        return any(pattern in path for pattern in significant_patterns)
    
    def _perform_post_request_monitoring(self, request: HttpRequest, 
                                       session: UserSession, 
                                       response: HttpResponse) -> None:
        """Perform additional monitoring after request processing."""
        try:
            # This could include additional analysis based on response
            # For now, we'll just log that post-monitoring was triggered
            logger.info(
                f"Post-request monitoring triggered for session {session.session_id}",
                extra={
                    'session_id': session.session_id,
                    'path': request.path,
                    'status_code': response.status_code,
                }
            )
            
        except Exception as e:
            logger.error(
                f"Error in post-request monitoring: {str(e)}",
                extra={
                    'session_id': session.session_id,
                    'error': str(e),
                }
            )
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address from request."""
        # Check for forwarded IP first
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        # Check for real IP
        real_ip = request.META.get('HTTP_X_REAL_IP')
        if real_ip:
            return real_ip
        
        # Fall back to remote address
        return request.META.get('REMOTE_ADDR', '127.0.0.1')