"""
Session lifecycle management middleware.

This middleware handles automatic session validation, activity tracking,
and lifecycle management for all authenticated requests.
"""

import logging
import time
from typing import Optional
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

from ..models.session import UserSession, SessionActivity
from ..services.session_service import SessionService, validate_user_session
from ..exceptions import SessionExpiredError, SessionInvalidError


logger = logging.getLogger(__name__)


class SessionLifecycleMiddleware(MiddlewareMixin):
    """
    Middleware for comprehensive session lifecycle management.
    
    This middleware:
    - Validates session on each request
    - Updates session activity timestamps
    - Logs session activities for audit
    - Handles session expiration gracefully
    - Monitors for suspicious session activity
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.session_service = SessionService()
        self.track_activities = getattr(settings, 'SESSION_TRACK_ACTIVITIES', True)
        self.activity_endpoints = getattr(settings, 'SESSION_ACTIVITY_ENDPOINTS', [])
        self.exclude_paths = getattr(settings, 'SESSION_EXCLUDE_PATHS', [
            '/health/',
            '/metrics/',
            '/static/',
            '/media/',
        ])
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming request for session validation.
        
        Args:
            request: HTTP request object
            
        Returns:
            HttpResponse if session is invalid, None to continue processing
        """
        # Skip session processing for excluded paths
        if self._should_skip_path(request.path):
            return None
        
        # Skip if no session ID in request
        session_id = self._extract_session_id(request)
        if not session_id:
            return None
        
        # Record request start time for performance tracking
        request._session_start_time = time.time()
        
        # Validate session
        is_valid, session, validation_details = validate_user_session(session_id)
        
        if not is_valid:
            return self._handle_invalid_session(request, session, validation_details)
        
        # Attach session to request
        request.user_session = session
        request.session_validation_details = validation_details
        
        # Check for suspicious activity
        if validation_details.get('risk_level') in ['high', 'critical']:
            self._handle_suspicious_session(request, session, validation_details)
        
        return None
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Process response to log session activity.
        
        Args:
            request: HTTP request object
            response: HTTP response object
            
        Returns:
            Modified HTTP response
        """
        # Skip if no session or excluded path
        if not hasattr(request, 'user_session') or self._should_skip_path(request.path):
            return response
        
        # Log session activity if enabled
        if self.track_activities:
            self._log_session_activity(request, response)
        
        return response
    
    def _extract_session_id(self, request: HttpRequest) -> Optional[str]:
        """
        Extract session ID from request.
        
        Args:
            request: HTTP request object
            
        Returns:
            Session ID string or None
        """
        # Check Authorization header for session token
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Session '):
            return auth_header[8:]  # Remove 'Session ' prefix
        
        # Check custom session header
        session_header = request.META.get('HTTP_X_SESSION_ID')
        if session_header:
            return session_header
        
        # Check session cookie
        session_cookie = request.COOKIES.get('session_id')
        if session_cookie:
            return session_cookie
        
        return None
    
    def _should_skip_path(self, path: str) -> bool:
        """
        Check if path should be skipped for session processing.
        
        Args:
            path: Request path
            
        Returns:
            True if path should be skipped
        """
        return any(path.startswith(exclude_path) for exclude_path in self.exclude_paths)
    
    def _handle_invalid_session(self, request: HttpRequest, session: Optional[UserSession],
                               validation_details: dict) -> HttpResponse:
        """
        Handle invalid session scenarios.
        
        Args:
            request: HTTP request object
            session: Session object (may be None)
            validation_details: Session validation details
            
        Returns:
            HTTP response for invalid session
        """
        error_data = {
            'error': 'invalid_session',
            'message': 'Session is invalid or expired',
            'details': validation_details,
        }
        
        # Log invalid session attempt
        if session:
            logger.warning(
                f"Invalid session access attempt: {session.session_id} "
                f"for user {session.user.email} from {request.META.get('REMOTE_ADDR')}"
            )
            
            # Log security event
            self._log_security_event(
                session=session,
                event_type='invalid_session_access',
                request=request,
                details=validation_details
            )
        else:
            logger.warning(
                f"Session not found for request from {request.META.get('REMOTE_ADDR')}"
            )
        
        # Return appropriate error response
        if validation_details.get('expired'):
            error_data['error'] = 'session_expired'
            error_data['message'] = 'Session has expired'
            return JsonResponse(error_data, status=401)
        elif validation_details.get('terminated'):
            error_data['error'] = 'session_terminated'
            error_data['message'] = 'Session has been terminated'
            return JsonResponse(error_data, status=401)
        else:
            return JsonResponse(error_data, status=401)
    
    def _handle_suspicious_session(self, request: HttpRequest, session: UserSession,
                                  validation_details: dict) -> None:
        """
        Handle suspicious session activity.
        
        Args:
            request: HTTP request object
            session: Session object
            validation_details: Session validation details
        """
        risk_level = validation_details.get('risk_level', 'unknown')
        
        logger.warning(
            f"Suspicious session activity detected: {session.session_id} "
            f"for user {session.user.email} (risk level: {risk_level})"
        )
        
        # Log security event
        self._log_security_event(
            session=session,
            event_type='suspicious_session_activity',
            request=request,
            details={
                'risk_level': risk_level,
                'risk_score': session.risk_score,
                'risk_factors': session.risk_factors,
            }
        )
        
        # Take action based on risk level
        if risk_level == 'critical':
            # Terminate session immediately for critical risk
            self.session_service.terminate_session(
                session.session_id,
                reason=f'automatic_termination_critical_risk_{session.risk_score:.1f}'
            )
            
            logger.error(
                f"Automatically terminated critical risk session {session.session_id} "
                f"for user {session.user.email}"
            )
    
    def _log_session_activity(self, request: HttpRequest, response: HttpResponse) -> None:
        """
        Log session activity for audit and analysis.
        
        Args:
            request: HTTP request object
            response: HTTP response object
        """
        try:
            session = request.user_session
            
            # Calculate response time
            response_time_ms = None
            if hasattr(request, '_session_start_time'):
                response_time_ms = int((time.time() - request._session_start_time) * 1000)
            
            # Determine activity type
            activity_type = self._determine_activity_type(request, response)
            
            # Check if this endpoint should be tracked
            if self.activity_endpoints and request.path not in self.activity_endpoints:
                # Only track specific endpoints if configured
                if activity_type not in ['login', 'logout', 'suspicious_activity']:
                    return
            
            # Create session activity record
            SessionActivity.objects.create(
                session=session,
                activity_type=activity_type,
                endpoint=request.path,
                method=request.method,
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                ip_address=request.META.get('REMOTE_ADDR'),
                activity_data={
                    'query_params': dict(request.GET),
                    'content_type': request.content_type,
                    'response_size': len(response.content) if hasattr(response, 'content') else 0,
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to log session activity: {e}")
    
    def _determine_activity_type(self, request: HttpRequest, response: HttpResponse) -> str:
        """
        Determine the type of activity based on request/response.
        
        Args:
            request: HTTP request object
            response: HTTP response object
            
        Returns:
            Activity type string
        """
        path = request.path.lower()
        method = request.method.upper()
        
        # Map common endpoints to activity types
        if 'login' in path:
            return 'login'
        elif 'logout' in path:
            return 'logout'
        elif 'password' in path and method in ['POST', 'PUT', 'PATCH']:
            return 'password_change'
        elif 'profile' in path and method in ['POST', 'PUT', 'PATCH']:
            return 'profile_update'
        elif 'mfa' in path:
            if 'setup' in path:
                return 'mfa_setup'
            else:
                return 'mfa_verify'
        elif 'oauth' in path:
            if 'link' in path:
                return 'oauth_link'
            elif 'unlink' in path:
                return 'oauth_unlink'
        elif path.startswith('/api/'):
            return 'api_call'
        else:
            return 'page_view'
    
    def _log_security_event(self, session: UserSession, event_type: str,
                           request: HttpRequest, details: dict) -> None:
        """
        Log security event for monitoring and alerting.
        
        Args:
            session: Session object
            event_type: Type of security event
            request: HTTP request object
            details: Additional event details
        """
        try:
            from ..models.audit import AuditLog
            
            AuditLog.objects.create(
                user=session.user,
                action=event_type,
                resource_type='session',
                resource_id=str(session.id),
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={
                    'session_id': session.session_id,
                    'risk_score': session.risk_score,
                    'endpoint': request.path,
                    'method': request.method,
                    **details
                },
                severity='high' if event_type == 'suspicious_session_activity' else 'medium'
            )
            
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")


class SessionCleanupMiddleware(MiddlewareMixin):
    """
    Lightweight middleware for periodic session cleanup.
    
    This middleware performs lightweight session cleanup operations
    on a subset of requests to maintain system health.
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.cleanup_frequency = getattr(settings, 'SESSION_CLEANUP_FREQUENCY', 100)
        self.request_count = 0
    
    def process_request(self, request: HttpRequest) -> None:
        """
        Periodically trigger session cleanup.
        
        Args:
            request: HTTP request object
        """
        self.request_count += 1
        
        # Trigger cleanup every N requests
        if self.request_count % self.cleanup_frequency == 0:
            try:
                # Import here to avoid circular imports
                from ..tasks.session_tasks import cleanup_expired_sessions_task
                
                # Trigger async cleanup task
                cleanup_expired_sessions_task.delay()
                
            except Exception as e:
                logger.error(f"Failed to trigger session cleanup: {e}")