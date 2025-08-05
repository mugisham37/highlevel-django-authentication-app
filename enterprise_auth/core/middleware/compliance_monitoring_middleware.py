"""
Compliance monitoring middleware for tracking compliance-related activities.
"""

import logging
import time
from typing import Dict, Any, Optional
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.http import HttpRequest, HttpResponse

from ..services.compliance_service import SOC2AuditService
from ..models.compliance import ComplianceAuditLog

User = get_user_model()
logger = logging.getLogger(__name__)


class ComplianceMonitoringMiddleware:
    """
    Middleware for monitoring compliance-related activities and creating audit logs.
    """
    
    # Compliance-sensitive endpoints that should be monitored
    MONITORED_ENDPOINTS = {
        # GDPR endpoints
        '/api/v1/compliance/data-export/': 'gdpr_data_export',
        '/api/v1/compliance/data-deletion/': 'gdpr_data_deletion',
        '/api/v1/compliance/consent/': 'gdpr_consent_management',
        
        # User management endpoints
        '/api/v1/auth/register/': 'user_registration',
        '/api/v1/auth/login/': 'user_authentication',
        '/api/v1/auth/logout/': 'user_logout',
        '/api/v1/users/profile/': 'user_profile_access',
        
        # Admin endpoints
        '/api/v1/admin/': 'admin_access',
        '/api/v1/compliance/reports/': 'compliance_reporting',
        '/api/v1/compliance/security/': 'security_compliance',
        
        # RBAC endpoints
        '/api/v1/rbac/': 'rbac_management',
    }
    
    # HTTP methods that indicate data modification
    MODIFICATION_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.audit_service = SOC2AuditService()
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process request and response for compliance monitoring."""
        
        # Skip monitoring for non-compliance-sensitive endpoints
        if not self._should_monitor_request(request):
            return self.get_response(request)
        
        # Capture request start time
        start_time = time.time()
        
        # Extract request context
        request_context = self._extract_request_context(request)
        
        # Capture request state for audit
        before_state = self._capture_request_state(request)
        
        # Process the request
        response = self.get_response(request)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Capture response state for audit
        after_state = self._capture_response_state(response, processing_time)
        
        # Create compliance audit log
        self._create_compliance_audit_log(
            request=request,
            response=response,
            request_context=request_context,
            before_state=before_state,
            after_state=after_state,
            processing_time=processing_time
        )
        
        return response
    
    def _should_monitor_request(self, request: HttpRequest) -> bool:
        """
        Determine if the request should be monitored for compliance.
        
        Args:
            request: HTTP request object
            
        Returns:
            True if request should be monitored
        """
        path = request.path
        
        # Check if path matches any monitored endpoints
        for monitored_path in self.MONITORED_ENDPOINTS:
            if path.startswith(monitored_path):
                return True
        
        # Monitor all data modification requests to sensitive areas
        if request.method in self.MODIFICATION_METHODS:
            sensitive_paths = ['/api/v1/users/', '/api/v1/admin/', '/api/v1/compliance/']
            for sensitive_path in sensitive_paths:
                if path.startswith(sensitive_path):
                    return True
        
        return False
    
    def _extract_request_context(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Extract relevant context from the request.
        
        Args:
            request: HTTP request object
            
        Returns:
            Dictionary containing request context
        """
        return {
            'method': request.method,
            'path': request.path,
            'user_id': str(request.user.id) if request.user.is_authenticated else None,
            'user_email': request.user.email if request.user.is_authenticated else None,
            'ip_address': self._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'session_key': request.session.session_key if hasattr(request, 'session') else None,
            'request_id': getattr(request, 'correlation_id', None),
            'content_type': request.content_type,
            'query_params': dict(request.GET) if request.GET else {},
            'timestamp': timezone.now().isoformat()
        }
    
    def _capture_request_state(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Capture relevant request state for audit purposes.
        
        Args:
            request: HTTP request object
            
        Returns:
            Dictionary containing request state
        """
        state = {
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers),
            'query_params': dict(request.GET)
        }
        
        # Capture request body for modification requests (excluding sensitive data)
        if request.method in self.MODIFICATION_METHODS:
            try:
                if hasattr(request, 'data') and request.data:
                    # Filter out sensitive fields
                    filtered_data = self._filter_sensitive_data(dict(request.data))
                    state['request_data'] = filtered_data
                elif request.POST:
                    filtered_data = self._filter_sensitive_data(dict(request.POST))
                    state['request_data'] = filtered_data
            except Exception as e:
                logger.warning(f"Failed to capture request data: {str(e)}")
                state['request_data'] = {'error': 'Failed to capture request data'}
        
        return state
    
    def _capture_response_state(self, response: HttpResponse, processing_time: float) -> Dict[str, Any]:
        """
        Capture relevant response state for audit purposes.
        
        Args:
            response: HTTP response object
            processing_time: Request processing time in seconds
            
        Returns:
            Dictionary containing response state
        """
        state = {
            'status_code': response.status_code,
            'processing_time_ms': round(processing_time * 1000, 2),
            'content_type': response.get('Content-Type', ''),
            'content_length': len(response.content) if hasattr(response, 'content') else 0
        }
        
        # Capture response headers (excluding sensitive ones)
        sensitive_headers = {'set-cookie', 'authorization', 'x-api-key'}
        state['headers'] = {
            k: v for k, v in response.items()
            if k.lower() not in sensitive_headers
        }
        
        return state
    
    def _create_compliance_audit_log(self, request: HttpRequest, response: HttpResponse,
                                   request_context: Dict[str, Any], before_state: Dict[str, Any],
                                   after_state: Dict[str, Any], processing_time: float) -> None:
        """
        Create compliance audit log entry.
        
        Args:
            request: HTTP request object
            response: HTTP response object
            request_context: Request context data
            before_state: Request state data
            after_state: Response state data
            processing_time: Request processing time
        """
        try:
            # Determine activity type based on endpoint
            activity_type = self._determine_activity_type(request.path, request.method)
            
            # Determine severity based on response and activity
            severity = self._determine_severity(response.status_code, activity_type, request.method)
            
            # Determine outcome
            outcome = 'success' if 200 <= response.status_code < 400 else 'failure'
            
            # Create audit log
            self.audit_service.create_audit_log(
                activity_type=activity_type,
                user=request.user if request.user.is_authenticated else None,
                session_id=request_context.get('session_key'),
                ip_address=request_context.get('ip_address'),
                user_agent=request_context.get('user_agent'),
                request_id=request_context.get('request_id'),
                action=f"{request.method} {request.path}",
                resource=self._extract_resource_name(request.path),
                outcome=outcome,
                details={
                    'endpoint': request.path,
                    'method': request.method,
                    'status_code': response.status_code,
                    'processing_time_ms': after_state['processing_time_ms'],
                    'content_length': after_state['content_length'],
                    'query_params': request_context.get('query_params', {}),
                    'compliance_context': self._get_compliance_context(request.path)
                },
                before_state=before_state,
                after_state=after_state,
                severity=severity
            )
            
        except Exception as e:
            logger.error(f"Failed to create compliance audit log: {str(e)}")
    
    def _determine_activity_type(self, path: str, method: str) -> str:
        """
        Determine the activity type based on the request path and method.
        
        Args:
            path: Request path
            method: HTTP method
            
        Returns:
            Activity type string
        """
        # Check for specific compliance endpoints
        for endpoint_path, activity_type in self.MONITORED_ENDPOINTS.items():
            if path.startswith(endpoint_path):
                return 'compliance_action'
        
        # Determine based on path patterns
        if '/auth/' in path:
            return 'authentication'
        elif '/users/' in path or '/profile/' in path:
            return 'data_access' if method == 'GET' else 'data_modification'
        elif '/admin/' in path:
            return 'admin_action'
        elif '/rbac/' in path:
            return 'authorization'
        elif '/compliance/' in path:
            return 'compliance_action'
        else:
            return 'data_access' if method == 'GET' else 'data_modification'
    
    def _determine_severity(self, status_code: int, activity_type: str, method: str) -> str:
        """
        Determine the severity level for the audit log.
        
        Args:
            status_code: HTTP response status code
            activity_type: Type of activity
            method: HTTP method
            
        Returns:
            Severity level string
        """
        # High severity for failures in critical operations
        if status_code >= 500:
            return 'high'
        elif status_code >= 400:
            if activity_type in ['authentication', 'authorization', 'compliance_action']:
                return 'medium'
            else:
                return 'low'
        
        # Medium severity for data modifications
        if method in self.MODIFICATION_METHODS:
            if activity_type in ['compliance_action', 'admin_action']:
                return 'medium'
            else:
                return 'low'
        
        # Low severity for successful read operations
        return 'low'
    
    def _extract_resource_name(self, path: str) -> str:
        """
        Extract resource name from the request path.
        
        Args:
            path: Request path
            
        Returns:
            Resource name
        """
        # Remove API version and extract main resource
        path_parts = path.strip('/').split('/')
        
        if len(path_parts) >= 3 and path_parts[0] == 'api':
            return path_parts[2]  # e.g., 'users', 'compliance', 'auth'
        elif len(path_parts) >= 1:
            return path_parts[0]
        else:
            return 'unknown'
    
    def _get_compliance_context(self, path: str) -> Dict[str, Any]:
        """
        Get compliance context for the request.
        
        Args:
            path: Request path
            
        Returns:
            Compliance context dictionary
        """
        context = {}
        
        if '/compliance/data-export/' in path:
            context['gdpr_article'] = 'Article 20 - Right to data portability'
            context['compliance_area'] = 'gdpr'
        elif '/compliance/data-deletion/' in path:
            context['gdpr_article'] = 'Article 17 - Right to erasure'
            context['compliance_area'] = 'gdpr'
        elif '/compliance/consent/' in path:
            context['gdpr_article'] = 'Article 6 - Lawfulness of processing'
            context['compliance_area'] = 'gdpr'
        elif '/compliance/security/' in path:
            context['compliance_area'] = 'security'
            context['framework'] = 'OWASP'
        elif '/compliance/reports/' in path:
            context['compliance_area'] = 'soc2'
            context['framework'] = 'SOC2'
        elif '/auth/' in path:
            context['compliance_area'] = 'authentication'
            context['security_control'] = 'access_control'
        
        return context
    
    def _filter_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter out sensitive data from request/response data.
        
        Args:
            data: Data dictionary to filter
            
        Returns:
            Filtered data dictionary
        """
        sensitive_fields = {
            'password', 'token', 'secret', 'key', 'authorization',
            'credit_card', 'ssn', 'social_security', 'passport'
        }
        
        filtered_data = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if field name contains sensitive keywords
            is_sensitive = any(sensitive_field in key_lower for sensitive_field in sensitive_fields)
            
            if is_sensitive:
                filtered_data[key] = '[REDACTED]'
            elif isinstance(value, dict):
                filtered_data[key] = self._filter_sensitive_data(value)
            elif isinstance(value, list):
                filtered_data[key] = [
                    self._filter_sensitive_data(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                filtered_data[key] = value
        
        return filtered_data
    
    def _get_client_ip(self, request: HttpRequest) -> Optional[str]:
        """
        Get the client IP address from the request.
        
        Args:
            request: HTTP request object
            
        Returns:
            Client IP address or None
        """
        # Check for IP in various headers (for load balancers/proxies)
        ip_headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ]
        
        for header in ip_headers:
            ip = request.META.get(header)
            if ip:
                # Handle comma-separated IPs (take the first one)
                return ip.split(',')[0].strip()
        
        return None