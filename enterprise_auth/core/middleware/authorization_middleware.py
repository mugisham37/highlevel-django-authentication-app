"""
Authorization Middleware

Role-based authorization middleware that enforces permissions
on API endpoints with flexible configuration and audit logging.
"""

import logging
import json
from typing import Dict, List, Optional, Any, Callable
from functools import wraps

from django.http import JsonResponse, HttpRequest, HttpResponse
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.urls import resolve, Resolver404

from ..services.authorization_service import authorization_engine
from ..exceptions import InsufficientPermissionsError, AuthorizationError


User = get_user_model()
logger = logging.getLogger(__name__)


class AuthorizationMiddleware(MiddlewareMixin):
    """
    Middleware for enforcing role-based authorization on API endpoints.
    
    Automatically checks permissions based on URL patterns and HTTP methods,
    with configurable permission mappings and bypass rules.
    """
    
    # Default permission mappings for HTTP methods
    DEFAULT_METHOD_PERMISSIONS = {
        'GET': 'read',
        'POST': 'create',
        'PUT': 'update',
        'PATCH': 'update',
        'DELETE': 'delete',
        'HEAD': 'read',
        'OPTIONS': 'read',
    }
    
    # URLs that bypass authorization
    BYPASS_URLS = [
        '/api/v1/auth/login',
        '/api/v1/auth/register',
        '/api/v1/auth/refresh',
        '/api/v1/oauth/',
        '/api/v1/health',
        '/admin/login/',
        '/static/',
        '/media/',
    ]
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Load custom permission mappings from settings
        self.permission_mappings = getattr(
            settings, 
            'RBAC_PERMISSION_MAPPINGS', 
            {}
        )
        
        # Load custom bypass URLs from settings
        custom_bypass = getattr(settings, 'RBAC_BYPASS_URLS', [])
        self.bypass_urls = self.BYPASS_URLS + custom_bypass
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming request for authorization.
        
        Args:
            request: Django HTTP request
            
        Returns:
            HttpResponse: Error response if authorization fails, None otherwise
        """
        # Skip authorization for bypass URLs
        if self._should_bypass_authorization(request):
            return None
        
        # Skip if user is not authenticated
        if not request.user or not request.user.is_authenticated:
            return None
        
        try:
            # Extract permission requirements from request
            permission_info = self._extract_permission_info(request)
            if not permission_info:
                return None
            
            resource_type = permission_info['resource_type']
            action = permission_info['action']
            resource_id = permission_info.get('resource_id')
            
            # Build context for permission evaluation
            context = self._build_permission_context(request, permission_info)
            
            # Check permission
            has_permission = authorization_engine.check_permission(
                user=request.user,
                resource_type=resource_type,
                action=action,
                resource_id=resource_id,
                context=context
            )
            
            if not has_permission:
                return self._create_permission_denied_response(
                    request, resource_type, action
                )
            
            # Store permission info in request for later use
            request.rbac_permission_info = permission_info
            
        except Exception as e:
            self.logger.error(f"Authorization middleware error: {e}")
            return self._create_error_response(
                "Authorization check failed", 
                status=500
            )
        
        return None
    
    def _should_bypass_authorization(self, request: HttpRequest) -> bool:
        """Check if request should bypass authorization."""
        path = request.path
        
        # Check exact matches and prefixes
        for bypass_url in self.bypass_urls:
            if path == bypass_url or path.startswith(bypass_url):
                return True
        
        return False
    
    def _extract_permission_info(self, request: HttpRequest) -> Optional[Dict[str, Any]]:
        """
        Extract permission information from request.
        
        Args:
            request: Django HTTP request
            
        Returns:
            Dict: Permission information or None if not applicable
        """
        try:
            # Resolve URL to get view information
            resolver_match = resolve(request.path)
            view_name = resolver_match.view_name
            url_kwargs = resolver_match.kwargs
            
            # Check for custom permission mapping
            if view_name in self.permission_mappings:
                mapping = self.permission_mappings[view_name]
                return {
                    'resource_type': mapping['resource_type'],
                    'action': mapping.get('action') or self._get_action_from_method(request.method),
                    'resource_id': self._extract_resource_id(url_kwargs, mapping.get('resource_id_param')),
                    'view_name': view_name,
                    'custom_mapping': True
                }
            
            # Default mapping based on URL patterns
            resource_type = self._extract_resource_type_from_url(request.path)
            if not resource_type:
                return None
            
            return {
                'resource_type': resource_type,
                'action': self._get_action_from_method(request.method),
                'resource_id': self._extract_resource_id(url_kwargs),
                'view_name': view_name,
                'custom_mapping': False
            }
            
        except Resolver404:
            # URL not found, let Django handle it
            return None
        except Exception as e:
            self.logger.error(f"Failed to extract permission info: {e}")
            return None
    
    def _extract_resource_type_from_url(self, path: str) -> Optional[str]:
        """
        Extract resource type from URL path.
        
        Args:
            path: URL path
            
        Returns:
            str: Resource type or None
        """
        # Remove API version prefix
        if path.startswith('/api/v1/'):
            path = path[8:]
        elif path.startswith('/api/'):
            path = path[5:]
        
        # Extract first path segment as resource type
        segments = [s for s in path.split('/') if s]
        if not segments:
            return None
        
        resource_type = segments[0]
        
        # Map common URL patterns to resource types
        resource_mapping = {
            'users': 'user',
            'roles': 'role',
            'permissions': 'permission',
            'sessions': 'session',
            'audit': 'audit_log',
            'security': 'security_event',
            'admin': 'system',
            'webhooks': 'webhook',
            'api-keys': 'api_key',
        }
        
        return resource_mapping.get(resource_type, resource_type)
    
    def _get_action_from_method(self, method: str) -> str:
        """Get action from HTTP method."""
        return self.DEFAULT_METHOD_PERMISSIONS.get(method.upper(), 'execute')
    
    def _extract_resource_id(
        self, 
        url_kwargs: Dict[str, Any], 
        resource_id_param: Optional[str] = None
    ) -> Optional[str]:
        """Extract resource ID from URL kwargs."""
        if resource_id_param and resource_id_param in url_kwargs:
            return str(url_kwargs[resource_id_param])
        
        # Common parameter names for resource IDs
        id_params = ['id', 'pk', 'user_id', 'role_id', 'permission_id', 'session_id']
        
        for param in id_params:
            if param in url_kwargs:
                return str(url_kwargs[param])
        
        return None
    
    def _build_permission_context(
        self, 
        request: HttpRequest, 
        permission_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build context for permission evaluation."""
        context = {
            'ip_address': self._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'request_id': getattr(request, 'correlation_id', ''),
            'method': request.method,
            'path': request.path,
            'view_name': permission_info.get('view_name', ''),
        }
        
        # Add request body for POST/PUT requests (if JSON)
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                if request.content_type == 'application/json':
                    context['request_data'] = json.loads(request.body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        
        # Add query parameters
        context['query_params'] = dict(request.GET)
        
        return context
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')
    
    def _create_permission_denied_response(
        self, 
        request: HttpRequest, 
        resource_type: str, 
        action: str
    ) -> JsonResponse:
        """Create permission denied response."""
        return JsonResponse({
            'error': {
                'code': 'INSUFFICIENT_PERMISSIONS',
                'message': f'Insufficient permissions for {resource_type}:{action}',
                'details': {
                    'resource_type': resource_type,
                    'action': action,
                    'user': request.user.email if request.user.is_authenticated else 'anonymous'
                },
                'request_id': getattr(request, 'correlation_id', ''),
            }
        }, status=403)
    
    def _create_error_response(self, message: str, status: int = 400) -> JsonResponse:
        """Create generic error response."""
        return JsonResponse({
            'error': {
                'code': 'AUTHORIZATION_ERROR',
                'message': message,
            }
        }, status=status)


def require_permission(resource_type: str, action: str, resource_id_param: Optional[str] = None):
    """
    Decorator for requiring specific permissions on view functions.
    
    Args:
        resource_type: Type of resource being accessed
        action: Action being performed
        resource_id_param: Optional parameter name for resource ID
        
    Returns:
        Decorated function
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if not request.user or not request.user.is_authenticated:
                return JsonResponse({
                    'error': {
                        'code': 'AUTHENTICATION_REQUIRED',
                        'message': 'Authentication required'
                    }
                }, status=401)
            
            # Extract resource ID if specified
            resource_id = None
            if resource_id_param and resource_id_param in kwargs:
                resource_id = str(kwargs[resource_id_param])
            
            # Build context
            context = {
                'ip_address': request.META.get('REMOTE_ADDR', ''),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'request_id': getattr(request, 'correlation_id', ''),
                'method': request.method,
                'path': request.path,
            }
            
            # Check permission
            try:
                authorization_engine.require_permission(
                    user=request.user,
                    resource_type=resource_type,
                    action=action,
                    resource_id=resource_id,
                    context=context
                )
            except InsufficientPermissionsError as e:
                return JsonResponse({
                    'error': {
                        'code': 'INSUFFICIENT_PERMISSIONS',
                        'message': str(e),
                        'details': {
                            'resource_type': resource_type,
                            'action': action,
                            'resource_id': resource_id,
                        }
                    }
                }, status=403)
            except AuthorizationError as e:
                return JsonResponse({
                    'error': {
                        'code': 'AUTHORIZATION_ERROR',
                        'message': str(e)
                    }
                }, status=500)
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def require_role(role_name: str):
    """
    Decorator for requiring specific role on view functions.
    
    Args:
        role_name: Name of required role
        
    Returns:
        Decorated function
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if not request.user or not request.user.is_authenticated:
                return JsonResponse({
                    'error': {
                        'code': 'AUTHENTICATION_REQUIRED',
                        'message': 'Authentication required'
                    }
                }, status=401)
            
            # Check if user has the required role
            user_roles = authorization_engine.get_user_roles(request.user)
            has_role = any(role.name == role_name for role in user_roles)
            
            if not has_role:
                return JsonResponse({
                    'error': {
                        'code': 'INSUFFICIENT_ROLE',
                        'message': f'Role "{role_name}" required',
                        'details': {
                            'required_role': role_name,
                            'user_roles': [role.name for role in user_roles]
                        }
                    }
                }, status=403)
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator