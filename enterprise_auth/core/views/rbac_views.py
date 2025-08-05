"""
RBAC API Views

Comprehensive API views for role-based access control management,
including role CRUD operations, permission management, and bulk operations.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.core.paginator import Paginator
from django.db.models import Q, Count, Prefetch

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ..models.rbac import Role, Permission, UserRole, RolePermission, PermissionAuditLog
from ..services.authorization_service import authorization_engine, role_management_service
from ..middleware.authorization_middleware import require_permission, require_role
from ..exceptions import AuthorizationError, InsufficientPermissionsError
from ..utils.validation import validate_json_request, validate_uuid


User = get_user_model()
logger = logging.getLogger(__name__)


# Role Management Views

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
@require_permission('role', 'list')
def roles_list_create(request):
    """
    List all roles or create a new role.
    
    GET: Returns paginated list of roles with hierarchy information
    POST: Creates a new role with optional parent and permissions
    """
    if request.method == 'GET':
        return _list_roles(request)
    elif request.method == 'POST':
        return _create_role(request)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def role_detail(request, role_id):
    """
    Retrieve, update, or delete a specific role.
    
    GET: Returns detailed role information including hierarchy and permissions
    PUT: Updates role information and permissions
    DELETE: Deactivates role (soft delete)
    """
    if not validate_uuid(role_id):
        return Response({
            'error': {
                'code': 'INVALID_UUID',
                'message': 'Invalid role ID format'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        role = Role.objects.get(id=role_id, is_active=True)
    except Role.DoesNotExist:
        return Response({
            'error': {
                'code': 'ROLE_NOT_FOUND',
                'message': 'Role not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        return _get_role_detail(request, role)
    elif request.method == 'PUT':
        return _update_role(request, role)
    elif request.method == 'DELETE':
        return _delete_role(request, role)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@require_permission('role', 'read')
def role_hierarchy(request, role_id):
    """Get complete role hierarchy for a specific role."""
    if not validate_uuid(role_id):
        return Response({
            'error': {
                'code': 'INVALID_UUID',
                'message': 'Invalid role ID format'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        role = Role.objects.get(id=role_id, is_active=True)
        hierarchy = role_management_service.get_role_hierarchy(role)
        
        return Response({
            'success': True,
            'data': hierarchy
        })
        
    except Role.DoesNotExist:
        return Response({
            'error': {
                'code': 'ROLE_NOT_FOUND',
                'message': 'Role not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Failed to get role hierarchy: {e}")
        return Response({
            'error': {
                'code': 'HIERARCHY_ERROR',
                'message': 'Failed to retrieve role hierarchy'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Permission Management Views

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
@require_permission('permission', 'list')
def permissions_list_create(request):
    """
    List all permissions or create a new permission.
    
    GET: Returns paginated list of permissions with filtering
    POST: Creates a new permission with conditions
    """
    if request.method == 'GET':
        return _list_permissions(request)
    elif request.method == 'POST':
        return _create_permission(request)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def permission_detail(request, permission_id):
    """
    Retrieve, update, or delete a specific permission.
    
    GET: Returns detailed permission information
    PUT: Updates permission information and conditions
    DELETE: Deactivates permission (soft delete)
    """
    if not validate_uuid(permission_id):
        return Response({
            'error': {
                'code': 'INVALID_UUID',
                'message': 'Invalid permission ID format'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        permission = Permission.objects.get(id=permission_id, is_active=True)
    except Permission.DoesNotExist:
        return Response({
            'error': {
                'code': 'PERMISSION_NOT_FOUND',
                'message': 'Permission not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        return _get_permission_detail(request, permission)
    elif request.method == 'PUT':
        return _update_permission(request, permission)
    elif request.method == 'DELETE':
        return _delete_permission(request, permission)


# Role Assignment Views

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@require_permission('role', 'manage')
def assign_role_to_user(request):
    """Assign a role to a user with optional expiration."""
    data = validate_json_request(request)
    if isinstance(data, JsonResponse):
        return data
    
    required_fields = ['user_id', 'role_id']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return Response({
            'error': {
                'code': 'MISSING_FIELDS',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(id=data['user_id'])
        role = Role.objects.get(id=data['role_id'], is_active=True)
        
        # Parse expiration date if provided
        expires_at = None
        if 'expires_at' in data:
            expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
        
        # Assign role
        user_role = role_management_service.assign_role_to_user(
            user=user,
            role=role,
            granted_by=request.user,
            expires_at=expires_at,
            reason=data.get('reason', '')
        )
        
        return Response({
            'success': True,
            'message': f'Role "{role.name}" assigned to user {user.email}',
            'data': {
                'assignment_id': str(user_role.id),
                'user_id': str(user.id),
                'role_id': str(role.id),
                'expires_at': user_role.expires_at.isoformat() if user_role.expires_at else None,
                'granted_at': user_role.granted_at.isoformat()
            }
        }, status=status.HTTP_201_CREATED)
        
    except User.DoesNotExist:
        return Response({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': 'User not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except Role.DoesNotExist:
        return Response({
            'error': {
                'code': 'ROLE_NOT_FOUND',
                'message': 'Role not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Failed to assign role: {e}")
        return Response({
            'error': {
                'code': 'ASSIGNMENT_ERROR',
                'message': 'Failed to assign role'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@require_permission('role', 'manage')
def revoke_role_from_user(request):
    """Revoke a role from a user."""
    data = validate_json_request(request)
    if isinstance(data, JsonResponse):
        return data
    
    required_fields = ['user_id', 'role_id']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return Response({
            'error': {
                'code': 'MISSING_FIELDS',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(id=data['user_id'])
        role = Role.objects.get(id=data['role_id'])
        
        # Revoke role
        success = role_management_service.revoke_role_from_user(
            user=user,
            role=role,
            revoked_by=request.user,
            reason=data.get('reason', '')
        )
        
        if success:
            return Response({
                'success': True,
                'message': f'Role "{role.name}" revoked from user {user.email}'
            })
        else:
            return Response({
                'error': {
                    'code': 'ROLE_NOT_ASSIGNED',
                    'message': 'Role is not assigned to user'
                }
            }, status=status.HTTP_404_NOT_FOUND)
        
    except User.DoesNotExist:
        return Response({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': 'User not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except Role.DoesNotExist:
        return Response({
            'error': {
                'code': 'ROLE_NOT_FOUND',
                'message': 'Role not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Failed to revoke role: {e}")
        return Response({
            'error': {
                'code': 'REVOCATION_ERROR',
                'message': 'Failed to revoke role'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@require_permission('role', 'manage')
def bulk_assign_roles(request):
    """Bulk assign roles to multiple users."""
    data = validate_json_request(request)
    if isinstance(data, JsonResponse):
        return data
    
    required_fields = ['user_ids', 'role_ids']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return Response({
            'error': {
                'code': 'MISSING_FIELDS',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        users = User.objects.filter(id__in=data['user_ids'])
        roles = Role.objects.filter(id__in=data['role_ids'], is_active=True)
        
        if len(users) != len(data['user_ids']):
            return Response({
                'error': {
                    'code': 'USERS_NOT_FOUND',
                    'message': 'Some users not found'
                }
            }, status=status.HTTP_404_NOT_FOUND)
        
        if len(roles) != len(data['role_ids']):
            return Response({
                'error': {
                    'code': 'ROLES_NOT_FOUND',
                    'message': 'Some roles not found'
                }
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Parse expiration date if provided
        expires_at = None
        if 'expires_at' in data:
            expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
        
        # Bulk assign roles
        assignments = role_management_service.bulk_assign_roles(
            users=list(users),
            roles=list(roles),
            granted_by=request.user,
            expires_at=expires_at
        )
        
        return Response({
            'success': True,
            'message': f'Assigned {len(roles)} roles to {len(users)} users',
            'data': {
                'assignments_created': len(assignments),
                'users_affected': len(users),
                'roles_assigned': len(roles)
            }
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"Bulk role assignment failed: {e}")
        return Response({
            'error': {
                'code': 'BULK_ASSIGNMENT_ERROR',
                'message': 'Bulk role assignment failed'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# User Role Views

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_roles(request, user_id):
    """Get all roles assigned to a specific user."""
    if not validate_uuid(user_id):
        return Response({
            'error': {
                'code': 'INVALID_UUID',
                'message': 'Invalid user ID format'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if user can view roles (own roles or has permission)
    if str(request.user.id) != user_id:
        try:
            authorization_engine.require_permission(
                user=request.user,
                resource_type='user',
                action='read',
                resource_id=user_id
            )
        except InsufficientPermissionsError:
            return Response({
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': 'Cannot view roles for this user'
                }
            }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        user = User.objects.get(id=user_id)
        user_roles = authorization_engine.get_user_roles(user)
        user_permissions = authorization_engine.get_user_permissions(user)
        
        roles_data = []
        for role in user_roles:
            user_role = UserRole.objects.get(user=user, role=role, is_active=True)
            roles_data.append({
                'id': str(role.id),
                'name': role.name,
                'description': role.description,
                'is_system_role': role.is_system_role,
                'granted_at': user_role.granted_at.isoformat(),
                'expires_at': user_role.expires_at.isoformat() if user_role.expires_at else None,
                'granted_by': user_role.granted_by.email if user_role.granted_by else None,
                'is_expired': user_role.is_expired()
            })
        
        permissions_data = [
            {
                'id': str(perm.id),
                'name': perm.name,
                'resource_type': perm.resource_type,
                'action': perm.action,
                'description': perm.description
            }
            for perm in user_permissions
        ]
        
        return Response({
            'success': True,
            'data': {
                'user_id': str(user.id),
                'user_email': user.email,
                'roles': roles_data,
                'permissions': permissions_data,
                'total_roles': len(roles_data),
                'total_permissions': len(permissions_data)
            }
        })
        
    except User.DoesNotExist:
        return Response({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': 'User not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Failed to get user roles: {e}")
        return Response({
            'error': {
                'code': 'ROLES_ERROR',
                'message': 'Failed to retrieve user roles'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Audit and Reporting Views

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@require_permission('audit_log', 'read')
def permission_audit_log(request):
    """Get permission audit log with filtering and pagination."""
    try:
        # Parse query parameters
        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('page_size', 50)), 100)
        
        # Build filters
        filters = Q()
        
        if 'user_id' in request.GET:
            filters &= Q(user_id=request.GET['user_id'])
        
        if 'action' in request.GET:
            filters &= Q(action=request.GET['action'])
        
        if 'resource_type' in request.GET:
            filters &= Q(resource_type=request.GET['resource_type'])
        
        if 'result' in request.GET:
            result = request.GET['result'].lower() == 'true'
            filters &= Q(result=result)
        
        if 'start_date' in request.GET:
            start_date = datetime.fromisoformat(request.GET['start_date'].replace('Z', '+00:00'))
            filters &= Q(timestamp__gte=start_date)
        
        if 'end_date' in request.GET:
            end_date = datetime.fromisoformat(request.GET['end_date'].replace('Z', '+00:00'))
            filters &= Q(timestamp__lte=end_date)
        
        # Get audit logs
        audit_logs = PermissionAuditLog.objects.filter(filters).select_related(
            'user', 'target_user', 'role', 'permission'
        ).order_by('-timestamp')
        
        # Paginate
        paginator = Paginator(audit_logs, page_size)
        page_obj = paginator.get_page(page)
        
        # Serialize data
        logs_data = []
        for log in page_obj:
            logs_data.append({
                'id': str(log.id),
                'action': log.action,
                'user': {
                    'id': str(log.user.id) if log.user else None,
                    'email': log.user.email if log.user else None
                },
                'target_user': {
                    'id': str(log.target_user.id) if log.target_user else None,
                    'email': log.target_user.email if log.target_user else None
                },
                'role': {
                    'id': str(log.role.id) if log.role else None,
                    'name': log.role.name if log.role else None
                },
                'permission': {
                    'id': str(log.permission.id) if log.permission else None,
                    'name': log.permission.name if log.permission else None
                },
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'action_attempted': log.action_attempted,
                'result': log.result,
                'reason': log.reason,
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.isoformat()
            })
        
        return Response({
            'success': True,
            'data': {
                'logs': logs_data,
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total_pages': paginator.num_pages,
                    'total_count': paginator.count,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous()
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to get audit log: {e}")
        return Response({
            'error': {
                'code': 'AUDIT_LOG_ERROR',
                'message': 'Failed to retrieve audit log'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Helper Functions

def _list_roles(request):
    """List roles with pagination and filtering."""
    try:
        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('page_size', 20)), 100)
        
        # Build filters
        filters = Q(is_active=True)
        
        if 'search' in request.GET:
            search = request.GET['search']
            filters &= Q(name__icontains=search) | Q(description__icontains=search)
        
        if 'parent_role_id' in request.GET:
            filters &= Q(parent_role_id=request.GET['parent_role_id'])
        
        # Get roles with related data
        roles = Role.objects.filter(filters).select_related('parent_role', 'created_by').prefetch_related(
            'permissions',
            'user_assignments'
        ).annotate(
            user_count=Count('user_assignments', filter=Q(user_assignments__is_active=True)),
            permission_count=Count('permissions', filter=Q(permissions__is_active=True))
        ).order_by('name')
        
        # Paginate
        paginator = Paginator(roles, page_size)
        page_obj = paginator.get_page(page)
        
        # Serialize data
        roles_data = []
        for role in page_obj:
            roles_data.append({
                'id': str(role.id),
                'name': role.name,
                'description': role.description,
                'parent_role': {
                    'id': str(role.parent_role.id) if role.parent_role else None,
                    'name': role.parent_role.name if role.parent_role else None
                },
                'is_system_role': role.is_system_role,
                'user_count': role.user_count,
                'permission_count': role.permission_count,
                'created_by': role.created_by.email if role.created_by else None,
                'created_at': role.created_at.isoformat(),
                'updated_at': role.updated_at.isoformat()
            })
        
        return Response({
            'success': True,
            'data': {
                'roles': roles_data,
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total_pages': paginator.num_pages,
                    'total_count': paginator.count,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous()
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to list roles: {e}")
        return Response({
            'error': {
                'code': 'ROLES_LIST_ERROR',
                'message': 'Failed to retrieve roles'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _create_role(request):
    """Create a new role."""
    data = validate_json_request(request)
    if isinstance(data, JsonResponse):
        return data
    
    required_fields = ['name']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return Response({
            'error': {
                'code': 'MISSING_FIELDS',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Check permission to create roles
        authorization_engine.require_permission(
            user=request.user,
            resource_type='role',
            action='create'
        )
        
        # Get parent role if specified
        parent_role = None
        if 'parent_role_id' in data:
            parent_role = Role.objects.get(id=data['parent_role_id'], is_active=True)
        
        # Get permissions if specified
        permissions = []
        if 'permission_ids' in data:
            permissions = Permission.objects.filter(
                id__in=data['permission_ids'], 
                is_active=True
            )
        
        # Create role
        role = role_management_service.create_role(
            name=data['name'],
            description=data.get('description', ''),
            parent_role=parent_role,
            created_by=request.user,
            permissions=list(permissions)
        )
        
        return Response({
            'success': True,
            'message': f'Role "{role.name}" created successfully',
            'data': {
                'id': str(role.id),
                'name': role.name,
                'description': role.description,
                'parent_role': {
                    'id': str(parent_role.id) if parent_role else None,
                    'name': parent_role.name if parent_role else None
                },
                'permissions_assigned': len(permissions),
                'created_at': role.created_at.isoformat()
            }
        }, status=status.HTTP_201_CREATED)
        
    except Role.DoesNotExist:
        return Response({
            'error': {
                'code': 'PARENT_ROLE_NOT_FOUND',
                'message': 'Parent role not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except InsufficientPermissionsError as e:
        return Response({
            'error': {
                'code': 'INSUFFICIENT_PERMISSIONS',
                'message': str(e)
            }
        }, status=status.HTTP_403_FORBIDDEN)
    except Exception as e:
        logger.error(f"Failed to create role: {e}")
        return Response({
            'error': {
                'code': 'ROLE_CREATION_ERROR',
                'message': 'Failed to create role'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _get_role_detail(request, role):
    """Get detailed role information."""
    try:
        authorization_engine.require_permission(
            user=request.user,
            resource_type='role',
            action='read',
            resource_id=str(role.id)
        )
        
        # Get role hierarchy and permissions
        hierarchy = role_management_service.get_role_hierarchy(role)
        
        # Get user assignments
        user_assignments = UserRole.objects.filter(
            role=role, 
            is_active=True
        ).select_related('user', 'granted_by')
        
        assignments_data = []
        for assignment in user_assignments:
            assignments_data.append({
                'user': {
                    'id': str(assignment.user.id),
                    'email': assignment.user.email,
                    'first_name': assignment.user.first_name,
                    'last_name': assignment.user.last_name
                },
                'granted_by': assignment.granted_by.email if assignment.granted_by else None,
                'granted_at': assignment.granted_at.isoformat(),
                'expires_at': assignment.expires_at.isoformat() if assignment.expires_at else None,
                'is_expired': assignment.is_expired()
            })
        
        return Response({
            'success': True,
            'data': {
                **hierarchy,
                'user_assignments': assignments_data,
                'total_users': len(assignments_data)
            }
        })
        
    except InsufficientPermissionsError as e:
        return Response({
            'error': {
                'code': 'INSUFFICIENT_PERMISSIONS',
                'message': str(e)
            }
        }, status=status.HTTP_403_FORBIDDEN)
    except Exception as e:
        logger.error(f"Failed to get role detail: {e}")
        return Response({
            'error': {
                'code': 'ROLE_DETAIL_ERROR',
                'message': 'Failed to retrieve role details'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _list_permissions(request):
    """List permissions with pagination and filtering."""
    try:
        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('page_size', 20)), 100)
        
        # Build filters
        filters = Q(is_active=True)
        
        if 'search' in request.GET:
            search = request.GET['search']
            filters &= Q(name__icontains=search) | Q(description__icontains=search)
        
        if 'resource_type' in request.GET:
            filters &= Q(resource_type=request.GET['resource_type'])
        
        if 'action' in request.GET:
            filters &= Q(action=request.GET['action'])
        
        # Get permissions
        permissions = Permission.objects.filter(filters).annotate(
            role_count=Count('role_assignments', filter=Q(role_assignments__is_active=True))
        ).order_by('resource_type', 'action', 'name')
        
        # Paginate
        paginator = Paginator(permissions, page_size)
        page_obj = paginator.get_page(page)
        
        # Serialize data
        permissions_data = []
        for permission in page_obj:
            permissions_data.append({
                'id': str(permission.id),
                'name': permission.name,
                'description': permission.description,
                'resource_type': permission.resource_type,
                'action': permission.action,
                'role_count': permission.role_count,
                'has_conditions': bool(permission.conditions),
                'created_at': permission.created_at.isoformat(),
                'updated_at': permission.updated_at.isoformat()
            })
        
        return Response({
            'success': True,
            'data': {
                'permissions': permissions_data,
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total_pages': paginator.num_pages,
                    'total_count': paginator.count,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous()
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to list permissions: {e}")
        return Response({
            'error': {
                'code': 'PERMISSIONS_LIST_ERROR',
                'message': 'Failed to retrieve permissions'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _create_permission(request):
    """Create a new permission."""
    data = validate_json_request(request)
    if isinstance(data, JsonResponse):
        return data
    
    required_fields = ['name', 'resource_type', 'action']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return Response({
            'error': {
                'code': 'MISSING_FIELDS',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Check permission to create permissions
        authorization_engine.require_permission(
            user=request.user,
            resource_type='permission',
            action='create'
        )
        
        # Create permission
        permission = Permission.objects.create(
            name=data['name'],
            description=data.get('description', ''),
            resource_type=data['resource_type'],
            action=data['action'],
            conditions=data.get('conditions', {})
        )
        
        return Response({
            'success': True,
            'message': f'Permission "{permission.name}" created successfully',
            'data': {
                'id': str(permission.id),
                'name': permission.name,
                'description': permission.description,
                'resource_type': permission.resource_type,
                'action': permission.action,
                'conditions': permission.conditions,
                'created_at': permission.created_at.isoformat()
            }
        }, status=status.HTTP_201_CREATED)
        
    except InsufficientPermissionsError as e:
        return Response({
            'error': {
                'code': 'INSUFFICIENT_PERMISSIONS',
                'message': str(e)
            }
        }, status=status.HTTP_403_FORBIDDEN)
    except Exception as e:
        logger.error(f"Failed to create permission: {e}")
        return Response({
            'error': {
                'code': 'PERMISSION_CREATION_ERROR',
                'message': 'Failed to create permission'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)