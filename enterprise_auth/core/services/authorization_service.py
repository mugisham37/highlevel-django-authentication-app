"""
Authorization Service

Comprehensive authorization service implementing role-based access control
with hierarchical roles, conditional permissions, and performance caching.
"""

import logging
from typing import Dict, List, Optional, Set, Any, Tuple
from datetime import datetime, timedelta
from functools import lru_cache

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from ..models.rbac import Role, Permission, UserRole, RolePermission, PermissionAuditLog
from ..exceptions import AuthorizationError, InsufficientPermissionsError


User = get_user_model()
logger = logging.getLogger(__name__)


class AuthorizationEngine:
    """
    Core authorization engine with caching and audit support.
    
    Provides high-performance permission evaluation with comprehensive
    audit logging and flexible condition-based permissions.
    """
    
    # Cache configuration
    CACHE_TIMEOUT = 300  # 5 minutes
    USER_PERMISSIONS_CACHE_KEY = "user_permissions:{user_id}"
    USER_ROLES_CACHE_KEY = "user_roles:{user_id}"
    ROLE_PERMISSIONS_CACHE_KEY = "role_permissions:{role_id}"
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def check_permission(
        self, 
        user: User, 
        resource_type: str, 
        action: str, 
        resource_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        audit: bool = True
    ) -> bool:
        """
        Check if user has permission for specific resource and action.
        
        Args:
            user: User to check permissions for
            resource_type: Type of resource being accessed
            action: Action being performed
            resource_id: Optional specific resource ID
            context: Additional context for condition evaluation
            audit: Whether to log the permission check
            
        Returns:
            bool: True if permission granted, False otherwise
        """
        if context is None:
            context = {}
        
        # Add user context
        context.update({
            'user_id': str(user.id),
            'user_email': user.email,
            'timestamp': timezone.now().isoformat(),
            'resource_type': resource_type,
            'action': action,
            'resource_id': resource_id,
        })
        
        try:
            # Get user permissions with caching
            user_permissions = self.get_user_permissions(user)
            
            # Find matching permissions
            matching_permissions = [
                perm for perm in user_permissions
                if perm.resource_type == resource_type and perm.action == action
            ]
            
            if not matching_permissions:
                result = False
                reason = f"No matching permissions for {resource_type}:{action}"
            else:
                # Evaluate conditions for matching permissions
                result = any(
                    perm.evaluate_conditions(context) 
                    for perm in matching_permissions
                )
                reason = "Permission granted" if result else "Conditions not met"
            
            # Audit the permission check
            if audit:
                self._audit_permission_check(
                    user=user,
                    resource_type=resource_type,
                    action=action,
                    resource_id=resource_id,
                    result=result,
                    reason=reason,
                    context=context
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Permission check failed for user {user.id}: {e}")
            
            # Audit the error
            if audit:
                self._audit_permission_check(
                    user=user,
                    resource_type=resource_type,
                    action=action,
                    resource_id=resource_id,
                    result=False,
                    reason=f"Permission check error: {str(e)}",
                    context=context
                )
            
            # Fail secure - deny permission on error
            return False
    
    def require_permission(
        self, 
        user: User, 
        resource_type: str, 
        action: str, 
        resource_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Require permission or raise AuthorizationError.
        
        Args:
            user: User to check permissions for
            resource_type: Type of resource being accessed
            action: Action being performed
            resource_id: Optional specific resource ID
            context: Additional context for condition evaluation
            
        Raises:
            InsufficientPermissionsError: If permission is denied
        """
        if not self.check_permission(user, resource_type, action, resource_id, context):
            raise InsufficientPermissionsError(
                f"User {user.email} lacks permission for {resource_type}:{action}"
            )
    
    def get_user_permissions(self, user: User) -> Set[Permission]:
        """
        Get all effective permissions for a user with caching.
        
        Args:
            user: User to get permissions for
            
        Returns:
            Set[Permission]: All effective permissions
        """
        cache_key = self.USER_PERMISSIONS_CACHE_KEY.format(user_id=user.id)
        permissions = cache.get(cache_key)
        
        if permissions is None:
            permissions = self._calculate_user_permissions(user)
            cache.set(cache_key, permissions, self.CACHE_TIMEOUT)
        
        return permissions
    
    def get_user_roles(self, user: User) -> List[Role]:
        """
        Get all effective roles for a user with caching.
        
        Args:
            user: User to get roles for
            
        Returns:
            List[Role]: All effective roles
        """
        cache_key = self.USER_ROLES_CACHE_KEY.format(user_id=user.id)
        roles = cache.get(cache_key)
        
        if roles is None:
            roles = self._calculate_user_roles(user)
            cache.set(cache_key, roles, self.CACHE_TIMEOUT)
        
        return roles
    
    def get_role_permissions(self, role: Role) -> Set[Permission]:
        """
        Get all permissions for a role including inherited permissions.
        
        Args:
            role: Role to get permissions for
            
        Returns:
            Set[Permission]: All role permissions
        """
        cache_key = self.ROLE_PERMISSIONS_CACHE_KEY.format(role_id=role.id)
        permissions = cache.get(cache_key)
        
        if permissions is None:
            permissions = role.get_inherited_permissions()
            cache.set(cache_key, permissions, self.CACHE_TIMEOUT)
        
        return permissions
    
    def invalidate_user_cache(self, user: User) -> None:
        """Invalidate cached permissions and roles for a user."""
        cache.delete(self.USER_PERMISSIONS_CACHE_KEY.format(user_id=user.id))
        cache.delete(self.USER_ROLES_CACHE_KEY.format(user_id=user.id))
    
    def invalidate_role_cache(self, role: Role) -> None:
        """Invalidate cached permissions for a role."""
        cache.delete(self.ROLE_PERMISSIONS_CACHE_KEY.format(role_id=role.id))
        
        # Also invalidate users who have this role
        user_roles = UserRole.objects.filter(role=role, is_active=True)
        for user_role in user_roles:
            self.invalidate_user_cache(user_role.user)
    
    def _calculate_user_permissions(self, user: User) -> Set[Permission]:
        """Calculate all effective permissions for a user."""
        permissions = set()
        
        # Get all active user roles
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            role__is_active=True
        ).select_related('role')
        
        # Filter out expired roles
        valid_roles = [
            ur.role for ur in user_roles 
            if not ur.is_expired()
        ]
        
        # Collect permissions from all roles (including inherited)
        for role in valid_roles:
            permissions.update(self.get_role_permissions(role))
        
        return permissions
    
    def _calculate_user_roles(self, user: User) -> List[Role]:
        """Calculate all effective roles for a user."""
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            role__is_active=True
        ).select_related('role')
        
        # Filter out expired roles and return role objects
        return [
            ur.role for ur in user_roles 
            if not ur.is_expired()
        ]
    
    def _audit_permission_check(
        self,
        user: User,
        resource_type: str,
        action: str,
        resource_id: Optional[str],
        result: bool,
        reason: str,
        context: Dict[str, Any]
    ) -> None:
        """Audit a permission check."""
        try:
            PermissionAuditLog.objects.create(
                action='permission_check',
                user=user,
                resource_type=resource_type,
                resource_id=resource_id or '',
                action_attempted=action,
                result=result,
                reason=reason,
                context_data=context,
                ip_address=context.get('ip_address'),
                user_agent=context.get('user_agent', ''),
                request_id=context.get('request_id', ''),
            )
        except Exception as e:
            self.logger.error(f"Failed to audit permission check: {e}")


class RoleManagementService:
    """
    Service for managing roles, permissions, and assignments.
    
    Provides comprehensive role management with validation,
    audit logging, and cache invalidation.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.auth_engine = AuthorizationEngine()
    
    @transaction.atomic
    def create_role(
        self,
        name: str,
        description: str = "",
        parent_role: Optional[Role] = None,
        created_by: Optional[User] = None,
        permissions: Optional[List[Permission]] = None
    ) -> Role:
        """
        Create a new role with optional parent and permissions.
        
        Args:
            name: Role name (must be unique)
            description: Role description
            parent_role: Optional parent role for inheritance
            created_by: User creating the role
            permissions: Optional list of permissions to assign
            
        Returns:
            Role: Created role instance
        """
        try:
            role = Role.objects.create(
                name=name,
                description=description,
                parent_role=parent_role,
                created_by=created_by
            )
            
            # Assign permissions if provided
            if permissions:
                self.assign_permissions_to_role(role, permissions, created_by)
            
            # Audit role creation
            self._audit_role_action('role_created', created_by, role=role)
            
            self.logger.info(f"Role '{name}' created by {created_by}")
            return role
            
        except Exception as e:
            self.logger.error(f"Failed to create role '{name}': {e}")
            raise
    
    @transaction.atomic
    def assign_role_to_user(
        self,
        user: User,
        role: Role,
        granted_by: Optional[User] = None,
        expires_at: Optional[datetime] = None,
        reason: str = ""
    ) -> UserRole:
        """
        Assign a role to a user.
        
        Args:
            user: User to assign role to
            role: Role to assign
            granted_by: User granting the role
            expires_at: Optional expiration date
            reason: Reason for assignment
            
        Returns:
            UserRole: Created user role assignment
        """
        try:
            # Check if assignment already exists
            existing = UserRole.objects.filter(user=user, role=role).first()
            if existing and existing.is_valid():
                self.logger.warning(f"Role '{role.name}' already assigned to user {user.email}")
                return existing
            
            # Create or reactivate assignment
            if existing:
                existing.is_active = True
                existing.granted_by = granted_by
                existing.granted_at = timezone.now()
                existing.expires_at = expires_at
                existing.reason = reason
                existing.save()
                user_role = existing
            else:
                user_role = UserRole.objects.create(
                    user=user,
                    role=role,
                    granted_by=granted_by,
                    expires_at=expires_at,
                    reason=reason
                )
            
            # Invalidate user cache
            self.auth_engine.invalidate_user_cache(user)
            
            # Audit role assignment
            self._audit_role_action(
                'role_assigned', 
                granted_by, 
                target_user=user, 
                role=role,
                reason=reason
            )
            
            self.logger.info(f"Role '{role.name}' assigned to user {user.email}")
            return user_role
            
        except Exception as e:
            self.logger.error(f"Failed to assign role '{role.name}' to user {user.email}: {e}")
            raise
    
    @transaction.atomic
    def revoke_role_from_user(
        self,
        user: User,
        role: Role,
        revoked_by: Optional[User] = None,
        reason: str = ""
    ) -> bool:
        """
        Revoke a role from a user.
        
        Args:
            user: User to revoke role from
            role: Role to revoke
            revoked_by: User revoking the role
            reason: Reason for revocation
            
        Returns:
            bool: True if role was revoked, False if not found
        """
        try:
            user_role = UserRole.objects.filter(
                user=user, 
                role=role, 
                is_active=True
            ).first()
            
            if not user_role:
                self.logger.warning(f"Role '{role.name}' not found for user {user.email}")
                return False
            
            user_role.is_active = False
            user_role.metadata.update({
                'revoked_by': str(revoked_by.id) if revoked_by else None,
                'revoked_at': timezone.now().isoformat(),
                'revocation_reason': reason
            })
            user_role.save()
            
            # Invalidate user cache
            self.auth_engine.invalidate_user_cache(user)
            
            # Audit role revocation
            self._audit_role_action(
                'role_revoked', 
                revoked_by, 
                target_user=user, 
                role=role,
                reason=reason
            )
            
            self.logger.info(f"Role '{role.name}' revoked from user {user.email}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to revoke role '{role.name}' from user {user.email}: {e}")
            raise
    
    @transaction.atomic
    def assign_permissions_to_role(
        self,
        role: Role,
        permissions: List[Permission],
        granted_by: Optional[User] = None
    ) -> List[RolePermission]:
        """
        Assign multiple permissions to a role.
        
        Args:
            role: Role to assign permissions to
            permissions: List of permissions to assign
            granted_by: User granting the permissions
            
        Returns:
            List[RolePermission]: Created role permission assignments
        """
        try:
            assignments = []
            
            for permission in permissions:
                # Check if assignment already exists
                existing = RolePermission.objects.filter(
                    role=role, 
                    permission=permission
                ).first()
                
                if existing and existing.is_active:
                    continue
                
                if existing:
                    existing.is_active = True
                    existing.granted_by = granted_by
                    existing.granted_at = timezone.now()
                    existing.save()
                    assignments.append(existing)
                else:
                    assignment = RolePermission.objects.create(
                        role=role,
                        permission=permission,
                        granted_by=granted_by
                    )
                    assignments.append(assignment)
            
            # Invalidate role cache
            self.auth_engine.invalidate_role_cache(role)
            
            # Audit permission assignments
            for assignment in assignments:
                self._audit_role_action(
                    'permission_granted',
                    granted_by,
                    role=role,
                    permission=assignment.permission
                )
            
            self.logger.info(f"Assigned {len(assignments)} permissions to role '{role.name}'")
            return assignments
            
        except Exception as e:
            self.logger.error(f"Failed to assign permissions to role '{role.name}': {e}")
            raise
    
    @transaction.atomic
    def bulk_assign_roles(
        self,
        users: List[User],
        roles: List[Role],
        granted_by: Optional[User] = None,
        expires_at: Optional[datetime] = None
    ) -> List[UserRole]:
        """
        Bulk assign roles to multiple users.
        
        Args:
            users: List of users to assign roles to
            roles: List of roles to assign
            granted_by: User granting the roles
            expires_at: Optional expiration date for all assignments
            
        Returns:
            List[UserRole]: Created user role assignments
        """
        assignments = []
        
        try:
            for user in users:
                for role in roles:
                    assignment = self.assign_role_to_user(
                        user=user,
                        role=role,
                        granted_by=granted_by,
                        expires_at=expires_at,
                        reason="Bulk assignment"
                    )
                    assignments.append(assignment)
            
            self.logger.info(f"Bulk assigned {len(roles)} roles to {len(users)} users")
            return assignments
            
        except Exception as e:
            self.logger.error(f"Bulk role assignment failed: {e}")
            raise
    
    def get_role_hierarchy(self, role: Role) -> Dict[str, Any]:
        """
        Get complete role hierarchy information.
        
        Args:
            role: Root role to get hierarchy for
            
        Returns:
            Dict: Role hierarchy with parents and children
        """
        return {
            'role': {
                'id': str(role.id),
                'name': role.name,
                'description': role.description,
                'is_system_role': role.is_system_role,
                'is_active': role.is_active,
            },
            'parents': [
                {
                    'id': str(parent.id),
                    'name': parent.name,
                    'description': parent.description,
                }
                for parent in role.get_all_parent_roles()
            ],
            'children': [
                {
                    'id': str(child.id),
                    'name': child.name,
                    'description': child.description,
                }
                for child in role.get_all_child_roles()
            ],
            'permissions': [
                {
                    'id': str(perm.id),
                    'name': perm.name,
                    'resource_type': perm.resource_type,
                    'action': perm.action,
                }
                for perm in self.auth_engine.get_role_permissions(role)
            ]
        }
    
    def _audit_role_action(
        self,
        action: str,
        user: Optional[User],
        target_user: Optional[User] = None,
        role: Optional[Role] = None,
        permission: Optional[Permission] = None,
        reason: str = ""
    ) -> None:
        """Audit a role management action."""
        try:
            PermissionAuditLog.objects.create(
                action=action,
                user=user,
                target_user=target_user,
                role=role,
                permission=permission,
                reason=reason,
                timestamp=timezone.now()
            )
        except Exception as e:
            self.logger.error(f"Failed to audit role action: {e}")


# Global instances
authorization_engine = AuthorizationEngine()
role_management_service = RoleManagementService()