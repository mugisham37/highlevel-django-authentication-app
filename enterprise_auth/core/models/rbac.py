"""
Role-Based Access Control (RBAC) Models

This module implements comprehensive RBAC models with hierarchical support,
temporal permissions, and condition-based evaluation.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any

from django.db import models
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db.models import JSONField

from .base import BaseModel


User = get_user_model()


class Role(BaseModel):
    """
    Role model with hierarchical support and inheritance.
    
    Supports role inheritance where child roles inherit permissions
    from parent roles, enabling flexible organizational structures.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True, db_index=True)
    description = models.TextField(blank=True)
    parent_role = models.ForeignKey(
        'self', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='child_roles'
    )
    is_system_role = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True, db_index=True)
    created_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='created_roles'
    )
    
    # Metadata for role management
    metadata = JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'rbac_role'
        ordering = ['name']
        indexes = [
            models.Index(fields=['name', 'is_active']),
            models.Index(fields=['parent_role', 'is_active']),
        ]
    
    def __str__(self):
        return self.name
    
    def clean(self):
        """Validate role hierarchy to prevent circular references."""
        if self.parent_role:
            # Check for circular reference
            current = self.parent_role
            visited = {self.id}
            
            while current:
                if current.id in visited:
                    raise ValidationError("Circular role hierarchy detected")
                visited.add(current.id)
                current = current.parent_role
    
    def get_all_parent_roles(self) -> List['Role']:
        """Get all parent roles in the hierarchy."""
        parents = []
        current = self.parent_role
        
        while current:
            parents.append(current)
            current = current.parent_role
            
        return parents
    
    def get_all_child_roles(self) -> List['Role']:
        """Get all child roles recursively."""
        children = []
        
        def collect_children(role):
            for child in role.child_roles.filter(is_active=True):
                children.append(child)
                collect_children(child)
        
        collect_children(self)
        return children
    
    def get_inherited_permissions(self) -> Set['Permission']:
        """Get all permissions including inherited from parent roles."""
        permissions = set(self.permissions.filter(is_active=True))
        
        # Add permissions from parent roles
        for parent in self.get_all_parent_roles():
            if parent.is_active:
                permissions.update(parent.permissions.filter(is_active=True))
        
        return permissions


class Permission(BaseModel):
    """
    Permission model with resource-action mapping and condition support.
    
    Supports fine-grained permissions with conditional evaluation
    based on context and resource attributes.
    """
    
    RESOURCE_TYPES = [
        ('user', 'User'),
        ('role', 'Role'),
        ('permission', 'Permission'),
        ('session', 'Session'),
        ('audit_log', 'Audit Log'),
        ('security_event', 'Security Event'),
        ('organization', 'Organization'),
        ('api_key', 'API Key'),
        ('webhook', 'Webhook'),
        ('system', 'System'),
    ]
    
    ACTION_TYPES = [
        ('create', 'Create'),
        ('read', 'Read'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('list', 'List'),
        ('execute', 'Execute'),
        ('manage', 'Manage'),
        ('admin', 'Admin'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True, db_index=True)
    description = models.TextField(blank=True)
    resource_type = models.CharField(max_length=50, choices=RESOURCE_TYPES, db_index=True)
    action = models.CharField(max_length=50, choices=ACTION_TYPES, db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    
    # Conditional permissions support
    conditions = JSONField(default=dict, blank=True, help_text="JSON conditions for permission evaluation")
    
    # Permission metadata
    metadata = JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'rbac_permission'
        ordering = ['resource_type', 'action', 'name']
        unique_together = [('resource_type', 'action', 'name')]
        indexes = [
            models.Index(fields=['resource_type', 'action']),
            models.Index(fields=['name', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.resource_type}:{self.action}:{self.name}"
    
    def evaluate_conditions(self, context: Dict[str, Any]) -> bool:
        """
        Evaluate permission conditions against provided context.
        
        Args:
            context: Dictionary containing evaluation context
            
        Returns:
            bool: True if conditions are met, False otherwise
        """
        if not self.conditions:
            return True
        
        try:
            return self._evaluate_condition_tree(self.conditions, context)
        except Exception:
            # If condition evaluation fails, deny permission for security
            return False
    
    def _evaluate_condition_tree(self, condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Recursively evaluate condition tree."""
        if 'and' in condition:
            return all(self._evaluate_condition_tree(c, context) for c in condition['and'])
        
        if 'or' in condition:
            return any(self._evaluate_condition_tree(c, context) for c in condition['or'])
        
        if 'not' in condition:
            return not self._evaluate_condition_tree(condition['not'], context)
        
        # Simple condition evaluation
        field = condition.get('field')
        operator = condition.get('operator', 'eq')
        value = condition.get('value')
        
        if field not in context:
            return False
        
        context_value = context[field]
        
        if operator == 'eq':
            return context_value == value
        elif operator == 'ne':
            return context_value != value
        elif operator == 'in':
            return context_value in value
        elif operator == 'not_in':
            return context_value not in value
        elif operator == 'gt':
            return context_value > value
        elif operator == 'gte':
            return context_value >= value
        elif operator == 'lt':
            return context_value < value
        elif operator == 'lte':
            return context_value <= value
        elif operator == 'contains':
            return value in context_value
        elif operator == 'startswith':
            return str(context_value).startswith(str(value))
        elif operator == 'endswith':
            return str(context_value).endswith(str(value))
        
        return False


class UserRole(BaseModel):
    """
    User-Role assignment model with temporal permissions support.
    
    Supports time-limited role assignments and tracks who granted
    the role for audit purposes.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_assignments')
    granted_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='granted_roles'
    )
    granted_at = models.DateTimeField(default=timezone.now, db_index=True)
    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    
    # Assignment metadata
    reason = models.TextField(blank=True)
    metadata = JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'rbac_userrole'
        ordering = ['-granted_at']
        unique_together = [('user', 'role')]
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['role', 'is_active']),
            models.Index(fields=['expires_at', 'is_active']),
            models.Index(fields=['granted_at']),
        ]
    
    def __str__(self):
        return f"{self.user} -> {self.role}"
    
    def clean(self):
        """Validate temporal constraints."""
        if self.expires_at and self.expires_at <= timezone.now():
            raise ValidationError("Expiration date must be in the future")
    
    def is_expired(self) -> bool:
        """Check if the role assignment has expired."""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if the role assignment is currently valid."""
        return self.is_active and not self.is_expired() and self.role.is_active
    
    def extend_expiration(self, days: int) -> None:
        """Extend the expiration date by specified days."""
        if self.expires_at:
            self.expires_at += timedelta(days=days)
        else:
            self.expires_at = timezone.now() + timedelta(days=days)
        self.save()


class RolePermission(BaseModel):
    """
    Role-Permission assignment model.
    
    Links roles to permissions with optional conditions and metadata.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='role_assignments')
    granted_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='granted_permissions'
    )
    granted_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True, db_index=True)
    
    # Override conditions for this specific assignment
    override_conditions = JSONField(default=dict, blank=True)
    
    # Assignment metadata
    metadata = JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'rbac_role_permissions'
        ordering = ['-granted_at']
        unique_together = [('role', 'permission')]
        indexes = [
            models.Index(fields=['role', 'is_active']),
            models.Index(fields=['permission', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.role} -> {self.permission}"
    
    def get_effective_conditions(self) -> Dict[str, Any]:
        """Get effective conditions (override or permission default)."""
        return self.override_conditions or self.permission.conditions


class PermissionAuditLog(BaseModel):
    """
    Audit log for permission evaluations and changes.
    
    Tracks all permission checks and administrative changes
    for compliance and security monitoring.
    """
    
    ACTION_TYPES = [
        ('permission_check', 'Permission Check'),
        ('permission_granted', 'Permission Granted'),
        ('permission_denied', 'Permission Denied'),
        ('role_assigned', 'Role Assigned'),
        ('role_revoked', 'Role Revoked'),
        ('permission_created', 'Permission Created'),
        ('permission_updated', 'Permission Updated'),
        ('permission_deleted', 'Permission Deleted'),
        ('role_created', 'Role Created'),
        ('role_updated', 'Role Updated'),
        ('role_deleted', 'Role Deleted'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    action = models.CharField(max_length=50, choices=ACTION_TYPES, db_index=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='permission_audits')
    target_user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='permission_audit_targets'
    )
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    permission = models.ForeignKey(Permission, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Request context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    request_id = models.CharField(max_length=255, blank=True, db_index=True)
    
    # Evaluation details
    resource_type = models.CharField(max_length=50, blank=True)
    resource_id = models.CharField(max_length=255, blank=True)
    action_attempted = models.CharField(max_length=50, blank=True)
    result = models.BooleanField(null=True)
    reason = models.TextField(blank=True)
    
    # Context and metadata
    context_data = JSONField(default=dict, blank=True)
    metadata = JSONField(default=dict, blank=True)
    
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    
    class Meta:
        db_table = 'rbac_permission_audit_log'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['resource_type', 'timestamp']),
            models.Index(fields=['result', 'timestamp']),
            models.Index(fields=['request_id']),
        ]
    
    def __str__(self):
        return f"{self.action} - {self.user} - {self.timestamp}"


# Add the new models to the Role model's permissions relationship
Role.add_to_class(
    'permissions',
    models.ManyToManyField(
        Permission,
        through=RolePermission,
        related_name='roles',
        blank=True
    )
)