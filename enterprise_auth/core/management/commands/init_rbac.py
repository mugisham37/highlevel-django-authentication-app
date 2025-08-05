"""
Management command to initialize RBAC system with default roles and permissions.

This command creates the basic role hierarchy and permissions needed
for the enterprise authentication system to function properly.
"""

import logging
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import transaction

from enterprise_auth.core.models.rbac import Role, Permission, RolePermission
from enterprise_auth.core.services.authorization_service import role_management_service


User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Initialize RBAC system with default roles and permissions'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force recreation of existing roles and permissions',
        )
        parser.add_argument(
            '--admin-email',
            type=str,
            help='Email of user to assign super admin role to',
        )
    
    def handle(self, *args, **options):
        """Initialize RBAC system."""
        try:
            with transaction.atomic():
                self.stdout.write(
                    self.style.SUCCESS('Initializing RBAC system...')
                )
                
                # Create default permissions
                permissions = self._create_default_permissions(options['force'])
                self.stdout.write(
                    self.style.SUCCESS(f'Created {len(permissions)} permissions')
                )
                
                # Create default roles
                roles = self._create_default_roles(permissions, options['force'])
                self.stdout.write(
                    self.style.SUCCESS(f'Created {len(roles)} roles')
                )
                
                # Assign super admin role if email provided
                if options['admin_email']:
                    self._assign_super_admin_role(options['admin_email'])
                
                self.stdout.write(
                    self.style.SUCCESS('RBAC system initialized successfully!')
                )
                
        except Exception as e:
            logger.error(f"RBAC initialization failed: {e}")
            raise CommandError(f"Failed to initialize RBAC system: {e}")
    
    def _create_default_permissions(self, force=False):
        """Create default permissions for all resource types."""
        permissions_data = [
            # User management permissions
            ('user:create', 'user', 'create', 'Create new users'),
            ('user:read', 'user', 'read', 'View user information'),
            ('user:update', 'user', 'update', 'Update user information'),
            ('user:delete', 'user', 'delete', 'Delete users'),
            ('user:list', 'user', 'list', 'List users'),
            ('user:manage', 'user', 'manage', 'Full user management'),
            
            # Role management permissions
            ('role:create', 'role', 'create', 'Create new roles'),
            ('role:read', 'role', 'read', 'View role information'),
            ('role:update', 'role', 'update', 'Update role information'),
            ('role:delete', 'role', 'delete', 'Delete roles'),
            ('role:list', 'role', 'list', 'List roles'),
            ('role:manage', 'role', 'manage', 'Full role management'),
            
            # Permission management permissions
            ('permission:create', 'permission', 'create', 'Create new permissions'),
            ('permission:read', 'permission', 'read', 'View permission information'),
            ('permission:update', 'permission', 'update', 'Update permission information'),
            ('permission:delete', 'permission', 'delete', 'Delete permissions'),
            ('permission:list', 'permission', 'list', 'List permissions'),
            ('permission:manage', 'permission', 'manage', 'Full permission management'),
            
            # Session management permissions
            ('session:create', 'session', 'create', 'Create sessions'),
            ('session:read', 'session', 'read', 'View session information'),
            ('session:update', 'session', 'update', 'Update session information'),
            ('session:delete', 'session', 'delete', 'Terminate sessions'),
            ('session:list', 'session', 'list', 'List sessions'),
            ('session:manage', 'session', 'manage', 'Full session management'),
            
            # Audit log permissions
            ('audit_log:read', 'audit_log', 'read', 'View audit logs'),
            ('audit_log:list', 'audit_log', 'list', 'List audit logs'),
            ('audit_log:manage', 'audit_log', 'manage', 'Full audit log management'),
            
            # Security event permissions
            ('security_event:read', 'security_event', 'read', 'View security events'),
            ('security_event:list', 'security_event', 'list', 'List security events'),
            ('security_event:manage', 'security_event', 'manage', 'Full security event management'),
            
            # Organization permissions
            ('organization:create', 'organization', 'create', 'Create organizations'),
            ('organization:read', 'organization', 'read', 'View organization information'),
            ('organization:update', 'organization', 'update', 'Update organization information'),
            ('organization:delete', 'organization', 'delete', 'Delete organizations'),
            ('organization:list', 'organization', 'list', 'List organizations'),
            ('organization:manage', 'organization', 'manage', 'Full organization management'),
            
            # API key permissions
            ('api_key:create', 'api_key', 'create', 'Create API keys'),
            ('api_key:read', 'api_key', 'read', 'View API key information'),
            ('api_key:update', 'api_key', 'update', 'Update API key information'),
            ('api_key:delete', 'api_key', 'delete', 'Delete API keys'),
            ('api_key:list', 'api_key', 'list', 'List API keys'),
            ('api_key:manage', 'api_key', 'manage', 'Full API key management'),
            
            # Webhook permissions
            ('webhook:create', 'webhook', 'create', 'Create webhooks'),
            ('webhook:read', 'webhook', 'read', 'View webhook information'),
            ('webhook:update', 'webhook', 'update', 'Update webhook information'),
            ('webhook:delete', 'webhook', 'delete', 'Delete webhooks'),
            ('webhook:list', 'webhook', 'list', 'List webhooks'),
            ('webhook:manage', 'webhook', 'manage', 'Full webhook management'),
            
            # System permissions
            ('system:read', 'system', 'read', 'View system information'),
            ('system:update', 'system', 'update', 'Update system configuration'),
            ('system:manage', 'system', 'manage', 'Full system management'),
            ('system:admin', 'system', 'admin', 'System administration'),
        ]
        
        created_permissions = []
        
        for name, resource_type, action, description in permissions_data:
            permission, created = Permission.objects.get_or_create(
                name=name,
                defaults={
                    'resource_type': resource_type,
                    'action': action,
                    'description': description,
                    'is_active': True
                }
            )
            
            if created or force:
                if force and not created:
                    permission.resource_type = resource_type
                    permission.action = action
                    permission.description = description
                    permission.is_active = True
                    permission.save()
                
                created_permissions.append(permission)
                self.stdout.write(f"  Created permission: {name}")
        
        return created_permissions
    
    def _create_default_roles(self, permissions, force=False):
        """Create default role hierarchy."""
        # Create permission lookup
        perm_lookup = {perm.name: perm for perm in Permission.objects.all()}
        
        roles_data = [
            # Super Admin - Full system access
            {
                'name': 'super_admin',
                'description': 'Super administrator with full system access',
                'is_system_role': True,
                'parent': None,
                'permissions': [
                    'system:admin', 'system:manage', 'system:read', 'system:update',
                    'user:manage', 'role:manage', 'permission:manage',
                    'session:manage', 'audit_log:manage', 'security_event:manage',
                    'organization:manage', 'api_key:manage', 'webhook:manage'
                ]
            },
            
            # System Admin - System management without super admin privileges
            {
                'name': 'system_admin',
                'description': 'System administrator with management privileges',
                'is_system_role': True,
                'parent': None,
                'permissions': [
                    'system:manage', 'system:read',
                    'user:manage', 'role:manage', 'permission:read', 'permission:list',
                    'session:manage', 'audit_log:read', 'audit_log:list',
                    'security_event:read', 'security_event:list',
                    'organization:manage', 'api_key:manage', 'webhook:manage'
                ]
            },
            
            # Organization Admin - Organization-level management
            {
                'name': 'organization_admin',
                'description': 'Organization administrator with user and role management',
                'is_system_role': False,
                'parent': None,
                'permissions': [
                    'user:manage', 'role:read', 'role:list', 'role:update',
                    'session:read', 'session:list', 'session:delete',
                    'audit_log:read', 'audit_log:list',
                    'organization:read', 'organization:update',
                    'api_key:manage', 'webhook:manage'
                ]
            },
            
            # User Manager - User management only
            {
                'name': 'user_manager',
                'description': 'User manager with user administration privileges',
                'is_system_role': False,
                'parent': 'organization_admin',
                'permissions': [
                    'user:create', 'user:read', 'user:update', 'user:list',
                    'session:read', 'session:list',
                    'audit_log:read', 'audit_log:list'
                ]
            },
            
            # Security Officer - Security monitoring and management
            {
                'name': 'security_officer',
                'description': 'Security officer with security monitoring privileges',
                'is_system_role': False,
                'parent': None,
                'permissions': [
                    'user:read', 'user:list',
                    'session:read', 'session:list', 'session:delete',
                    'audit_log:read', 'audit_log:list', 'audit_log:manage',
                    'security_event:read', 'security_event:list', 'security_event:manage'
                ]
            },
            
            # API Manager - API and webhook management
            {
                'name': 'api_manager',
                'description': 'API manager with API key and webhook management',
                'is_system_role': False,
                'parent': None,
                'permissions': [
                    'api_key:manage', 'webhook:manage',
                    'audit_log:read', 'audit_log:list'
                ]
            },
            
            # Regular User - Basic user privileges
            {
                'name': 'user',
                'description': 'Regular user with basic privileges',
                'is_system_role': False,
                'parent': None,
                'permissions': [
                    'user:read',  # Can read own profile
                    'session:read'  # Can view own sessions
                ]
            },
            
            # Guest - Minimal privileges
            {
                'name': 'guest',
                'description': 'Guest user with minimal privileges',
                'is_system_role': False,
                'parent': None,
                'permissions': []
            }
        ]
        
        created_roles = []
        role_lookup = {}
        
        # First pass: create roles without parents
        for role_data in roles_data:
            role, created = Role.objects.get_or_create(
                name=role_data['name'],
                defaults={
                    'description': role_data['description'],
                    'is_system_role': role_data['is_system_role'],
                    'is_active': True
                }
            )
            
            if created or force:
                if force and not created:
                    role.description = role_data['description']
                    role.is_system_role = role_data['is_system_role']
                    role.is_active = True
                    role.save()
                
                created_roles.append(role)
                role_lookup[role_data['name']] = role
                self.stdout.write(f"  Created role: {role_data['name']}")
        
        # Second pass: set parent relationships
        for role_data in roles_data:
            if role_data['parent']:
                role = role_lookup.get(role_data['name']) or Role.objects.get(name=role_data['name'])
                parent_role = role_lookup.get(role_data['parent']) or Role.objects.get(name=role_data['parent'])
                role.parent_role = parent_role
                role.save()
                self.stdout.write(f"  Set parent for {role_data['name']}: {role_data['parent']}")
        
        # Third pass: assign permissions
        for role_data in roles_data:
            role = role_lookup.get(role_data['name']) or Role.objects.get(name=role_data['name'])
            
            # Clear existing permissions if force
            if force:
                RolePermission.objects.filter(role=role).delete()
            
            # Assign permissions
            for perm_name in role_data['permissions']:
                if perm_name in perm_lookup:
                    permission = perm_lookup[perm_name]
                    role_perm, created = RolePermission.objects.get_or_create(
                        role=role,
                        permission=permission,
                        defaults={'is_active': True}
                    )
                    if created:
                        self.stdout.write(f"    Assigned permission {perm_name} to {role_data['name']}")
        
        return created_roles
    
    def _assign_super_admin_role(self, admin_email):
        """Assign super admin role to specified user."""
        try:
            user = User.objects.get(email=admin_email)
            super_admin_role = Role.objects.get(name='super_admin')
            
            user_role = role_management_service.assign_role_to_user(
                user=user,
                role=super_admin_role,
                reason='Initial RBAC setup'
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'Assigned super_admin role to {admin_email}')
            )
            
        except User.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(f'User {admin_email} not found - skipping role assignment')
            )
        except Role.DoesNotExist:
            self.stdout.write(
                self.style.ERROR('Super admin role not found')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to assign super admin role: {e}')
            )