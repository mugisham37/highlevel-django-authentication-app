"""
Tests for RBAC (Role-Based Access Control) system.

This module tests the comprehensive RBAC implementation including
models, services, middleware, and API endpoints.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status

from ..models.rbac import Role, Permission, UserRole, RolePermission, PermissionAuditLog
from ..services.authorization_service import authorization_engine, role_management_service


User = get_user_model()


class RBACModelsTestCase(TestCase):
    """Test RBAC models functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Create test permissions
        self.read_permission = Permission.objects.create(
            name='test:read',
            resource_type='test',
            action='read',
            description='Read test resources'
        )
        
        self.write_permission = Permission.objects.create(
            name='test:write',
            resource_type='test',
            action='create',
            description='Write test resources'
        )
        
        # Create test roles
        self.admin_role = Role.objects.create(
            name='test_admin',
            description='Test administrator role'
        )
        
        self.user_role = Role.objects.create(
            name='test_user',
            description='Test user role',
            parent_role=self.admin_role
        )
    
    def test_permission_creation(self):
        """Test permission model creation and validation."""
        self.assertEqual(self.read_permission.name, 'test:read')
        self.assertEqual(self.read_permission.resource_type, 'test')
        self.assertEqual(self.read_permission.action, 'read')
        self.assertTrue(self.read_permission.is_active)
    
    def test_role_creation(self):
        """Test role model creation and hierarchy."""
        self.assertEqual(self.admin_role.name, 'test_admin')
        self.assertTrue(self.admin_role.is_active)
        self.assertIsNone(self.admin_role.parent_role)
        
        self.assertEqual(self.user_role.parent_role, self.admin_role)
        self.assertIn(self.user_role, self.admin_role.child_roles.all())
    
    def test_role_hierarchy(self):
        """Test role hierarchy methods."""
        # Test parent roles
        parents = self.user_role.get_all_parent_roles()
        self.assertIn(self.admin_role, parents)
        
        # Test child roles
        children = self.admin_role.get_all_child_roles()
        self.assertIn(self.user_role, children)
    
    def test_permission_assignment(self):
        """Test permission assignment to roles."""
        # Assign permission to role
        role_perm = RolePermission.objects.create(
            role=self.admin_role,
            permission=self.read_permission
        )
        
        self.assertTrue(role_perm.is_active)
        self.assertIn(self.read_permission, self.admin_role.permissions.all())
    
    def test_user_role_assignment(self):
        """Test user role assignment."""
        user_role = UserRole.objects.create(
            user=self.user,
            role=self.admin_role
        )
        
        self.assertTrue(user_role.is_valid())
        self.assertFalse(user_role.is_expired())
    
    def test_permission_conditions(self):
        """Test conditional permission evaluation."""
        # Create permission with conditions
        conditional_perm = Permission.objects.create(
            name='test:conditional',
            resource_type='test',
            action='read',
            conditions={
                'field': 'user_id',
                'operator': 'eq',
                'value': str(self.user.id)
            }
        )
        
        # Test condition evaluation
        context = {'user_id': str(self.user.id)}
        self.assertTrue(conditional_perm.evaluate_conditions(context))
        
        context = {'user_id': 'different_id'}
        self.assertFalse(conditional_perm.evaluate_conditions(context))


class AuthorizationEngineTestCase(TestCase):
    """Test authorization engine functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Create permission
        self.permission = Permission.objects.create(
            name='test:read',
            resource_type='test',
            action='read'
        )
        
        # Create role and assign permission
        self.role = Role.objects.create(name='test_role')
        RolePermission.objects.create(
            role=self.role,
            permission=self.permission
        )
        
        # Assign role to user
        UserRole.objects.create(
            user=self.user,
            role=self.role
        )
    
    def test_permission_check(self):
        """Test basic permission checking."""
        # User should have permission
        has_permission = authorization_engine.check_permission(
            user=self.user,
            resource_type='test',
            action='read'
        )
        self.assertTrue(has_permission)
        
        # User should not have different permission
        has_permission = authorization_engine.check_permission(
            user=self.user,
            resource_type='test',
            action='write'
        )
        self.assertFalse(has_permission)
    
    def test_user_permissions_caching(self):
        """Test that user permissions are cached."""
        # First call should cache permissions
        permissions1 = authorization_engine.get_user_permissions(self.user)
        
        # Second call should return cached permissions
        permissions2 = authorization_engine.get_user_permissions(self.user)
        
        self.assertEqual(permissions1, permissions2)
        self.assertIn(self.permission, permissions1)
    
    def test_cache_invalidation(self):
        """Test cache invalidation when roles change."""
        # Get initial permissions
        initial_permissions = authorization_engine.get_user_permissions(self.user)
        
        # Create new permission and assign to role
        new_permission = Permission.objects.create(
            name='test:write',
            resource_type='test',
            action='write'
        )
        RolePermission.objects.create(
            role=self.role,
            permission=new_permission
        )
        
        # Invalidate cache
        authorization_engine.invalidate_role_cache(self.role)
        
        # Get updated permissions
        updated_permissions = authorization_engine.get_user_permissions(self.user)
        
        self.assertIn(new_permission, updated_permissions)
        self.assertNotEqual(initial_permissions, updated_permissions)


class RoleManagementServiceTestCase(TestCase):
    """Test role management service functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.admin_user = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            first_name='Admin',
            last_name='User'
        )
        
        self.regular_user = User.objects.create_user(
            email='user@example.com',
            password='userpass123',
            first_name='Regular',
            last_name='User'
        )
        
        self.permission = Permission.objects.create(
            name='test:read',
            resource_type='test',
            action='read'
        )
    
    def test_role_creation(self):
        """Test role creation through service."""
        role = role_management_service.create_role(
            name='test_role',
            description='Test role',
            created_by=self.admin_user,
            permissions=[self.permission]
        )
        
        self.assertEqual(role.name, 'test_role')
        self.assertEqual(role.created_by, self.admin_user)
        self.assertIn(self.permission, role.permissions.all())
    
    def test_role_assignment(self):
        """Test role assignment to user."""
        role = Role.objects.create(name='test_role')
        
        user_role = role_management_service.assign_role_to_user(
            user=self.regular_user,
            role=role,
            granted_by=self.admin_user,
            reason='Test assignment'
        )
        
        self.assertEqual(user_role.user, self.regular_user)
        self.assertEqual(user_role.role, role)
        self.assertEqual(user_role.granted_by, self.admin_user)
        self.assertTrue(user_role.is_valid())
    
    def test_role_revocation(self):
        """Test role revocation from user."""
        role = Role.objects.create(name='test_role')
        UserRole.objects.create(user=self.regular_user, role=role)
        
        success = role_management_service.revoke_role_from_user(
            user=self.regular_user,
            role=role,
            revoked_by=self.admin_user,
            reason='Test revocation'
        )
        
        self.assertTrue(success)
        
        # Check that role is deactivated
        user_role = UserRole.objects.get(user=self.regular_user, role=role)
        self.assertFalse(user_role.is_active)
    
    def test_bulk_role_assignment(self):
        """Test bulk role assignment."""
        users = [self.regular_user, self.admin_user]
        roles = [
            Role.objects.create(name='role1'),
            Role.objects.create(name='role2')
        ]
        
        assignments = role_management_service.bulk_assign_roles(
            users=users,
            roles=roles,
            granted_by=self.admin_user
        )
        
        # Should create 4 assignments (2 users × 2 roles)
        self.assertEqual(len(assignments), 4)
        
        # Verify assignments exist
        for user in users:
            for role in roles:
                self.assertTrue(
                    UserRole.objects.filter(
                        user=user, 
                        role=role, 
                        is_active=True
                    ).exists()
                )


class RBACAPITestCase(APITestCase):
    """Test RBAC API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.admin_user = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            first_name='Admin',
            last_name='User'
        )
        
        self.regular_user = User.objects.create_user(
            email='user@example.com',
            password='userpass123',
            first_name='Regular',
            last_name='User'
        )
        
        # Create admin role with permissions
        self.admin_role = Role.objects.create(name='admin')
        self.role_manage_permission = Permission.objects.create(
            name='role:manage',
            resource_type='role',
            action='manage'
        )
        RolePermission.objects.create(
            role=self.admin_role,
            permission=self.role_manage_permission
        )
        
        # Assign admin role to admin user
        UserRole.objects.create(
            user=self.admin_user,
            role=self.admin_role
        )
    
    def test_roles_list_api(self):
        """Test roles list API endpoint."""
        self.client.force_authenticate(user=self.admin_user)
        
        url = reverse('core:rbac_roles_list_create')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)
        self.assertIn('roles', response.data['data'])
    
    def test_role_creation_api(self):
        """Test role creation API endpoint."""
        self.client.force_authenticate(user=self.admin_user)
        
        url = reverse('core:rbac_roles_list_create')
        data = {
            'name': 'new_test_role',
            'description': 'New test role'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Role.objects.filter(name='new_test_role').exists())
    
    def test_role_assignment_api(self):
        """Test role assignment API endpoint."""
        self.client.force_authenticate(user=self.admin_user)
        
        test_role = Role.objects.create(name='test_role')
        
        url = reverse('core:rbac_assign_role')
        data = {
            'user_id': str(self.regular_user.id),
            'role_id': str(test_role.id),
            'reason': 'Test assignment'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            UserRole.objects.filter(
                user=self.regular_user,
                role=test_role,
                is_active=True
            ).exists()
        )
    
    def test_unauthorized_access(self):
        """Test that unauthorized users cannot access RBAC APIs."""
        self.client.force_authenticate(user=self.regular_user)
        
        url = reverse('core:rbac_roles_list_create')
        response = self.client.get(url)
        
        # Should be forbidden since regular user doesn't have role:list permission
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class PermissionAuditTestCase(TestCase):
    """Test permission audit logging."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.permission = Permission.objects.create(
            name='test:read',
            resource_type='test',
            action='read'
        )
        
        self.role = Role.objects.create(name='test_role')
        RolePermission.objects.create(
            role=self.role,
            permission=self.permission
        )
        UserRole.objects.create(user=self.user, role=self.role)
    
    def test_permission_check_audit(self):
        """Test that permission checks are audited."""
        initial_count = PermissionAuditLog.objects.count()
        
        # Perform permission check
        authorization_engine.check_permission(
            user=self.user,
            resource_type='test',
            action='read',
            context={'ip_address': '127.0.0.1'}
        )
        
        # Check that audit log was created
        self.assertEqual(PermissionAuditLog.objects.count(), initial_count + 1)
        
        audit_log = PermissionAuditLog.objects.latest('timestamp')
        self.assertEqual(audit_log.user, self.user)
        self.assertEqual(audit_log.action, 'permission_check')
        self.assertEqual(audit_log.resource_type, 'test')
        self.assertEqual(audit_log.action_attempted, 'read')
        self.assertTrue(audit_log.result)
    
    def test_role_assignment_audit(self):
        """Test that role assignments are audited."""
        new_user = User.objects.create_user(
            email='newuser@example.com',
            password='newpass123',
            first_name='New',
            last_name='User'
        )
        
        initial_count = PermissionAuditLog.objects.count()
        
        # Assign role
        role_management_service.assign_role_to_user(
            user=new_user,
            role=self.role,
            granted_by=self.user,
            reason='Test assignment'
        )
        
        # Check that audit log was created
        self.assertEqual(PermissionAuditLog.objects.count(), initial_count + 1)
        
        audit_log = PermissionAuditLog.objects.latest('timestamp')
        self.assertEqual(audit_log.action, 'role_assigned')
        self.assertEqual(audit_log.user, self.user)
        self.assertEqual(audit_log.target_user, new_user)
        self.assertEqual(audit_log.role, self.role)