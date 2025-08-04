"""
Unit tests for MFA Device Management service.

This module contains comprehensive tests for MFA device registration,
confirmation, listing, removal, and organization policy enforcement.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase
from django.utils import timezone
from django.core.cache import cache
from datetime import timedelta

from enterprise_auth.core.models import UserProfile, MFADevice, MFAAttempt
from enterprise_auth.core.services.mfa_device_management_service import (
    MFADeviceManagementService,
    mfa_device_management_service
)
from enterprise_auth.core.exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError
)


class TestMFADeviceManagementService(TestCase):
    """Test cases for MFA Device Management service."""
    
    def setUp(self):
        """Set up test data."""
        self.service = MFADeviceManagementService()
        
        # Create test user
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            organization='Test Corp'
        )
        
        # Clear cache before each test
        cache.clear()
    
    def tearDown(self):
        """Clean up after tests."""
        cache.clear()
    
    def test_register_totp_device_success(self):
        """Test successful TOTP device registration."""
        with patch('enterprise_auth.core.services.mfa_device_management_service.MFAService') as mock_mfa_service:
            mock_mfa_service.return_value.setup_totp.return_value = {
                'device_id': 'test-device-id',
                'secret_key': 'TESTSECRET123',
                'qr_code_uri': 'otpauth://totp/test',
                'qr_code_data': 'data:image/png;base64,test'
            }
            
            result = self.service.register_device(
                user=self.user,
                device_type='totp',
                device_name='My Phone',
                device_config={},
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
            
            self.assertIn('device_id', result)
            self.assertIn('secret_key', result)
            mock_mfa_service.return_value.setup_totp.assert_called_once()
    
    def test_register_sms_device_success(self):
        """Test successful SMS device registration."""
        with patch.object(self.service, 'sms_service') as mock_sms_service:
            mock_sms_service.setup_sms.return_value = {
                'device_id': 'test-sms-device-id',
                'phone_number_masked': '***-***-1234',
                'code_sent': True
            }
            
            result = self.service.register_device(
                user=self.user,
                device_type='sms',
                device_name='My SMS',
                device_config={'phone_number': '+1234567890'},
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
            
            self.assertIn('device_id', result)
            self.assertIn('phone_number_masked', result)
            mock_sms_service.setup_sms.assert_called_once()
    
    def test_register_device_invalid_type(self):
        """Test device registration with invalid type."""
        with self.assertRaises(MFAError) as context:
            self.service.register_device(
                user=self.user,
                device_type='invalid_type',
                device_name='Test Device',
                device_config={},
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
        
        self.assertIn('Invalid device type', str(context.exception))
    
    def test_register_device_duplicate_name(self):
        """Test device registration with duplicate name."""
        # Create existing device
        MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='My Phone'
        )
        
        with self.assertRaises(MFAError) as context:
            self.service.register_device(
                user=self.user,
                device_type='totp',
                device_name='My Phone',
                device_config={},
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
        
        self.assertIn('Device name already exists', str(context.exception))
    
    def test_register_device_exceeds_limit(self):
        """Test device registration when user exceeds device limit."""
        # Mock the device limit check
        with patch.object(self.service, 'max_devices_per_user', 1):
            # Create existing device
            MFADevice.objects.create(
                user=self.user,
                device_type='totp',
                device_name='Existing Device'
            )
            
            with self.assertRaises(MFAError) as context:
                self.service.register_device(
                    user=self.user,
                    device_type='sms',
                    device_name='New Device',
                    device_config={'phone_number': '+1234567890'},
                    ip_address='192.168.1.1',
                    user_agent='Test Agent'
                )
            
            self.assertIn('Maximum', str(context.exception))
    
    def test_confirm_totp_device_success(self):
        """Test successful TOTP device confirmation."""
        # Create pending device
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='My Phone',
            status='pending'
        )
        
        with patch('enterprise_auth.core.services.mfa_device_management_service.MFAService') as mock_mfa_service:
            mock_mfa_service.return_value.confirm_totp_setup.return_value = {
                'device_id': str(device.id),
                'device_name': 'My Phone',
                'status': 'active'
            }
            
            result = self.service.confirm_device_registration(
                user=self.user,
                device_id=str(device.id),
                confirmation_data={'verification_code': '123456'},
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
            
            self.assertEqual(result['device_id'], str(device.id))
            self.assertEqual(result['status'], 'active')
            mock_mfa_service.return_value.confirm_totp_setup.assert_called_once()
    
    def test_confirm_device_not_found(self):
        """Test device confirmation with non-existent device."""
        with self.assertRaises(MFADeviceNotFoundError):
            self.service.confirm_device_registration(
                user=self.user,
                device_id='non-existent-id',
                confirmation_data={'verification_code': '123456'},
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
    
    def test_confirm_device_timeout(self):
        """Test device confirmation after timeout."""
        # Create device that's older than timeout
        old_time = timezone.now() - timedelta(hours=2)
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='My Phone',
            status='pending'
        )
        device.created_at = old_time
        device.save()
        
        with patch.object(self.service, 'device_confirmation_timeout', 3600):  # 1 hour
            with self.assertRaises(MFAVerificationError) as context:
                self.service.confirm_device_registration(
                    user=self.user,
                    device_id=str(device.id),
                    confirmation_data={'verification_code': '123456'},
                    ip_address='192.168.1.1',
                    user_agent='Test Agent'
                )
            
            self.assertIn('timeout', str(context.exception))
            
            # Check device was marked as compromised
            device.refresh_from_db()
            self.assertEqual(device.status, 'compromised')
    
    def test_list_user_devices_active_only(self):
        """Test listing only active devices."""
        # Create devices with different statuses
        active_device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Active Device',
            status='active',
            is_confirmed=True
        )
        
        pending_device = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Pending Device',
            status='pending'
        )
        
        disabled_device = MFADevice.objects.create(
            user=self.user,
            device_type='email',
            device_name='Disabled Device',
            status='disabled',
            is_confirmed=True
        )
        
        # List active devices only
        devices = self.service.list_user_devices(
            user=self.user,
            include_inactive=False
        )
        
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['id'], str(active_device.id))
        self.assertEqual(devices[0]['name'], 'Active Device')
    
    def test_list_user_devices_include_inactive(self):
        """Test listing all devices including inactive."""
        # Create devices with different statuses
        MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Active Device',
            status='active',
            is_confirmed=True
        )
        
        MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Pending Device',
            status='pending'
        )
        
        # List all devices
        devices = self.service.list_user_devices(
            user=self.user,
            include_inactive=True
        )
        
        self.assertEqual(len(devices), 2)
    
    def test_list_user_devices_filter_by_type(self):
        """Test listing devices filtered by type."""
        # Create devices of different types
        MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='TOTP Device',
            status='active',
            is_confirmed=True
        )
        
        MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='SMS Device',
            status='active',
            is_confirmed=True
        )
        
        # Filter by TOTP type
        devices = self.service.list_user_devices(
            user=self.user,
            device_type_filter='totp'
        )
        
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['type'], 'totp')
    
    def test_remove_device_success(self):
        """Test successful device removal."""
        # Create multiple devices so removal is allowed
        device_to_remove = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Device to Remove',
            status='active',
            is_confirmed=True
        )
        
        MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Remaining Device',
            status='active',
            is_confirmed=True
        )
        
        # Mock MFA verification requirement
        with patch.object(self.service, 'require_current_mfa_for_removal', False):
            result = self.service.remove_device(
                user=self.user,
                device_id=str(device_to_remove.id),
                removal_reason='user_request',
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
        
        self.assertTrue(result['removed'])
        self.assertEqual(result['device_info']['device_name'], 'Device to Remove')
        
        # Verify device was deleted
        with self.assertRaises(MFADevice.DoesNotExist):
            MFADevice.objects.get(id=device_to_remove.id)
    
    def test_remove_device_not_found(self):
        """Test removing non-existent device."""
        with self.assertRaises(MFADeviceNotFoundError):
            self.service.remove_device(
                user=self.user,
                device_id='non-existent-id',
                removal_reason='user_request',
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
    
    def test_remove_device_violates_minimum(self):
        """Test removing device when it would violate minimum requirement."""
        # Create only one device
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Only Device',
            status='active',
            is_confirmed=True
        )
        
        with patch.object(self.service, 'min_active_devices', 1):
            with self.assertRaises(MFAError) as context:
                self.service.remove_device(
                    user=self.user,
                    device_id=str(device.id),
                    removal_reason='user_request',
                    ip_address='192.168.1.1',
                    user_agent='Test Agent'
                )
            
            self.assertIn('At least one active MFA device must remain', str(context.exception))
    
    def test_remove_device_requires_mfa_verification(self):
        """Test removing device when MFA verification is required."""
        # Create multiple devices
        device_to_remove = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Device to Remove',
            status='active',
            is_confirmed=True
        )
        
        MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Remaining Device',
            status='active',
            is_confirmed=True
        )
        
        # Test without MFA verification
        with patch.object(self.service, 'require_current_mfa_for_removal', True):
            with self.assertRaises(MFAError) as context:
                self.service.remove_device(
                    user=self.user,
                    device_id=str(device_to_remove.id),
                    removal_reason='user_request',
                    ip_address='192.168.1.1',
                    user_agent='Test Agent'
                )
            
            self.assertIn('Current MFA verification required', str(context.exception))
    
    def test_get_organization_mfa_policy_no_enforcement(self):
        """Test getting organization policy when enforcement is disabled."""
        with patch.object(self.service, 'org_mfa_enforcement_enabled', False):
            policy = self.service.get_organization_mfa_policy('Test Corp')
            
            self.assertFalse(policy['enforcement_enabled'])
            self.assertFalse(policy['mfa_required'])
    
    def test_get_organization_mfa_policy_with_enforcement(self):
        """Test getting organization policy with enforcement enabled."""
        with patch.object(self.service, 'org_mfa_enforcement_enabled', True):
            with patch.object(self.service, 'default_org_mfa_required', True):
                policy = self.service.get_organization_mfa_policy('Test Corp')
                
                self.assertTrue(policy['enforcement_enabled'])
                self.assertTrue(policy['mfa_required'])
                self.assertEqual(policy['min_devices_required'], 1)
    
    def test_get_organization_mfa_policy_cached(self):
        """Test that organization policy is cached."""
        with patch.object(self.service, 'org_mfa_enforcement_enabled', True):
            # First call
            policy1 = self.service.get_organization_mfa_policy('Test Corp')
            
            # Second call should use cache
            policy2 = self.service.get_organization_mfa_policy('Test Corp')
            
            self.assertEqual(policy1, policy2)
            
            # Verify cache key exists
            cache_key = f"org_mfa_policy:Test Corp"
            cached_policy = cache.get(cache_key)
            self.assertIsNotNone(cached_policy)
    
    def test_enforce_organization_mfa_policy_no_organization(self):
        """Test policy enforcement for user without organization."""
        user_no_org = UserProfile.objects.create_user(
            email='noorg@example.com',
            password='testpass123',
            first_name='No',
            last_name='Org'
        )
        
        result = self.service.enforce_organization_mfa_policy(
            user=user_no_org,
            ip_address='192.168.1.1',
            user_agent='Test Agent'
        )
        
        self.assertFalse(result['policy_enforced'])
        self.assertEqual(result['compliance_status'], 'not_applicable')
    
    def test_enforce_organization_mfa_policy_compliant(self):
        """Test policy enforcement for compliant user."""
        # Create active MFA device
        MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='TOTP Device',
            status='active',
            is_confirmed=True
        )
        
        MFADevice.objects.create(
            user=self.user,
            device_type='backup_codes',
            device_name='Backup Codes',
            status='active',
            is_confirmed=True
        )
        
        with patch.object(self.service, 'org_mfa_enforcement_enabled', True):
            with patch.object(self.service, 'default_org_mfa_required', True):
                result = self.service.enforce_organization_mfa_policy(
                    user=self.user,
                    ip_address='192.168.1.1',
                    user_agent='Test Agent'
                )
                
                self.assertTrue(result['policy_enforced'])
                self.assertEqual(result['compliance_status'], 'compliant')
                self.assertEqual(len(result['compliance_issues']), 0)
    
    def test_enforce_organization_mfa_policy_non_compliant(self):
        """Test policy enforcement for non-compliant user."""
        with patch.object(self.service, 'org_mfa_enforcement_enabled', True):
            with patch.object(self.service, 'default_org_mfa_required', True):
                result = self.service.enforce_organization_mfa_policy(
                    user=self.user,
                    ip_address='192.168.1.1',
                    user_agent='Test Agent'
                )
                
                self.assertTrue(result['policy_enforced'])
                self.assertEqual(result['compliance_status'], 'non_compliant')
                self.assertGreater(len(result['compliance_issues']), 0)
                self.assertIn('block_access', result['enforcement_actions'])
    
    def test_enforce_organization_mfa_policy_grace_period(self):
        """Test policy enforcement during grace period."""
        # Create user within grace period
        recent_user = UserProfile.objects.create_user(
            email='recent@example.com',
            password='testpass123',
            first_name='Recent',
            last_name='User',
            organization='Test Corp'
        )
        
        with patch.object(self.service, 'org_mfa_enforcement_enabled', True):
            with patch.object(self.service, 'default_org_mfa_required', True):
                # Mock policy to have grace period
                mock_policy = {
                    'enforcement_enabled': True,
                    'mfa_required': True,
                    'allowed_device_types': ['totp', 'sms', 'email', 'backup_codes'],
                    'min_devices_required': 1,
                    'max_devices_allowed': 10,
                    'require_backup_codes': False,
                    'allowed_grace_period_hours': 24,
                    'enforce_device_diversity': False
                }
                
                with patch.object(self.service, 'get_organization_mfa_policy', return_value=mock_policy):
                    result = self.service.enforce_organization_mfa_policy(
                        user=recent_user,
                        ip_address='192.168.1.1',
                        user_agent='Test Agent'
                    )
                    
                    self.assertEqual(result['compliance_status'], 'grace_period')
                    self.assertIn('show_warning', result['enforcement_actions'])
    
    def test_get_device_management_statistics(self):
        """Test getting device management statistics."""
        # Create devices and attempts
        totp_device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='TOTP Device',
            status='active',
            is_confirmed=True
        )
        
        sms_device = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='SMS Device',
            status='pending'
        )
        
        # Create MFA attempts
        MFAAttempt.objects.create(
            user=self.user,
            device=totp_device,
            result='success',
            ip_address='192.168.1.1'
        )
        
        MFAAttempt.objects.create(
            user=self.user,
            device=totp_device,
            result='failure',
            ip_address='192.168.1.1'
        )
        
        statistics = self.service.get_device_management_statistics(
            user=self.user,
            days=30
        )
        
        self.assertEqual(statistics['total_devices'], 2)
        self.assertEqual(statistics['active_devices'], 1)
        self.assertEqual(statistics['pending_devices'], 1)
        self.assertEqual(statistics['device_type_statistics']['totp']['device_count'], 1)
        self.assertEqual(statistics['device_type_statistics']['totp']['total_attempts'], 2)
        self.assertEqual(statistics['device_type_statistics']['totp']['successful_attempts'], 1)
        self.assertEqual(statistics['device_type_statistics']['totp']['failed_attempts'], 1)
    
    def test_can_device_be_removed_inactive_device(self):
        """Test that inactive devices can always be removed."""
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Inactive Device',
            status='disabled'
        )
        
        can_remove = self.service._can_device_be_removed(self.user, device)
        self.assertTrue(can_remove)
    
    def test_can_device_be_removed_violates_minimum(self):
        """Test that device cannot be removed if it violates minimum."""
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Only Device',
            status='active',
            is_confirmed=True
        )
        
        with patch.object(self.service, 'min_active_devices', 1):
            can_remove = self.service._can_device_be_removed(self.user, device)
            self.assertFalse(can_remove)
    
    def test_calculate_device_security_score(self):
        """Test device security score calculation."""
        # Create TOTP device (high security)
        totp_device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='TOTP Device',
            status='active',
            is_confirmed=True,
            last_used=timezone.now() - timedelta(days=1)  # Recent usage
        )
        
        # Create SMS device (lower security)
        sms_device = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='SMS Device',
            status='active',
            is_confirmed=True
        )
        
        totp_score = self.service._calculate_device_security_score(totp_device)
        sms_score = self.service._calculate_device_security_score(sms_device)
        
        # TOTP should have higher security score than SMS
        self.assertGreater(totp_score, sms_score)
        self.assertGreaterEqual(totp_score, 0.9)  # TOTP base score + recent usage bonus
        self.assertLessEqual(sms_score, 0.6)  # SMS base score
    
    def test_is_primary_device(self):
        """Test primary device identification."""
        # Create first device (should be primary)
        first_device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='First Device',
            status='active',
            is_confirmed=True
        )
        
        # Create second device of same type (should not be primary)
        second_device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Second Device',
            status='active',
            is_confirmed=True
        )
        
        self.assertTrue(self.service._is_primary_device(self.user, first_device))
        self.assertFalse(self.service._is_primary_device(self.user, second_device))
    
    def test_verify_current_mfa_totp(self):
        """Test current MFA verification with TOTP."""
        verification_data = {
            'type': 'totp',
            'code': '123456',
            'device_id': 'test-device-id'
        }
        
        with patch('enterprise_auth.core.services.mfa_device_management_service.MFAService') as mock_mfa_service:
            mock_mfa_service.return_value.verify_totp.return_value = {'verified': True}
            
            # Should not raise exception
            self.service._verify_current_mfa(
                user=self.user,
                verification_data=verification_data,
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
            
            mock_mfa_service.return_value.verify_totp.assert_called_once()
    
    def test_verify_current_mfa_backup_code(self):
        """Test current MFA verification with backup code."""
        verification_data = {
            'type': 'backup_code',
            'code': 'ABCD1234'
        }
        
        with patch.object(self.service, 'backup_codes_service') as mock_backup_service:
            mock_backup_service.validate_backup_code.return_value = {'valid': True}
            
            # Should not raise exception
            self.service._verify_current_mfa(
                user=self.user,
                verification_data=verification_data,
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
            
            mock_backup_service.validate_backup_code.assert_called_once()
    
    def test_verify_current_mfa_invalid_type(self):
        """Test current MFA verification with invalid type."""
        verification_data = {
            'type': 'invalid_type',
            'code': '123456'
        }
        
        with self.assertRaises(MFAError) as context:
            self.service._verify_current_mfa(
                user=self.user,
                verification_data=verification_data,
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
        
        self.assertIn('Invalid MFA verification type', str(context.exception))


class TestMFADeviceManagementServiceIntegration(TestCase):
    """Integration tests for MFA Device Management service."""
    
    def setUp(self):
        """Set up test data."""
        self.service = mfa_device_management_service
        
        # Create test user
        self.user = UserProfile.objects.create_user(
            email='integration@example.com',
            password='testpass123',
            first_name='Integration',
            last_name='Test',
            organization='Integration Corp'
        )
        
        # Clear cache
        cache.clear()
    
    def tearDown(self):
        """Clean up after tests."""
        cache.clear()
    
    def test_full_device_lifecycle(self):
        """Test complete device lifecycle from registration to removal."""
        # 1. Register device
        with patch('enterprise_auth.core.services.mfa_device_management_service.MFAService') as mock_mfa_service:
            mock_mfa_service.return_value.setup_totp.return_value = {
                'device_id': 'test-device-id',
                'secret_key': 'TESTSECRET123'
            }
            
            registration_result = self.service.register_device(
                user=self.user,
                device_type='totp',
                device_name='Integration Test Device',
                device_config={},
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
            
            self.assertIn('device_id', registration_result)
        
        # 2. Create actual device for confirmation test
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Integration Test Device',
            status='pending'
        )
        
        # 3. Confirm device
        with patch('enterprise_auth.core.services.mfa_device_management_service.MFAService') as mock_mfa_service:
            mock_mfa_service.return_value.confirm_totp_setup.return_value = {
                'device_id': str(device.id),
                'device_name': 'Integration Test Device',
                'status': 'active'
            }
            
            confirmation_result = self.service.confirm_device_registration(
                user=self.user,
                device_id=str(device.id),
                confirmation_data={'verification_code': '123456'},
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
            
            self.assertEqual(confirmation_result['status'], 'active')
        
        # 4. List devices
        devices = self.service.list_user_devices(user=self.user)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['name'], 'Integration Test Device')
        
        # 5. Create second device to allow removal
        second_device = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Second Device',
            status='active',
            is_confirmed=True
        )
        
        # 6. Remove first device
        with patch.object(self.service, 'require_current_mfa_for_removal', False):
            removal_result = self.service.remove_device(
                user=self.user,
                device_id=str(device.id),
                removal_reason='integration_test',
                ip_address='192.168.1.1',
                user_agent='Test Agent'
            )
            
            self.assertTrue(removal_result['removed'])
        
        # 7. Verify device was removed
        remaining_devices = self.service.list_user_devices(user=self.user)
        self.assertEqual(len(remaining_devices), 1)
        self.assertEqual(remaining_devices[0]['name'], 'Second Device')
    
    def test_organization_policy_enforcement_workflow(self):
        """Test organization policy enforcement workflow."""
        # 1. Check policy for organization
        policy = self.service.get_organization_mfa_policy('Integration Corp')
        self.assertIn('enforcement_enabled', policy)
        
        # 2. Enforce policy with no devices (should be non-compliant)
        with patch.object(self.service, 'org_mfa_enforcement_enabled', True):
            with patch.object(self.service, 'default_org_mfa_required', True):
                enforcement_result = self.service.enforce_organization_mfa_policy(
                    user=self.user,
                    ip_address='192.168.1.1',
                    user_agent='Test Agent'
                )
                
                self.assertEqual(enforcement_result['compliance_status'], 'non_compliant')
                self.assertGreater(len(enforcement_result['compliance_issues']), 0)
        
        # 3. Add MFA device
        MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Compliance Device',
            status='active',
            is_confirmed=True
        )
        
        # 4. Enforce policy again (should be compliant)
        with patch.object(self.service, 'org_mfa_enforcement_enabled', True):
            with patch.object(self.service, 'default_org_mfa_required', True):
                enforcement_result = self.service.enforce_organization_mfa_policy(
                    user=self.user,
                    ip_address='192.168.1.1',
                    user_agent='Test Agent'
                )
                
                self.assertEqual(enforcement_result['compliance_status'], 'compliant')
                self.assertEqual(len(enforcement_result['compliance_issues']), 0)
    
    def test_device_statistics_accuracy(self):
        """Test accuracy of device management statistics."""
        # Create devices with different statuses
        active_device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Active Device',
            status='active',
            is_confirmed=True,
            usage_count=5
        )
        
        pending_device = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Pending Device',
            status='pending'
        )
        
        disabled_device = MFADevice.objects.create(
            user=self.user,
            device_type='email',
            device_name='Disabled Device',
            status='disabled',
            is_confirmed=True
        )
        
        # Create MFA attempts
        MFAAttempt.objects.create(
            user=self.user,
            device=active_device,
            result='success',
            ip_address='192.168.1.1'
        )
        
        MFAAttempt.objects.create(
            user=self.user,
            device=active_device,
            result='failure',
            ip_address='192.168.1.1'
        )
        
        # Get statistics
        statistics = self.service.get_device_management_statistics(
            user=self.user,
            days=30
        )
        
        # Verify statistics accuracy
        self.assertEqual(statistics['total_devices'], 3)
        self.assertEqual(statistics['active_devices'], 1)
        self.assertEqual(statistics['pending_devices'], 1)
        self.assertEqual(statistics['disabled_devices'], 1)
        
        # Verify device type statistics
        totp_stats = statistics['device_type_statistics']['totp']
        self.assertEqual(totp_stats['device_count'], 1)
        self.assertEqual(totp_stats['total_attempts'], 2)
        self.assertEqual(totp_stats['successful_attempts'], 1)
        self.assertEqual(totp_stats['failed_attempts'], 1)
        
        sms_stats = statistics['device_type_statistics']['sms']
        self.assertEqual(sms_stats['device_count'], 0)  # Pending devices not counted as active
        self.assertEqual(sms_stats['total_attempts'], 0)