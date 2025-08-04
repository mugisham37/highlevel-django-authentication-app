"""
Tests for MFA Device Management functionality.

This module contains comprehensive tests for MFA device registration,
confirmation, listing, removal, and organization policy enforcement.
"""

import json
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from ..models import UserProfile, MFADevice, MFAAttempt
from ..services.mfa_device_management_service import MFADeviceManagementService
from ..exceptions import MFAError, MFADeviceNotFoundError, MFAVerificationError


class MFADeviceManagementServiceTest(TestCase):
    """Test cases for MFA Device Management Service."""
    
    def setUp(self):
        """Set up test data."""
        self.service = MFADeviceManagementService()
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            organization='Test Corp'
        )
        self.ip_address = '192.168.1.1'
        self.user_agent = 'Mozilla/5.0 Test Browser'
    
    def test_register_totp_device(self):
        """Test TOTP device registration."""
        with patch('enterprise_auth.core.services.mfa_service.MFAService.setup_totp') as mock_setup:
            mock_setup.return_value = {
                'device_id': 'test-device-id',
                'device_type': 'totp',
                'device_name': 'Test TOTP',
                'status': 'pending',
                'qr_code': 'data:image/png;base64,test',
                'secret_key': 'TESTSECRET123',
                'confirmation_required': True
            }
            
            result = self.service.register_device(
                user=self.user,
                device_type='totp',
                device_name='Test TOTP',
                device_config={},
                ip_address=self.ip_address,
                user_agent=self.user_agent
            )
            
            self.assertEqual(result['device_type'], 'totp')
            self.assertEqual(result['device_name'], 'Test TOTP')
            self.assertEqual(result['status'], 'pending')
            self.assertTrue(result['confirmation_required'])
            mock_setup.assert_called_once()
    
    def test_register_sms_device(self):
        """Test SMS device registration."""
        with patch.object(self.service.sms_service, 'setup_sms') as mock_setup:
            mock_setup.return_value = {
                'device_id': 'test-sms-device-id',
                'device_type': 'sms',
                'device_name': 'Test SMS',
                'status': 'pending',
                'phone_number_masked': '***-***-1234',
                'confirmation_required': True
            }
            
            result = self.service.register_device(
                user=self.user,
                device_type='sms',
                device_name='Test SMS',
                device_config={'phone_number': '+1234567890'},
                ip_address=self.ip_address,
                user_agent=self.user_agent
            )
            
            self.assertEqual(result['device_type'], 'sms')
            self.assertEqual(result['device_name'], 'Test SMS')
            mock_setup.assert_called_once()
    
    def test_register_device_invalid_type(self):
        """Test device registration with invalid type."""
        with self.assertRaises(MFAError) as context:
            self.service.register_device(
                user=self.user,
                device_type='invalid',
                device_name='Test Device',
                device_config={},
                ip_address=self.ip_address,
                user_agent=self.user_agent
            )
        
        self.assertIn('Invalid device type', str(context.exception))
    
    def test_register_device_duplicate_name(self):
        """Test device registration with duplicate name."""
        # Create existing device
        MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Test Device',
            status='active',
            is_confirmed=True
        )
        
        with self.assertRaises(MFAError) as context:
            self.service.register_device(
                user=self.user,
                device_type='totp',
                device_name='Test Device',
                device_config={},
                ip_address=self.ip_address,
                user_agent=self.user_agent
            )
        
        self.assertIn('Device name already exists', str(context.exception))
    
    def test_list_user_devices(self):
        """Test listing user devices."""
        # Create test devices
        totp_device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='TOTP Device',
            status='active',
            is_confirmed=True,
            usage_count=5
        )
        
        sms_device = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='SMS Device',
            status='pending',
            is_confirmed=False
        )
        
        # Test active devices only
        devices = self.service.list_user_devices(self.user, include_inactive=False)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['name'], 'TOTP Device')
        self.assertTrue(devices[0]['is_active'])
        
        # Test all devices
        devices = self.service.list_user_devices(self.user, include_inactive=True)
        self.assertEqual(len(devices), 2)
    
    def test_remove_device_success(self):
        """Test successful device removal."""
        # Create multiple devices
        device1 = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='TOTP Device 1',
            status='active',
            is_confirmed=True
        )
        
        device2 = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='TOTP Device 2',
            status='active',
            is_confirmed=True
        )
        
        # Mock MFA verification
        with patch.object(self.service, '_verify_current_mfa', return_value=True):
            result = self.service.remove_device(
                user=self.user,
                device_id=str(device1.id),
                removal_reason='user_request',
                current_mfa_verification={'type': 'totp', 'code': '123456'},
                ip_address=self.ip_address,
                user_agent=self.user_agent
            )
        
        self.assertTrue(result['removed'])
        self.assertEqual(result['device_info']['device_name'], 'TOTP Device 1')
        
        # Verify device was deleted
        with self.assertRaises(MFADevice.DoesNotExist):
            MFADevice.objects.get(id=device1.id)
    
    def test_remove_device_not_found(self):
        """Test removing non-existent device."""
        import uuid
        with self.assertRaises(MFADeviceNotFoundError):
            self.service.remove_device(
                user=self.user,
                device_id=str(uuid.uuid4()),  # Use valid UUID format
                removal_reason='user_request',
                ip_address=self.ip_address,
                user_agent=self.user_agent
            )
    
    def test_remove_last_device_blocked(self):
        """Test that removing the last device is blocked."""
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Last Device',
            status='active',
            is_confirmed=True
        )
        
        with self.assertRaises(MFAError) as context:
            self.service.remove_device(
                user=self.user,
                device_id=str(device.id),
                removal_reason='user_request',
                ip_address=self.ip_address,
                user_agent=self.user_agent
            )
        
        self.assertIn('At least one active MFA device must remain', str(context.exception))
    
    def test_get_organization_mfa_policy(self):
        """Test getting organization MFA policy."""
        policy = self.service.get_organization_mfa_policy('Test Corp')
        
        self.assertIsInstance(policy, dict)
        self.assertIn('enforcement_enabled', policy)
        self.assertIn('mfa_required', policy)
        self.assertIn('allowed_device_types', policy)
        self.assertIn('min_devices_required', policy)
    
    def test_enforce_organization_mfa_policy_compliant(self):
        """Test organization policy enforcement for compliant user."""
        # Create active devices
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
        
        result = self.service.enforce_organization_mfa_policy(
            user=self.user,
            ip_address=self.ip_address,
            user_agent=self.user_agent
        )
        
        self.assertTrue(result['policy_enforced'])
        self.assertEqual(result['organization'], 'Test Corp')
        self.assertEqual(result['compliance_status'], 'compliant')
        self.assertEqual(len(result['compliance_issues']), 0)
    
    def test_get_device_management_statistics(self):
        """Test getting device management statistics."""
        # Create test devices and attempts
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='TOTP Device',
            status='active',
            is_confirmed=True
        )
        
        # Create some attempts
        MFAAttempt.objects.create(
            user=self.user,
            device=device,
            result='success',
            ip_address=self.ip_address
        )
        
        MFAAttempt.objects.create(
            user=self.user,
            device=device,
            result='failure',
            ip_address=self.ip_address
        )
        
        stats = self.service.get_device_management_statistics(self.user, days=30)
        
        self.assertEqual(stats['total_devices'], 1)
        self.assertEqual(stats['active_devices'], 1)
        self.assertIn('device_type_statistics', stats)
        self.assertIn('totp', stats['device_type_statistics'])
        self.assertEqual(stats['device_type_statistics']['totp']['total_attempts'], 2)
        self.assertEqual(stats['device_type_statistics']['totp']['successful_attempts'], 1)


class MFADeviceManagementViewsTest(TestCase):
    """Test cases for MFA Device Management API views."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            organization='Test Corp'
        )
        self.client.force_authenticate(user=self.user)
    
    def test_register_mfa_device_api(self):
        """Test MFA device registration API."""
        with patch('enterprise_auth.core.services.mfa_device_management_service.mfa_device_management_service.register_device') as mock_register:
            mock_register.return_value = {
                'device_id': 'test-device-id',
                'device_type': 'totp',
                'device_name': 'Test TOTP',
                'status': 'pending',
                'confirmation_required': True
            }
            
            response = self.client.post(
                reverse('core:register_mfa_device'),
                data={
                    'device_type': 'totp',
                    'device_name': 'Test TOTP',
                    'device_config': {}
                },
                format='json'
            )
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['device_type'], 'totp')
            mock_register.assert_called_once()
    
    def test_register_mfa_device_missing_type(self):
        """Test MFA device registration with missing device type."""
        response = self.client.post(
            reverse('core:register_mfa_device'),
            data={
                'device_name': 'Test Device',
                'device_config': {}
            },
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertIn('Device type is required', response.data['error']['message'])
    
    def test_confirm_mfa_device_registration_api(self):
        """Test MFA device confirmation API."""
        with patch('enterprise_auth.core.services.mfa_device_management_service.mfa_device_management_service.confirm_device_registration') as mock_confirm:
            mock_confirm.return_value = {
                'device_id': 'test-device-id',
                'device_name': 'Test TOTP',
                'device_type': 'totp',
                'status': 'active',
                'confirmed_at': timezone.now().isoformat()
            }
            
            response = self.client.post(
                reverse('core:confirm_mfa_device_registration'),
                data={
                    'device_id': 'test-device-id',
                    'confirmation_data': {
                        'verification_code': '123456'
                    }
                },
                format='json'
            )
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['status'], 'active')
            mock_confirm.assert_called_once()
    
    def test_list_mfa_devices_api(self):
        """Test MFA devices listing API."""
        with patch('enterprise_auth.core.services.mfa_device_management_service.mfa_device_management_service.list_user_devices') as mock_list:
            mock_list.return_value = [
                {
                    'id': 'device-1',
                    'name': 'TOTP Device',
                    'type': 'totp',
                    'status': 'active',
                    'is_active': True,
                    'usage_count': 5
                }
            ]
            
            response = self.client.get(reverse('core:list_mfa_devices_detailed'))
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(len(response.data['data']['devices']), 1)
            self.assertEqual(response.data['data']['total_devices'], 1)
            self.assertEqual(response.data['data']['active_devices'], 1)
            mock_list.assert_called_once()
    
    def test_remove_mfa_device_api(self):
        """Test MFA device removal API."""
        with patch('enterprise_auth.core.services.mfa_device_management_service.mfa_device_management_service.remove_device') as mock_remove:
            mock_remove.return_value = {
                'removed': True,
                'device_info': {
                    'device_id': 'test-device-id',
                    'device_name': 'Test Device',
                    'device_type': 'totp'
                },
                'removal_reason': 'user_request',
                'removed_at': timezone.now().isoformat()
            }
            
            response = self.client.delete(
                reverse('core:remove_mfa_device'),
                data={
                    'device_id': 'test-device-id',
                    'removal_reason': 'user_request',
                    'current_mfa_verification': {
                        'type': 'totp',
                        'code': '123456'
                    }
                },
                format='json'
            )
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertTrue(response.data['data']['removed'])
            mock_remove.assert_called_once()
    
    def test_get_organization_mfa_policy_api(self):
        """Test organization MFA policy API."""
        with patch('enterprise_auth.core.services.mfa_device_management_service.mfa_device_management_service.get_organization_mfa_policy') as mock_policy:
            mock_policy.return_value = {
                'enforcement_enabled': True,
                'mfa_required': True,
                'allowed_device_types': ['totp', 'sms', 'email', 'backup_codes'],
                'min_devices_required': 2
            }
            
            response = self.client.get(reverse('core:get_organization_mfa_policy'))
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['organization'], 'Test Corp')
            self.assertTrue(response.data['data']['enforcement_enabled'])
            mock_policy.assert_called_once()
    
    def test_get_organization_mfa_policy_no_org(self):
        """Test organization MFA policy API for user without organization."""
        self.user.organization = None
        self.user.save()
        
        response = self.client.get(reverse('core:get_organization_mfa_policy'))
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertIn('not associated with an organization', response.data['error']['message'])
    
    def test_enforce_organization_mfa_policy_api(self):
        """Test organization MFA policy enforcement API."""
        with patch('enterprise_auth.core.services.mfa_device_management_service.mfa_device_management_service.enforce_organization_mfa_policy') as mock_enforce:
            mock_enforce.return_value = {
                'policy_enforced': True,
                'organization': 'Test Corp',
                'compliance_status': 'compliant',
                'compliance_issues': [],
                'active_devices_count': 2,
                'device_types': ['totp', 'backup_codes']
            }
            
            response = self.client.post(reverse('core:enforce_organization_mfa_policy'))
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['compliance_status'], 'compliant')
            mock_enforce.assert_called_once()
    
    def test_get_device_management_statistics_api(self):
        """Test device management statistics API."""
        with patch('enterprise_auth.core.services.mfa_device_management_service.mfa_device_management_service.get_device_management_statistics') as mock_stats:
            mock_stats.return_value = {
                'period_days': 30,
                'total_devices': 2,
                'active_devices': 2,
                'pending_devices': 0,
                'disabled_devices': 0,
                'device_type_statistics': {
                    'totp': {
                        'device_count': 1,
                        'total_attempts': 10,
                        'successful_attempts': 9,
                        'failed_attempts': 1
                    }
                }
            }
            
            response = self.client.get(
                reverse('core:get_device_management_statistics'),
                {'days': '30'}
            )
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['total_devices'], 2)
            self.assertEqual(response.data['data']['active_devices'], 2)
            mock_stats.assert_called_once_with(user=self.user, days=30)
    
    def test_bulk_device_operation_api(self):
        """Test bulk device operation API."""
        # Create test devices
        device1 = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Device 1',
            status='active',
            is_confirmed=True
        )
        
        device2 = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Device 2',
            status='active',
            is_confirmed=True
        )
        
        response = self.client.post(
            reverse('core:bulk_device_operation'),
            data={
                'operation': 'disable',
                'device_ids': [str(device1.id), str(device2.id)],
                'reason': 'security_incident'
            },
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['data']['operation'], 'disable')
        self.assertEqual(response.data['data']['total_devices'], 2)
        
        # Verify devices were disabled
        device1.refresh_from_db()
        device2.refresh_from_db()
        self.assertEqual(device1.status, 'disabled')
        self.assertEqual(device2.status, 'disabled')
    
    def test_unauthenticated_access_denied(self):
        """Test that unauthenticated requests are denied."""
        self.client.force_authenticate(user=None)
        
        response = self.client.get(reverse('core:list_mfa_devices_detailed'))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)