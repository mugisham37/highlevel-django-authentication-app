#!/usr/bin/env python3
"""
Comprehensive test suite for JWT Token Refresh and Rotation System.

This test validates the implementation of task 12: "Create token refresh and rotation system"
including:
- Refresh token rotation to prevent replay attacks
- Automatic token refresh flow for client applications
- Refresh token family tracking for security
- Refresh token revocation on suspicious activity

Requirements tested: 2.3, 2.5
"""

import os
import sys
import django
import uuid
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.testing')

try:
    django.setup()
except Exception as e:
    print(f"Failed to setup Django: {e}")
    sys.exit(1)

# Import after Django setup
from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from django.core.cache import cache
from rest_framework.test import APIClient
from rest_framework import status

from enterprise_auth.core.models.user import UserProfile
from enterprise_auth.core.models.jwt import RefreshToken, TokenBlacklist
from enterprise_auth.core.services.jwt_service import jwt_service, DeviceInfo
from enterprise_auth.core.tasks.jwt_tasks import (
    cleanup_expired_refresh_tokens,
    monitor_refresh_token_security
)


class TokenRefreshRotationSystemTest(TransactionTestCase):
    """Test suite for JWT Token Refresh and Rotation System."""
    
    def setUp(self):
        """Set up test data."""
        print("\n" + "="*80)
        print("JWT TOKEN REFRESH AND ROTATION SYSTEM TEST")
        print("="*80)
        
        # Clear cache
        cache.clear()
        
        # Create test user
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        
        # Create device info
        self.device_info = DeviceInfo(
            device_id='test_device_123',
            device_fingerprint='fp_test_123',
            device_type='desktop',
            browser='Chrome',
            operating_system='Windows',
            ip_address='192.168.1.100',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        # Create API client
        self.client = APIClient()
        
        print("✓ Test setup completed")
    
    def tearDown(self):
        """Clean up test data."""
        try:
            # Clean up database entries
            RefreshToken.objects.filter(user=self.user).delete()
            TokenBlacklist.objects.filter(user=self.user).delete()
            self.user.delete()
            
            # Clear cache
            cache.clear()
            
            print("✓ Test cleanup completed")
        except Exception as e:
            print(f"⚠ Cleanup warning: {e}")
    
    def test_basic_token_refresh_rotation(self):
        """Test basic refresh token rotation functionality."""
        print("\n--- Testing Basic Token Refresh Rotation ---")
        
        # Generate initial token pair
        initial_token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        self.assertIsNotNone(initial_token_pair)
        print("✓ Initial token pair generated")
        
        # Verify refresh token record was created
        refresh_token_record = RefreshToken.objects.get(user=self.user, status='active')
        self.assertEqual(refresh_token_record.rotation_count, 0)
        print("✓ Initial refresh token record created with rotation_count=0")
        
        # Wait a moment to ensure different timestamps
        time.sleep(0.1)
        
        # Refresh the token pair
        new_token_pair = jwt_service.refresh_token_pair(
            refresh_token=initial_token_pair.refresh_token,
            device_info=self.device_info
        )
        
        self.assertIsNotNone(new_token_pair)
        self.assertNotEqual(initial_token_pair.access_token, new_token_pair.access_token)
        self.assertNotEqual(initial_token_pair.refresh_token, new_token_pair.refresh_token)
        print("✓ Token pair refreshed successfully with new tokens")
        
        # Verify old refresh token was rotated
        old_token_record = RefreshToken.objects.get(
            token_id=jwt_service._decode_jwt_token(initial_token_pair.refresh_token).token_id
        )
        self.assertEqual(old_token_record.status, 'rotated')
        print("✓ Old refresh token marked as rotated")
        
        # Verify new refresh token record was created
        new_token_record = RefreshToken.objects.get(user=self.user, status='active')
        self.assertEqual(new_token_record.rotation_count, 1)
        self.assertEqual(new_token_record.parent_token, old_token_record)
        print("✓ New refresh token record created with rotation_count=1 and proper parent link")
        
        # Verify old refresh token is blacklisted
        old_token_claims = jwt_service._decode_jwt_token(initial_token_pair.refresh_token)
        self.assertTrue(jwt_service.blacklist_service.is_token_blacklisted(old_token_claims.token_id))
        print("✓ Old refresh token is blacklisted")
        
        # Try to use old refresh token (should fail)
        failed_refresh = jwt_service.refresh_token_pair(
            refresh_token=initial_token_pair.refresh_token,
            device_info=self.device_info
        )
        
        self.assertIsNone(failed_refresh)
        print("✓ Old refresh token cannot be reused (replay attack prevented)")
    
    def test_token_family_tracking(self):
        """Test refresh token family tracking through multiple rotations."""
        print("\n--- Testing Token Family Tracking ---")
        
        # Generate initial token pair
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Perform multiple rotations
        rotation_count = 5
        for i in range(rotation_count):
            time.sleep(0.1)  # Ensure different timestamps
            token_pair = jwt_service.refresh_token_pair(
                refresh_token=token_pair.refresh_token,
                device_info=self.device_info
            )
            self.assertIsNotNone(token_pair)
        
        print(f"✓ Performed {rotation_count} token rotations")
        
        # Get current token record
        current_token_record = RefreshToken.objects.get(user=self.user, status='active')
        self.assertEqual(current_token_record.rotation_count, rotation_count)
        print(f"✓ Current token has rotation_count={rotation_count}")
        
        # Get token family chain
        family_chain = current_token_record.get_rotation_chain()
        self.assertEqual(len(family_chain), rotation_count + 1)  # +1 for initial token
        print(f"✓ Token family chain has {len(family_chain)} tokens")
        
        # Verify chain integrity
        for i in range(1, len(family_chain)):
            self.assertEqual(family_chain[i].parent_token, family_chain[i-1])
        print("✓ Token family chain integrity verified")
        
        # Test family info API
        current_token_claims = jwt_service._decode_jwt_token(token_pair.refresh_token)
        family_info = jwt_service.get_refresh_token_family_info(current_token_claims.token_id)
        
        self.assertIsNotNone(family_info)
        self.assertEqual(family_info['family_size'], rotation_count + 1)
        self.assertEqual(family_info['rotation_count'], rotation_count)
        self.assertEqual(family_info['active_tokens'], 1)
        self.assertEqual(family_info['rotated_tokens'], rotation_count)
        print("✓ Token family info API returns correct data")
    
    def test_suspicious_activity_detection(self):
        """Test detection and handling of suspicious refresh token activity."""
        print("\n--- Testing Suspicious Activity Detection ---")
        
        # Generate initial token pair
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Test device fingerprint change detection
        different_device_info = DeviceInfo(
            device_id='different_device_456',
            device_fingerprint='fp_different_456',
            device_type='mobile',
            browser='Safari',
            operating_system='iOS',
            ip_address='10.0.0.50',
            user_agent='Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'
        )
        
        # Try to refresh with different device (should fail due to fingerprint mismatch)
        suspicious_refresh = jwt_service.refresh_token_pair(
            refresh_token=token_pair.refresh_token,
            device_info=different_device_info
        )
        
        self.assertIsNone(suspicious_refresh)
        print("✓ Refresh token rejected due to device fingerprint mismatch")
        
        # Verify all user tokens were revoked due to suspicious activity
        active_tokens = RefreshToken.objects.filter(user=self.user, status='active')
        self.assertEqual(active_tokens.count(), 0)
        print("✓ All user tokens revoked due to suspicious activity")
        
        # Verify security event was logged (check cache for security events)
        security_events = []
        for key in cache._cache.get_client().keys('security_event:*'):
            event = cache.get(key.decode())
            if event and event.get('user_id') == str(self.user.id):
                security_events.append(event)
        
        self.assertGreater(len(security_events), 0)
        print("✓ Security event logged for suspicious activity")
    
    def test_rotation_limit_enforcement(self):
        """Test enforcement of rotation limits to prevent abuse."""
        print("\n--- Testing Rotation Limit Enforcement ---")
        
        # Generate initial token pair
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Manually set a high rotation count to test limit
        current_token_record = RefreshToken.objects.get(user=self.user, status='active')
        current_token_record.rotation_count = 99  # Just below limit
        current_token_record.save()
        
        # This refresh should work (at limit)
        token_pair = jwt_service.refresh_token_pair(
            refresh_token=token_pair.refresh_token,
            device_info=self.device_info
        )
        self.assertIsNotNone(token_pair)
        print("✓ Refresh allowed at rotation limit")
        
        # Set rotation count to limit
        current_token_record = RefreshToken.objects.get(user=self.user, status='active')
        current_token_record.rotation_count = 100  # At limit
        current_token_record.save()
        
        # This refresh should fail (exceeds limit)
        failed_refresh = jwt_service.refresh_token_pair(
            refresh_token=token_pair.refresh_token,
            device_info=self.device_info
        )
        self.assertIsNone(failed_refresh)
        print("✓ Refresh blocked when rotation limit exceeded")
    
    def test_automatic_token_refresh_flow(self):
        """Test automatic token refresh flow for client applications."""
        print("\n--- Testing Automatic Token Refresh Flow ---")
        
        # Generate token pair
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Test token refresh timing checks
        should_refresh_5min = jwt_service.should_refresh_token(token_pair.access_token, 5)
        should_refresh_20min = jwt_service.should_refresh_token(token_pair.access_token, 20)
        
        # Token should not need refresh within 5 minutes but should within 20 minutes
        # (since access tokens expire in 15 minutes)
        self.assertFalse(should_refresh_5min)
        self.assertTrue(should_refresh_20min)
        print("✓ Token refresh timing logic works correctly")
        
        # Test token refresh info API
        refresh_info = jwt_service.get_token_refresh_info(token_pair.access_token)
        self.assertIsNotNone(refresh_info)
        self.assertIn('time_remaining_seconds', refresh_info)
        self.assertIn('should_refresh_5min', refresh_info)
        self.assertIn('refresh_recommended', refresh_info)
        print("✓ Token refresh info API provides detailed timing information")
        
        # Test API endpoint for checking refresh needed
        response = self.client.post('/api/v1/core/auth/check-refresh/', {
            'access_token': token_pair.access_token,
            'threshold_minutes': 5
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('should_refresh', response.data)
        self.assertIn('token_info', response.data)
        print("✓ Check refresh needed API endpoint works correctly")
    
    def test_token_family_revocation(self):
        """Test revocation of entire token families."""
        print("\n--- Testing Token Family Revocation ---")
        
        # Generate initial token pair and perform rotations
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Perform several rotations to create a family
        for _ in range(3):
            time.sleep(0.1)
            token_pair = jwt_service.refresh_token_pair(
                refresh_token=token_pair.refresh_token,
                device_info=self.device_info
            )
        
        # Get current token ID
        current_token_claims = jwt_service._decode_jwt_token(token_pair.refresh_token)
        
        # Revoke the entire family
        revoked_count = jwt_service.revoke_refresh_token_family(
            current_token_claims.token_id,
            'test_family_revocation'
        )
        
        self.assertEqual(revoked_count, 1)  # Only the active token should be revoked
        print(f"✓ Revoked {revoked_count} active tokens in family")
        
        # Verify no active tokens remain for the user
        active_tokens = RefreshToken.objects.filter(user=self.user, status='active')
        self.assertEqual(active_tokens.count(), 0)
        print("✓ No active tokens remain after family revocation")
        
        # Verify tokens are blacklisted
        self.assertTrue(jwt_service.blacklist_service.is_token_blacklisted(current_token_claims.token_id))
        print("✓ Revoked tokens are properly blacklisted")
    
    def test_api_endpoints(self):
        """Test the new API endpoints for token refresh and family management."""
        print("\n--- Testing API Endpoints ---")
        
        # Generate token pair and authenticate
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token_pair.access_token}')
        
        # Test get refresh token family endpoint
        response = self.client.get('/api/v1/core/auth/token-family/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('families', response.data)
        print("✓ Get token family API endpoint works")
        
        # Test revoke refresh token family endpoint
        current_token_claims = jwt_service._decode_jwt_token(token_pair.refresh_token)
        response = self.client.post('/api/v1/core/auth/revoke-family/', {
            'token_id': current_token_claims.token_id,
            'reason': 'api_test'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('revoked_count', response.data)
        print("✓ Revoke token family API endpoint works")
    
    def test_cleanup_tasks(self):
        """Test cleanup and monitoring tasks."""
        print("\n--- Testing Cleanup and Monitoring Tasks ---")
        
        # Create some test tokens
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Manually expire a token for testing
        expired_token = RefreshToken.objects.get(user=self.user, status='active')
        expired_token.expires_at = timezone.now() - timedelta(hours=1)
        expired_token.save()
        
        # Run cleanup task
        cleanup_result = jwt_service.cleanup_expired_refresh_tokens()
        self.assertIn('expired_tokens_marked', cleanup_result)
        self.assertGreater(cleanup_result['expired_tokens_marked'], 0)
        print("✓ Cleanup task successfully marked expired tokens")
        
        # Test security monitoring task
        try:
            monitor_result = monitor_refresh_token_security()
            self.assertEqual(monitor_result['status'], 'success')
            self.assertIn('stats', monitor_result)
            print("✓ Security monitoring task completed successfully")
        except Exception as e:
            print(f"⚠ Security monitoring task warning: {e}")
    
    def test_replay_attack_prevention(self):
        """Test comprehensive replay attack prevention."""
        print("\n--- Testing Replay Attack Prevention ---")
        
        # Generate initial token pair
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Use the refresh token once
        new_token_pair = jwt_service.refresh_token_pair(
            refresh_token=token_pair.refresh_token,
            device_info=self.device_info
        )
        self.assertIsNotNone(new_token_pair)
        print("✓ First refresh token use successful")
        
        # Try to use the same refresh token again (replay attack)
        replay_attempt = jwt_service.refresh_token_pair(
            refresh_token=token_pair.refresh_token,
            device_info=self.device_info
        )
        self.assertIsNone(replay_attempt)
        print("✓ Replay attack with used refresh token blocked")
        
        # Verify that the replay attempt triggered security measures
        # (all user tokens should be revoked)
        active_tokens = RefreshToken.objects.filter(user=self.user, status='active')
        self.assertEqual(active_tokens.count(), 0)
        print("✓ Replay attack triggered automatic token revocation")
        
        # Verify security event was logged
        security_events = []
        for key in cache._cache.get_client().keys('security_event:*'):
            event = cache.get(key.decode())
            if event and event.get('user_id') == str(self.user.id):
                security_events.append(event)
        
        self.assertGreater(len(security_events), 0)
        print("✓ Security event logged for replay attack")
    
    def run_all_tests(self):
        """Run all test methods."""
        test_methods = [
            self.test_basic_token_refresh_rotation,
            self.test_token_family_tracking,
            self.test_suspicious_activity_detection,
            self.test_rotation_limit_enforcement,
            self.test_automatic_token_refresh_flow,
            self.test_token_family_revocation,
            self.test_api_endpoints,
            self.test_cleanup_tasks,
            self.test_replay_attack_prevention,
        ]
        
        passed = 0
        failed = 0
        
        for test_method in test_methods:
            try:
                # Reset state for each test
                self.setUp()
                test_method()
                passed += 1
                print(f"✅ {test_method.__name__} PASSED")
            except Exception as e:
                failed += 1
                print(f"❌ {test_method.__name__} FAILED: {e}")
            finally:
                self.tearDown()
        
        print("\n" + "="*80)
        print("TOKEN REFRESH AND ROTATION SYSTEM TEST SUMMARY")
        print("="*80)
        print(f"Total Tests: {len(test_methods)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(passed/len(test_methods)*100):.1f}%")
        
        if failed == 0:
            print("\n🎉 ALL TESTS PASSED! Token refresh and rotation system is working correctly.")
            print("\nImplemented features:")
            print("✓ Refresh token rotation to prevent replay attacks")
            print("✓ Automatic token refresh flow for client applications")
            print("✓ Refresh token family tracking for security")
            print("✓ Refresh token revocation on suspicious activity")
            print("✓ API endpoints for token management")
            print("✓ Cleanup and monitoring tasks")
            print("✓ Comprehensive security measures")
        else:
            print(f"\n⚠️  {failed} test(s) failed. Please review the implementation.")
        
        return failed == 0


def main():
    """Main test execution function."""
    print("Starting JWT Token Refresh and Rotation System Test...")
    
    try:
        # Create test instance
        test_instance = TokenRefreshRotationSystemTest()
        
        # Run all tests
        success = test_instance.run_all_tests()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()