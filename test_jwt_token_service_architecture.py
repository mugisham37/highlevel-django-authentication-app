#!/usr/bin/env python
"""
Comprehensive test suite for JWT Token Service Architecture (Task 9).

This test validates all components of the JWT token service architecture:
- JWTService class with RS256 signing algorithm
- Access token generation with 15-minute expiration
- Refresh token generation with 30-day expiration and rotation
- Device fingerprinting for token binding
- Token validation and introspection
- Distributed token blacklist management
"""

import os
import sys
import django
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.testing')
django.setup()

from django.test import TestCase, RequestFactory
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.cache import caches

from enterprise_auth.core.services.jwt_service import (
    JWTService, 
    TokenType, 
    TokenStatus, 
    DeviceInfo,
    TokenClaims,
    TokenPair,
    TokenValidationResult,
    JWTKeyManager,
    TokenBlacklistService
)
from enterprise_auth.core.models.user import UserProfile
from enterprise_auth.core.models.jwt import RefreshToken, TokenBlacklist, JWTKeyRotation


class JWTTokenServiceArchitectureTest(TestCase):
    """Test suite for JWT Token Service Architecture."""
    
    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.jwt_service = JWTService()
        self.key_manager = JWTKeyManager()
        self.blacklist_service = TokenBlacklistService()
        
        # Create test user
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        
        # Create mock request for device info
        self.request = self.factory.get('/')
        self.request.META.update({
            'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9',
            'HTTP_ACCEPT_ENCODING': 'gzip, deflate, br',
            'REMOTE_ADDR': '192.168.1.100'
        })
        
        self.device_info = DeviceInfo.from_request(self.request)
        
        # Clear cache before each test
        cache = caches['default']
        cache.clear()
    
    def test_jwt_service_initialization(self):
        """Test JWT service initialization and configuration."""
        print("Testing JWT service initialization...")
        
        # Test service initialization
        self.assertIsInstance(self.jwt_service, JWTService)
        self.assertIsInstance(self.jwt_service.key_manager, JWTKeyManager)
        self.assertIsInstance(self.jwt_service.blacklist_service, TokenBlacklistService)
        
        # Test configuration
        self.assertEqual(self.jwt_service.access_token_lifetime, timedelta(seconds=900))  # 15 minutes
        self.assertEqual(self.jwt_service.refresh_token_lifetime, timedelta(seconds=2592000))  # 30 days
        self.assertEqual(self.jwt_service.issuer, 'enterprise-auth')
        self.assertEqual(self.jwt_service.audience, 'enterprise-auth-clients')
        
        print("✓ JWT service initialization test passed")
    
    def test_rs256_key_management(self):
        """Test RS256 key generation and management."""
        print("Testing RS256 key management...")
        
        # Test key generation
        key_id = self.key_manager.get_current_key_id()
        self.assertIsNotNone(key_id)
        self.assertTrue(len(key_id) > 0)
        
        # Test private key retrieval
        private_key = self.key_manager.get_private_key()
        self.assertIsNotNone(private_key)
        
        # Test public key retrieval
        public_key = self.key_manager.get_public_key()
        self.assertIsNotNone(public_key)
        
        # Test key metadata
        metadata = self.key_manager.get_key_metadata(key_id)
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata['algorithm'], 'RS256')
        self.assertEqual(metadata['key_size'], 2048)
        
        print("✓ RS256 key management test passed")
    
    def test_device_fingerprinting(self):
        """Test device fingerprinting for token binding."""
        print("Testing device fingerprinting...")
        
        # Test device info extraction
        self.assertIsNotNone(self.device_info.device_id)
        self.assertIsNotNone(self.device_info.device_fingerprint)
        self.assertEqual(self.device_info.device_type, 'desktop')
        self.assertEqual(self.device_info.browser, 'chrome')
        self.assertEqual(self.device_info.operating_system, 'windows')
        self.assertEqual(self.device_info.ip_address, '192.168.1.100')
        
        # Test fingerprint consistency
        device_info2 = DeviceInfo.from_request(self.request)
        self.assertEqual(self.device_info.device_fingerprint, device_info2.device_fingerprint)
        
        # Test fingerprint uniqueness with different request
        request2 = self.factory.get('/')
        request2.META.update({
            'HTTP_USER_AGENT': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'REMOTE_ADDR': '192.168.1.101'
        })
        device_info3 = DeviceInfo.from_request(request2)
        self.assertNotEqual(self.device_info.device_fingerprint, device_info3.device_fingerprint)
        
        print("✓ Device fingerprinting test passed")
    
    def test_access_token_generation(self):
        """Test access token generation with 15-minute expiration."""
        print("Testing access token generation...")
        
        # Generate token pair
        token_pair = self.jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write'],
            session_id='test-session-123'
        )
        
        # Test token pair structure
        self.assertIsInstance(token_pair, TokenPair)
        self.assertIsNotNone(token_pair.access_token)
        self.assertIsNotNone(token_pair.refresh_token)
        self.assertEqual(token_pair.token_type, 'Bearer')
        
        # Test access token expiration (15 minutes)
        now = timezone.now()
        expected_expiry = now + timedelta(minutes=15)
        time_diff = abs((token_pair.access_token_expires_at - expected_expiry).total_seconds())
        self.assertLess(time_diff, 5)  # Allow 5 seconds tolerance
        
        # Validate access token
        validation_result = self.jwt_service.validate_access_token(
            token_pair.access_token,
            self.device_info.device_fingerprint
        )
        
        self.assertTrue(validation_result.is_valid)
        self.assertEqual(validation_result.status, TokenStatus.VALID)
        self.assertIsNotNone(validation_result.claims)
        
        # Test token claims
        claims = validation_result.claims
        self.assertEqual(claims.user_id, str(self.user.id))
        self.assertEqual(claims.email, self.user.email)
        self.assertEqual(claims.token_type, TokenType.ACCESS.value)
        self.assertEqual(claims.device_fingerprint, self.device_info.device_fingerprint)
        self.assertEqual(claims.scopes, ['read', 'write'])
        self.assertEqual(claims.session_id, 'test-session-123')
        
        print("✓ Access token generation test passed")
    
    def test_refresh_token_generation(self):
        """Test refresh token generation with 30-day expiration."""
        print("Testing refresh token generation...")
        
        # Generate token pair
        token_pair = self.jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Test refresh token expiration (30 days)
        now = timezone.now()
        expected_expiry = now + timedelta(days=30)
        time_diff = abs((token_pair.refresh_token_expires_at - expected_expiry).total_seconds())
        self.assertLess(time_diff, 5)  # Allow 5 seconds tolerance
        
        # Validate refresh token structure
        validation_result = self.jwt_service._validate_refresh_token(
            token_pair.refresh_token,
            self.device_info.device_fingerprint
        )
        
        self.assertTrue(validation_result.is_valid)
        self.assertEqual(validation_result.claims.token_type, TokenType.REFRESH.value)
        
        print("✓ Refresh token generation test passed")
    
    def test_token_rotation(self):
        """Test refresh token rotation to prevent replay attacks."""
        print("Testing token rotation...")
        
        # Generate initial token pair
        initial_token_pair = self.jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Use refresh token to get new token pair
        new_token_pair = self.jwt_service.refresh_token_pair(
            initial_token_pair.refresh_token,
            self.device_info
        )
        
        self.assertIsNotNone(new_token_pair)
        self.assertNotEqual(initial_token_pair.access_token, new_token_pair.access_token)
        self.assertNotEqual(initial_token_pair.refresh_token, new_token_pair.refresh_token)
        
        # Test that old refresh token is blacklisted
        old_validation = self.jwt_service._validate_refresh_token(
            initial_token_pair.refresh_token,
            self.device_info.device_fingerprint
        )
        self.assertEqual(old_validation.status, TokenStatus.BLACKLISTED)
        
        # Test that new refresh token works
        newer_token_pair = self.jwt_service.refresh_token_pair(
            new_token_pair.refresh_token,
            self.device_info
        )
        self.assertIsNotNone(newer_token_pair)
        
        print("✓ Token rotation test passed")
    
    def test_token_validation_and_introspection(self):
        """Test token validation and introspection capabilities."""
        print("Testing token validation and introspection...")
        
        # Generate token pair
        token_pair = self.jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write', 'admin']
        )
        
        # Test token introspection
        introspection_data = self.jwt_service.introspect_token(token_pair.access_token)
        
        self.assertTrue(introspection_data['active'])
        self.assertEqual(introspection_data['token_type'], 'Bearer')
        self.assertEqual(introspection_data['user_id'], str(self.user.id))
        self.assertEqual(introspection_data['email'], self.user.email)
        self.assertEqual(introspection_data['scopes'], ['read', 'write', 'admin'])
        self.assertIn('issued_at', introspection_data)
        self.assertIn('expires_at', introspection_data)
        
        # Test validation with device binding
        validation_result = self.jwt_service.validate_access_token(
            token_pair.access_token,
            self.device_info.device_fingerprint
        )
        self.assertTrue(validation_result.is_valid)
        
        # Test validation with wrong device fingerprint
        wrong_validation = self.jwt_service.validate_access_token(
            token_pair.access_token,
            'wrong-fingerprint'
        )
        self.assertFalse(wrong_validation.is_valid)
        self.assertEqual(wrong_validation.status, TokenStatus.INVALID)
        
        print("✓ Token validation and introspection test passed")
    
    def test_distributed_token_blacklist(self):
        """Test distributed token blacklist management."""
        print("Testing distributed token blacklist...")
        
        # Generate token pair
        token_pair = self.jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Validate token is initially valid
        validation_result = self.jwt_service.validate_access_token(token_pair.access_token)
        self.assertTrue(validation_result.is_valid)
        
        # Revoke token
        revoke_success = self.jwt_service.revoke_token(token_pair.access_token, 'test_revocation')
        self.assertTrue(revoke_success)
        
        # Test that revoked token is now invalid
        validation_result = self.jwt_service.validate_access_token(token_pair.access_token)
        self.assertFalse(validation_result.is_valid)
        self.assertEqual(validation_result.status, TokenStatus.BLACKLISTED)
        
        # Test introspection of revoked token
        introspection_data = self.jwt_service.introspect_token(token_pair.access_token)
        self.assertFalse(introspection_data['active'])
        self.assertIn('error', introspection_data)
        
        print("✓ Distributed token blacklist test passed")
    
    def test_bulk_token_revocation(self):
        """Test bulk token revocation for security incidents."""
        print("Testing bulk token revocation...")
        
        # Generate multiple token pairs
        token_pairs = []
        for i in range(3):
            token_pair = self.jwt_service.generate_token_pair(
                user=self.user,
                device_info=self.device_info
            )
            token_pairs.append(token_pair)
        
        # Validate all tokens are initially valid
        for token_pair in token_pairs:
            validation_result = self.jwt_service.validate_access_token(token_pair.access_token)
            self.assertTrue(validation_result.is_valid)
        
        # Revoke all user tokens
        revoke_success = self.jwt_service.revoke_all_user_tokens(
            str(self.user.id), 
            'security_incident'
        )
        self.assertTrue(revoke_success)
        
        # Test that all tokens are now invalid
        for token_pair in token_pairs:
            validation_result = self.jwt_service.validate_access_token(token_pair.access_token)
            self.assertFalse(validation_result.is_valid)
            self.assertEqual(validation_result.status, TokenStatus.REVOKED)
        
        print("✓ Bulk token revocation test passed")
    
    def test_key_rotation_support(self):
        """Test JWT key rotation support."""
        print("Testing key rotation support...")
        
        # Get initial key
        initial_key_id = self.key_manager.get_current_key_id()
        
        # Generate token with initial key
        token_pair = self.jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Validate token with initial key
        validation_result = self.jwt_service.validate_access_token(token_pair.access_token)
        self.assertTrue(validation_result.is_valid)
        
        # Rotate keys
        new_key_id = self.key_manager.rotate_keys()
        self.assertNotEqual(initial_key_id, new_key_id)
        
        # Old token should still be valid (old key still available for verification)
        validation_result = self.jwt_service.validate_access_token(token_pair.access_token)
        self.assertTrue(validation_result.is_valid)
        
        # New tokens should use new key
        new_token_pair = self.jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Both tokens should be valid
        old_validation = self.jwt_service.validate_access_token(token_pair.access_token)
        new_validation = self.jwt_service.validate_access_token(new_token_pair.access_token)
        
        self.assertTrue(old_validation.is_valid)
        self.assertTrue(new_validation.is_valid)
        
        print("✓ Key rotation support test passed")
    
    def test_token_expiration_handling(self):
        """Test proper handling of expired tokens."""
        print("Testing token expiration handling...")
        
        # Mock timezone.now to simulate token expiration
        with patch('django.utils.timezone.now') as mock_now:
            # Generate token
            initial_time = timezone.now()
            mock_now.return_value = initial_time
            
            token_pair = self.jwt_service.generate_token_pair(
                user=self.user,
                device_info=self.device_info
            )
            
            # Validate token is initially valid
            validation_result = self.jwt_service.validate_access_token(token_pair.access_token)
            self.assertTrue(validation_result.is_valid)
            
            # Simulate time passing (16 minutes - beyond access token expiry)
            expired_time = initial_time + timedelta(minutes=16)
            mock_now.return_value = expired_time
            
            # Test that access token is now expired
            validation_result = self.jwt_service.validate_access_token(token_pair.access_token)
            self.assertFalse(validation_result.is_valid)
            self.assertEqual(validation_result.status, TokenStatus.EXPIRED)
            
            # Test that refresh token is still valid (30-day expiry)
            refresh_validation = self.jwt_service._validate_refresh_token(token_pair.refresh_token)
            self.assertTrue(refresh_validation.is_valid)
            
            # Test token refresh with expired access token
            new_token_pair = self.jwt_service.refresh_token_pair(
                token_pair.refresh_token,
                self.device_info
            )
            self.assertIsNotNone(new_token_pair)
            
            # New access token should be valid
            new_validation = self.jwt_service.validate_access_token(new_token_pair.access_token)
            self.assertTrue(new_validation.is_valid)
        
        print("✓ Token expiration handling test passed")
    
    def test_comprehensive_integration(self):
        """Test comprehensive integration of all JWT service components."""
        print("Testing comprehensive integration...")
        
        # Test complete authentication flow
        # 1. Generate initial token pair
        token_pair = self.jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write'],
            session_id='integration-test-session'
        )
        
        # 2. Validate access token
        validation_result = self.jwt_service.validate_access_token(
            token_pair.access_token,
            self.device_info.device_fingerprint
        )
        self.assertTrue(validation_result.is_valid)
        
        # 3. Introspect token
        introspection_data = self.jwt_service.introspect_token(token_pair.access_token)
        self.assertTrue(introspection_data['active'])
        self.assertEqual(introspection_data['session_id'], 'integration-test-session')
        
        # 4. Refresh token pair
        new_token_pair = self.jwt_service.refresh_token_pair(
            token_pair.refresh_token,
            self.device_info
        )
        self.assertIsNotNone(new_token_pair)
        
        # 5. Validate new access token
        new_validation = self.jwt_service.validate_access_token(new_token_pair.access_token)
        self.assertTrue(new_validation.is_valid)
        
        # 6. Revoke new token
        revoke_success = self.jwt_service.revoke_token(new_token_pair.access_token)
        self.assertTrue(revoke_success)
        
        # 7. Validate revoked token is blacklisted
        revoked_validation = self.jwt_service.validate_access_token(new_token_pair.access_token)
        self.assertEqual(revoked_validation.status, TokenStatus.BLACKLISTED)
        
        print("✓ Comprehensive integration test passed")
    
    def run_all_tests(self):
        """Run all JWT token service architecture tests."""
        print("=" * 60)
        print("JWT TOKEN SERVICE ARCHITECTURE TEST SUITE")
        print("=" * 60)
        
        test_methods = [
            self.test_jwt_service_initialization,
            self.test_rs256_key_management,
            self.test_device_fingerprinting,
            self.test_access_token_generation,
            self.test_refresh_token_generation,
            self.test_token_rotation,
            self.test_token_validation_and_introspection,
            self.test_distributed_token_blacklist,
            self.test_bulk_token_revocation,
            self.test_key_rotation_support,
            self.test_token_expiration_handling,
            self.test_comprehensive_integration,
        ]
        
        passed_tests = 0
        total_tests = len(test_methods)
        
        for test_method in test_methods:
            try:
                test_method()
                passed_tests += 1
            except Exception as e:
                print(f"✗ {test_method.__name__} FAILED: {str(e)}")
        
        print("=" * 60)
        print(f"TEST RESULTS: {passed_tests}/{total_tests} tests passed")
        
        if passed_tests == total_tests:
            print("🎉 ALL TESTS PASSED! JWT Token Service Architecture is working correctly.")
            return True
        else:
            print("❌ Some tests failed. Please check the implementation.")
            return False


def main():
    """Main function to run the test suite."""
    test_suite = JWTTokenServiceArchitectureTest()
    test_suite.setUp()
    success = test_suite.run_all_tests()
    
    if success:
        print("\n✅ Task 9: JWT Token Service Architecture - COMPLETED")
        print("\nImplemented components:")
        print("- JWTService class with RS256 signing algorithm")
        print("- Access token generation with 15-minute expiration")
        print("- Refresh token generation with 30-day expiration and rotation")
        print("- Device fingerprinting for token binding")
        print("- Token validation and introspection")
        print("- Distributed token blacklist management")
        print("- Key rotation support")
        print("- Comprehensive error handling")
        return 0
    else:
        print("\n❌ Task 9: JWT Token Service Architecture - FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())