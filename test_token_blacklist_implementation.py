#!/usr/bin/env python
"""
Test script for JWT token blacklist and revocation implementation.

This script tests the token blacklist functionality including:
- Token revocation
- Bulk token revocation
- Device token revocation
- User token revocation
- Automatic cleanup
"""

import os
import sys
import django
from datetime import datetime, timedelta

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.development')
django.setup()

from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.db import transaction

from enterprise_auth.core.services.jwt_service import jwt_service, DeviceInfo
from enterprise_auth.core.models.jwt import TokenBlacklist, RefreshToken
from enterprise_auth.core.models.user import UserProfile

User = get_user_model()


class TokenBlacklistTest:
    """Test class for token blacklist functionality."""
    
    def __init__(self):
        self.user = None
        self.device_info = None
        self.token_pair = None
        
    def setup(self):
        """Set up test data."""
        print("Setting up test data...")
        
        # Create test user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Create device info
        self.device_info = DeviceInfo(
            device_id='test-device-123',
            device_fingerprint='test-fingerprint-456',
            device_type='desktop',
            browser='Chrome',
            operating_system='Windows',
            ip_address='192.168.1.100',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        # Generate token pair
        self.token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        print(f"✓ Created test user: {self.user.email}")
        print(f"✓ Generated token pair")
        
    def test_single_token_revocation(self):
        """Test revoking a single token."""
        print("\n--- Testing Single Token Revocation ---")
        
        # Verify token is initially valid
        validation_result = jwt_service.validate_access_token(
            self.token_pair.access_token,
            self.device_info.device_fingerprint
        )
        assert validation_result.is_valid, "Token should be valid initially"
        print("✓ Token is initially valid")
        
        # Revoke the token
        success = jwt_service.revoke_token(
            self.token_pair.access_token,
            reason='test_revocation'
        )
        assert success, "Token revocation should succeed"
        print("✓ Token revoked successfully")
        
        # Verify token is now invalid
        validation_result = jwt_service.validate_access_token(
            self.token_pair.access_token,
            self.device_info.device_fingerprint
        )
        assert not validation_result.is_valid, "Token should be invalid after revocation"
        assert validation_result.status.value == 'blacklisted', "Token should be blacklisted"
        print("✓ Token is now blacklisted")
        
    def test_user_token_revocation(self):
        """Test revoking all tokens for a user."""
        print("\n--- Testing User Token Revocation ---")
        
        # Generate another token pair for the same user
        token_pair_2 = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        # Verify both tokens are valid
        validation_1 = jwt_service.validate_access_token(
            self.token_pair.access_token,
            self.device_info.device_fingerprint
        )
        validation_2 = jwt_service.validate_access_token(
            token_pair_2.access_token,
            self.device_info.device_fingerprint
        )
        
        print(f"✓ Token 1 valid: {validation_1.is_valid}")
        print(f"✓ Token 2 valid: {validation_2.is_valid}")
        
        # Revoke all user tokens
        success = jwt_service.revoke_all_user_tokens(
            str(self.user.id),
            reason='test_user_revocation'
        )
        assert success, "User token revocation should succeed"
        print("✓ All user tokens revoked")
        
        # Verify both tokens are now invalid
        validation_1 = jwt_service.validate_access_token(
            self.token_pair.access_token,
            self.device_info.device_fingerprint
        )
        validation_2 = jwt_service.validate_access_token(
            token_pair_2.access_token,
            self.device_info.device_fingerprint
        )
        
        assert not validation_1.is_valid, "Token 1 should be invalid"
        assert not validation_2.is_valid, "Token 2 should be invalid"
        print("✓ Both tokens are now invalid")
        
    def test_device_token_revocation(self):
        """Test revoking all tokens for a device."""
        print("\n--- Testing Device Token Revocation ---")
        
        # Create a new device and generate tokens
        device_info_2 = DeviceInfo(
            device_id='test-device-789',
            device_fingerprint='test-fingerprint-789',
            device_type='mobile',
            browser='Safari',
            operating_system='iOS',
            ip_address='192.168.1.101',
            user_agent='Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'
        )
        
        token_pair_device_1 = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        token_pair_device_2 = jwt_service.generate_token_pair(
            user=self.user,
            device_info=device_info_2,
            scopes=['read', 'write']
        )
        
        print("✓ Generated tokens for two different devices")
        
        # Revoke tokens for device 1 only
        success = jwt_service.revoke_device_tokens(
            self.device_info.device_id,
            reason='test_device_revocation'
        )
        assert success, "Device token revocation should succeed"
        print(f"✓ Revoked tokens for device: {self.device_info.device_id}")
        
        # Verify device 1 tokens are invalid, device 2 tokens are still valid
        validation_device_1 = jwt_service.validate_access_token(
            token_pair_device_1.access_token,
            self.device_info.device_fingerprint
        )
        validation_device_2 = jwt_service.validate_access_token(
            token_pair_device_2.access_token,
            device_info_2.device_fingerprint
        )
        
        assert not validation_device_1.is_valid, "Device 1 token should be invalid"
        assert validation_device_2.is_valid, "Device 2 token should still be valid"
        print("✓ Device 1 tokens revoked, Device 2 tokens still valid")
        
    def test_bulk_token_revocation(self):
        """Test bulk token revocation."""
        print("\n--- Testing Bulk Token Revocation ---")
        
        # Generate multiple token pairs
        token_pairs = []
        for i in range(3):
            device_info = DeviceInfo(
                device_id=f'bulk-device-{i}',
                device_fingerprint=f'bulk-fingerprint-{i}',
                device_type='desktop',
                browser='Chrome',
                operating_system='Windows',
                ip_address=f'192.168.1.{200 + i}',
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            )
            
            token_pair = jwt_service.generate_token_pair(
                user=self.user,
                device_info=device_info,
                scopes=['read', 'write']
            )
            token_pairs.append(token_pair)
        
        print(f"✓ Generated {len(token_pairs)} token pairs for bulk test")
        
        # Extract token IDs (we need to decode tokens to get IDs)
        token_ids = []
        for token_pair in token_pairs:
            validation_result = jwt_service.validate_access_token(token_pair.access_token)
            if validation_result.is_valid:
                token_ids.append(validation_result.claims.token_id)
        
        print(f"✓ Extracted {len(token_ids)} token IDs")
        
        # Bulk revoke tokens
        revoked_count = jwt_service.bulk_revoke_tokens(
            token_ids,
            reason='test_bulk_revocation'
        )
        
        assert revoked_count == len(token_ids), f"Should revoke {len(token_ids)} tokens, got {revoked_count}"
        print(f"✓ Bulk revoked {revoked_count} tokens")
        
        # Verify all tokens are now invalid
        for i, token_pair in enumerate(token_pairs):
            validation_result = jwt_service.validate_access_token(token_pair.access_token)
            assert not validation_result.is_valid, f"Token {i} should be invalid after bulk revocation"
        
        print("✓ All bulk revoked tokens are now invalid")
        
    def test_token_cleanup(self):
        """Test automatic token cleanup."""
        print("\n--- Testing Token Cleanup ---")
        
        # Create some blacklist entries
        TokenBlacklist.objects.create(
            token_id='expired-token-1',
            token_type='access',
            user=self.user,
            issued_at=timezone.now() - timedelta(days=2),
            expires_at=timezone.now() - timedelta(days=1),  # Already expired
            reason='test_cleanup'
        )
        
        TokenBlacklist.objects.create(
            token_id='active-token-1',
            token_type='access',
            user=self.user,
            issued_at=timezone.now(),
            expires_at=timezone.now() + timedelta(days=1),  # Still active
            reason='test_cleanup'
        )
        
        print("✓ Created test blacklist entries")
        
        # Run cleanup
        cleaned_count = TokenBlacklist.cleanup_expired_entries()
        print(f"✓ Cleaned up {cleaned_count} expired entries")
        
        # Verify expired entry was removed, active entry remains
        remaining_entries = TokenBlacklist.objects.filter(
            token_id__in=['expired-token-1', 'active-token-1']
        )
        
        assert remaining_entries.count() == 1, "Should have 1 remaining entry"
        assert remaining_entries.first().token_id == 'active-token-1', "Active token should remain"
        print("✓ Cleanup worked correctly")
        
    def test_refresh_token_rotation(self):
        """Test refresh token rotation and blacklisting."""
        print("\n--- Testing Refresh Token Rotation ---")
        
        # Generate initial token pair
        initial_token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        print("✓ Generated initial token pair")
        
        # Use refresh token to get new token pair
        new_token_pair = jwt_service.refresh_token_pair(
            initial_token_pair.refresh_token,
            self.device_info
        )
        
        assert new_token_pair is not None, "Token refresh should succeed"
        print("✓ Successfully refreshed token pair")
        
        # Verify old refresh token is blacklisted
        old_validation = jwt_service._validate_refresh_token(
            initial_token_pair.refresh_token,
            self.device_info.device_fingerprint
        )
        
        assert not old_validation.is_valid, "Old refresh token should be invalid"
        assert old_validation.status.value == 'blacklisted', "Old refresh token should be blacklisted"
        print("✓ Old refresh token is blacklisted after rotation")
        
        # Verify new tokens are valid
        new_access_validation = jwt_service.validate_access_token(
            new_token_pair.access_token,
            self.device_info.device_fingerprint
        )
        new_refresh_validation = jwt_service._validate_refresh_token(
            new_token_pair.refresh_token,
            self.device_info.device_fingerprint
        )
        
        assert new_access_validation.is_valid, "New access token should be valid"
        assert new_refresh_validation.is_valid, "New refresh token should be valid"
        print("✓ New tokens are valid")
        
    def run_all_tests(self):
        """Run all tests."""
        print("=" * 60)
        print("JWT TOKEN BLACKLIST AND REVOCATION TESTS")
        print("=" * 60)
        
        try:
            self.setup()
            self.test_single_token_revocation()
            self.test_user_token_revocation()
            self.test_device_token_revocation()
            self.test_bulk_token_revocation()
            self.test_token_cleanup()
            self.test_refresh_token_rotation()
            
            print("\n" + "=" * 60)
            print("✅ ALL TESTS PASSED!")
            print("Token blacklist and revocation implementation is working correctly.")
            print("=" * 60)
            
        except Exception as e:
            print(f"\n❌ TEST FAILED: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
            
        return True
    
    def cleanup(self):
        """Clean up test data."""
        print("\nCleaning up test data...")
        try:
            # Clean up database entries
            TokenBlacklist.objects.filter(user=self.user).delete()
            RefreshToken.objects.filter(user=self.user).delete()
            self.user.delete()
            print("✓ Test data cleaned up")
        except Exception as e:
            print(f"⚠️  Cleanup warning: {str(e)}")


def main():
    """Main test function."""
    test = TokenBlacklistTest()
    try:
        success = test.run_all_tests()
        return 0 if success else 1
    finally:
        test.cleanup()


if __name__ == '__main__':
    sys.exit(main())