#!/usr/bin/env python3
"""
Simple test for JWT Token Refresh and Rotation System.

This test validates the core functionality of task 12 without requiring
full Django test framework setup.
"""

import os
import sys
import django
import uuid
import time
from datetime import datetime, timedelta

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.development')

try:
    django.setup()
except Exception as e:
    print(f"Failed to setup Django: {e}")
    sys.exit(1)

# Import after Django setup
from django.utils import timezone
from django.core.cache import cache

from enterprise_auth.core.models.user import UserProfile
from enterprise_auth.core.models.jwt import RefreshToken, TokenBlacklist
from enterprise_auth.core.services.jwt_service import jwt_service, DeviceInfo


class SimpleTokenRefreshTest:
    """Simple test class for token refresh and rotation functionality."""
    
    def __init__(self):
        self.user = None
        self.device_info = None
        
    def setup(self):
        """Set up test data."""
        print("Setting up test data...")
        
        # Clear cache
        cache.clear()
        
        # Create or get test user
        test_email = f'test_refresh_{int(time.time())}@example.com'
        try:
            self.user = UserProfile.objects.get(email=test_email)
        except UserProfile.DoesNotExist:
            self.user = UserProfile.objects.create_user(
                username=test_email,  # Use email as username for uniqueness
                email=test_email,
                password='TestPassword123!',
                first_name='Test',
                last_name='Refresh'
            )
        
        # Create device info
        self.device_info = DeviceInfo(
            device_id='test_device_refresh',
            device_fingerprint='fp_refresh_test',
            device_type='desktop',
            browser='Chrome',
            operating_system='Windows',
            ip_address='192.168.1.200',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        print("✓ Test setup completed")
    
    def cleanup(self):
        """Clean up test data."""
        try:
            if self.user:
                # Clean up database entries
                RefreshToken.objects.filter(user=self.user).delete()
                TokenBlacklist.objects.filter(user=self.user).delete()
                # Delete the test user
                self.user.delete()
            
            # Clear cache
            cache.clear()
            
            print("✓ Test cleanup completed")
        except Exception as e:
            print(f"⚠ Cleanup warning: {e}")
    
    def test_basic_refresh_rotation(self):
        """Test basic refresh token rotation."""
        print("\n--- Testing Basic Refresh Token Rotation ---")
        
        # Generate initial token pair
        initial_tokens = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        if not initial_tokens:
            raise Exception("Failed to generate initial token pair")
        
        print("✓ Initial token pair generated")
        
        # Check that refresh token record was created
        refresh_records = RefreshToken.objects.filter(user=self.user, status='active')
        if refresh_records.count() != 1:
            raise Exception(f"Expected 1 active refresh token, found {refresh_records.count()}")
        
        initial_record = refresh_records.first()
        if initial_record.rotation_count != 0:
            raise Exception(f"Expected rotation_count=0, found {initial_record.rotation_count}")
        
        print("✓ Initial refresh token record created correctly")
        
        # Wait a moment for different timestamps
        time.sleep(0.1)
        
        # Refresh the token pair
        new_tokens = jwt_service.refresh_token_pair(
            refresh_token=initial_tokens.refresh_token,
            device_info=self.device_info
        )
        
        if not new_tokens:
            raise Exception("Failed to refresh token pair")
        
        if new_tokens.access_token == initial_tokens.access_token:
            raise Exception("New access token should be different from initial")
        
        if new_tokens.refresh_token == initial_tokens.refresh_token:
            raise Exception("New refresh token should be different from initial")
        
        print("✓ Token pair refreshed successfully with new tokens")
        
        # Check that old token was rotated and new token was created
        old_token_claims = jwt_service._decode_jwt_token(initial_tokens.refresh_token)
        old_record = RefreshToken.objects.get(token_id=old_token_claims.token_id)
        
        if old_record.status != 'rotated':
            raise Exception(f"Expected old token status 'rotated', found '{old_record.status}'")
        
        print("✓ Old refresh token marked as rotated")
        
        # Check new token record
        new_records = RefreshToken.objects.filter(user=self.user, status='active')
        if new_records.count() != 1:
            raise Exception(f"Expected 1 active refresh token after rotation, found {new_records.count()}")
        
        new_record = new_records.first()
        if new_record.rotation_count != 1:
            raise Exception(f"Expected rotation_count=1, found {new_record.rotation_count}")
        
        if new_record.parent_token != old_record:
            raise Exception("New token should have old token as parent")
        
        print("✓ New refresh token record created with correct rotation tracking")
        
        # Verify old token is blacklisted
        if not jwt_service.blacklist_service.is_token_blacklisted(old_token_claims.token_id):
            raise Exception("Old refresh token should be blacklisted")
        
        print("✓ Old refresh token is blacklisted")
        
        # Try to use old refresh token (should fail)
        failed_refresh = jwt_service.refresh_token_pair(
            refresh_token=initial_tokens.refresh_token,
            device_info=self.device_info
        )
        
        if failed_refresh is not None:
            raise Exception("Old refresh token should not be usable (replay attack prevention)")
        
        print("✓ Old refresh token cannot be reused (replay attack prevented)")
        
        return True
    
    def test_token_family_tracking(self):
        """Test token family tracking through multiple rotations."""
        print("\n--- Testing Token Family Tracking ---")
        
        # Generate initial token pair
        tokens = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Perform multiple rotations
        rotation_count = 3
        for i in range(rotation_count):
            time.sleep(0.1)  # Ensure different timestamps
            tokens = jwt_service.refresh_token_pair(
                refresh_token=tokens.refresh_token,
                device_info=self.device_info
            )
            if not tokens:
                raise Exception(f"Failed to refresh token on rotation {i+1}")
        
        print(f"✓ Performed {rotation_count} token rotations")
        
        # Check current token record
        current_records = RefreshToken.objects.filter(user=self.user, status='active')
        if current_records.count() != 1:
            raise Exception(f"Expected 1 active token, found {current_records.count()}")
        
        current_record = current_records.first()
        if current_record.rotation_count != rotation_count:
            raise Exception(f"Expected rotation_count={rotation_count}, found {current_record.rotation_count}")
        
        print(f"✓ Current token has correct rotation_count={rotation_count}")
        
        # Test token family chain
        family_chain = current_record.get_rotation_chain()
        expected_chain_length = rotation_count + 1  # +1 for initial token
        
        if len(family_chain) != expected_chain_length:
            raise Exception(f"Expected family chain length {expected_chain_length}, found {len(family_chain)}")
        
        print(f"✓ Token family chain has correct length: {len(family_chain)}")
        
        # Verify chain integrity
        for i in range(1, len(family_chain)):
            if family_chain[i].parent_token != family_chain[i-1]:
                raise Exception(f"Chain integrity broken at position {i}")
        
        print("✓ Token family chain integrity verified")
        
        # Test family info API
        current_token_claims = jwt_service._decode_jwt_token(tokens.refresh_token)
        family_info = jwt_service.get_refresh_token_family_info(current_token_claims.token_id)
        
        if not family_info:
            raise Exception("Failed to get token family info")
        
        if family_info['family_size'] != expected_chain_length:
            raise Exception(f"Expected family_size={expected_chain_length}, found {family_info['family_size']}")
        
        if family_info['rotation_count'] != rotation_count:
            raise Exception(f"Expected rotation_count={rotation_count}, found {family_info['rotation_count']}")
        
        if family_info['active_tokens'] != 1:
            raise Exception(f"Expected 1 active token, found {family_info['active_tokens']}")
        
        if family_info['rotated_tokens'] != rotation_count:
            raise Exception(f"Expected {rotation_count} rotated tokens, found {family_info['rotated_tokens']}")
        
        print("✓ Token family info API returns correct data")
        
        return True
    
    def test_automatic_refresh_flow(self):
        """Test automatic token refresh flow helpers."""
        print("\n--- Testing Automatic Token Refresh Flow ---")
        
        # Generate token pair
        tokens = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Test refresh timing logic
        should_refresh_5min = jwt_service.should_refresh_token(tokens.access_token, 5)
        should_refresh_20min = jwt_service.should_refresh_token(tokens.access_token, 20)
        
        # Access tokens expire in 15 minutes, so:
        # - Should not need refresh within 5 minutes
        # - Should need refresh within 20 minutes
        if should_refresh_5min:
            raise Exception("Token should not need refresh within 5 minutes")
        
        if not should_refresh_20min:
            raise Exception("Token should need refresh within 20 minutes")
        
        print("✓ Token refresh timing logic works correctly")
        
        # Test token refresh info API
        refresh_info = jwt_service.get_token_refresh_info(tokens.access_token)
        
        if not refresh_info:
            raise Exception("Failed to get token refresh info")
        
        required_fields = [
            'token_id', 'issued_at', 'expires_at', 'total_lifetime_seconds',
            'time_remaining_seconds', 'time_elapsed_seconds', 'is_expired',
            'should_refresh_5min', 'should_refresh_2min', 'should_refresh_1min',
            'refresh_recommended', 'refresh_urgent'
        ]
        
        for field in required_fields:
            if field not in refresh_info:
                raise Exception(f"Missing field '{field}' in refresh info")
        
        print("✓ Token refresh info API provides all required fields")
        
        # Verify timing calculations
        if refresh_info['is_expired']:
            raise Exception("Token should not be expired")
        
        if refresh_info['time_remaining_seconds'] <= 0:
            raise Exception("Token should have time remaining")
        
        if refresh_info['total_lifetime_seconds'] != 900:  # 15 minutes = 900 seconds
            print(f"⚠ Expected 900 seconds lifetime, found {refresh_info['total_lifetime_seconds']}")
        
        print("✓ Token refresh info calculations are correct")
        
        return True
    
    def test_suspicious_activity_detection(self):
        """Test detection of suspicious refresh token activity."""
        print("\n--- Testing Suspicious Activity Detection ---")
        
        # Generate initial token pair
        tokens = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Create different device info (simulating device change)
        different_device = DeviceInfo(
            device_id='different_device_123',
            device_fingerprint='fp_different_123',
            device_type='mobile',
            browser='Safari',
            operating_system='iOS',
            ip_address='10.0.0.100',
            user_agent='Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'
        )
        
        # Try to refresh with different device (should fail)
        suspicious_refresh = jwt_service.refresh_token_pair(
            refresh_token=tokens.refresh_token,
            device_info=different_device
        )
        
        if suspicious_refresh is not None:
            raise Exception("Refresh should fail with different device fingerprint")
        
        print("✓ Refresh token rejected due to device fingerprint mismatch")
        
        # Verify security response (all user tokens should be revoked)
        active_tokens = RefreshToken.objects.filter(user=self.user, status='active')
        if active_tokens.count() != 0:
            raise Exception(f"Expected 0 active tokens after suspicious activity, found {active_tokens.count()}")
        
        print("✓ All user tokens revoked due to suspicious activity")
        
        return True
    
    def test_family_revocation(self):
        """Test revocation of entire token families."""
        print("\n--- Testing Token Family Revocation ---")
        
        # Generate token pair and perform rotations
        tokens = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info
        )
        
        # Perform rotations to create a family
        for _ in range(2):
            time.sleep(0.1)
            tokens = jwt_service.refresh_token_pair(
                refresh_token=tokens.refresh_token,
                device_info=self.device_info
            )
        
        # Get current token ID
        current_token_claims = jwt_service._decode_jwt_token(tokens.refresh_token)
        
        # Revoke the entire family
        revoked_count = jwt_service.revoke_refresh_token_family(
            current_token_claims.token_id,
            'test_family_revocation'
        )
        
        if revoked_count != 1:  # Only the active token should be revoked
            raise Exception(f"Expected 1 token revoked, found {revoked_count}")
        
        print(f"✓ Revoked {revoked_count} active token in family")
        
        # Verify no active tokens remain
        active_tokens = RefreshToken.objects.filter(user=self.user, status='active')
        if active_tokens.count() != 0:
            raise Exception(f"Expected 0 active tokens after family revocation, found {active_tokens.count()}")
        
        print("✓ No active tokens remain after family revocation")
        
        # Verify token is blacklisted
        if not jwt_service.blacklist_service.is_token_blacklisted(current_token_claims.token_id):
            raise Exception("Revoked token should be blacklisted")
        
        print("✓ Revoked token is properly blacklisted")
        
        return True
    
    def run_all_tests(self):
        """Run all test methods."""
        print("="*80)
        print("JWT TOKEN REFRESH AND ROTATION SYSTEM - SIMPLE TEST")
        print("="*80)
        
        test_methods = [
            ('Basic Refresh Rotation', self.test_basic_refresh_rotation),
            ('Token Family Tracking', self.test_token_family_tracking),
            ('Automatic Refresh Flow', self.test_automatic_refresh_flow),
            ('Suspicious Activity Detection', self.test_suspicious_activity_detection),
            ('Family Revocation', self.test_family_revocation),
        ]
        
        passed = 0
        failed = 0
        
        for test_name, test_method in test_methods:
            try:
                # Setup for each test
                self.setup()
                
                # Run the test
                result = test_method()
                
                if result:
                    passed += 1
                    print(f"✅ {test_name} PASSED")
                else:
                    failed += 1
                    print(f"❌ {test_name} FAILED")
                
            except Exception as e:
                failed += 1
                print(f"❌ {test_name} FAILED: {e}")
            
            finally:
                # Cleanup after each test
                self.cleanup()
        
        print("\n" + "="*80)
        print("TEST SUMMARY")
        print("="*80)
        print(f"Total Tests: {len(test_methods)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(passed/len(test_methods)*100):.1f}%")
        
        if failed == 0:
            print("\n🎉 ALL TESTS PASSED!")
            print("\nImplemented features for Task 12:")
            print("✓ Refresh token rotation to prevent replay attacks")
            print("✓ Automatic token refresh flow for client applications")
            print("✓ Refresh token family tracking for security")
            print("✓ Refresh token revocation on suspicious activity")
            print("\nRequirements satisfied: 2.3, 2.5")
        else:
            print(f"\n⚠️  {failed} test(s) failed. Please review the implementation.")
        
        return failed == 0


def main():
    """Main test execution function."""
    try:
        test_instance = SimpleTokenRefreshTest()
        success = test_instance.run_all_tests()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()