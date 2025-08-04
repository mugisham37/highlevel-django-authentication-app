#!/usr/bin/env python
"""
Simple API test for JWT token revocation endpoints.

This script tests the token revocation API endpoints to verify they work correctly.
"""

import os
import sys
import django
import json
from datetime import datetime, timedelta

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.development')
django.setup()

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone

from enterprise_auth.core.services.jwt_service import jwt_service, DeviceInfo
from enterprise_auth.core.models.user import UserProfile

User = get_user_model()


class TokenRevocationAPITest:
    """Test class for token revocation API endpoints."""
    
    def __init__(self):
        self.client = Client()
        self.user = None
        self.token_pair = None
        self.device_info = None
        
    def setup(self):
        """Set up test data."""
        print("Setting up test data...")
        
        # Create or get test user
        try:
            self.user = User.objects.get(email='test@example.com')
        except User.DoesNotExist:
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
        
    def test_login_endpoint(self):
        """Test the login endpoint to get tokens."""
        print("\n--- Testing Login Endpoint ---")
        
        response = self.client.post('/api/v1/core/auth/login/', {
            'email': 'test@example.com',
            'password': 'testpass123'
        }, content_type='application/json')
        
        assert response.status_code == 200, f"Login should succeed, got {response.status_code}"
        
        data = response.json()
        assert 'tokens' in data, "Response should contain tokens"
        assert 'access_token' in data['tokens'], "Response should contain access token"
        assert 'refresh_token' in data['tokens'], "Response should contain refresh token"
        
        print("✓ Login endpoint works correctly")
        return data['tokens']
        
    def test_token_validation(self):
        """Test token validation endpoint."""
        print("\n--- Testing Token Validation ---")
        
        # Get fresh tokens
        tokens = self.test_login_endpoint()
        
        # Test token validation
        response = self.client.get('/api/v1/core/auth/validate/', 
                                 HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        
        assert response.status_code == 200, f"Token validation should succeed, got {response.status_code}"
        
        data = response.json()
        assert data['valid'] == True, "Token should be valid"
        assert 'user' in data, "Response should contain user info"
        
        print("✓ Token validation endpoint works correctly")
        return tokens
        
    def test_single_token_revocation(self):
        """Test single token revocation endpoint."""
        print("\n--- Testing Single Token Revocation ---")
        
        # Get fresh tokens
        tokens = self.test_login_endpoint()
        
        # Revoke the access token
        response = self.client.post('/api/v1/core/auth/revoke/', {
            'token': tokens['access_token'],
            'reason': 'test_revocation'
        }, content_type='application/json',
           HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        
        assert response.status_code == 200, f"Token revocation should succeed, got {response.status_code}"
        
        data = response.json()
        assert 'message' in data, "Response should contain success message"
        
        print("✓ Single token revocation endpoint works correctly")
        
        # Verify token is now invalid
        validation_response = self.client.get('/api/v1/auth/validate/', 
                                            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        
        assert validation_response.status_code == 401, "Revoked token should be invalid"
        print("✓ Revoked token is now invalid")
        
    def test_revoke_all_user_tokens(self):
        """Test revoking all user tokens endpoint."""
        print("\n--- Testing Revoke All User Tokens ---")
        
        # Get fresh tokens
        tokens = self.test_login_endpoint()
        
        # Revoke all user tokens
        response = self.client.post('/api/v1/auth/revoke-all/', {
            'reason': 'test_revoke_all'
        }, content_type='application/json',
           HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        
        assert response.status_code == 200, f"Revoke all should succeed, got {response.status_code}"
        
        data = response.json()
        assert 'message' in data, "Response should contain success message"
        
        print("✓ Revoke all user tokens endpoint works correctly")
        
        # Verify token is now invalid
        validation_response = self.client.get('/api/v1/auth/validate/', 
                                            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        
        assert validation_response.status_code == 401, "All tokens should be invalid after revoke-all"
        print("✓ All user tokens are now invalid")
        
    def test_device_token_revocation(self):
        """Test device token revocation endpoint."""
        print("\n--- Testing Device Token Revocation ---")
        
        # Get fresh tokens
        tokens = self.test_login_endpoint()
        
        # Revoke device tokens
        response = self.client.post('/api/v1/auth/revoke-device/', {
            'device_id': self.device_info.device_id,
            'reason': 'test_device_revocation'
        }, content_type='application/json',
           HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        
        assert response.status_code == 200, f"Device revocation should succeed, got {response.status_code}"
        
        data = response.json()
        assert 'message' in data, "Response should contain success message"
        
        print("✓ Device token revocation endpoint works correctly")
        
    def test_bulk_token_revocation(self):
        """Test bulk token revocation endpoint."""
        print("\n--- Testing Bulk Token Revocation ---")
        
        # Get fresh tokens
        tokens = self.test_login_endpoint()
        
        # For bulk revocation, we need token IDs, which requires decoding tokens
        # For this test, we'll use dummy token IDs
        dummy_token_ids = ['token-id-1', 'token-id-2', 'token-id-3']
        
        # Bulk revoke tokens
        response = self.client.post('/api/v1/auth/bulk-revoke/', {
            'token_ids': dummy_token_ids,
            'reason': 'test_bulk_revocation'
        }, content_type='application/json',
           HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        
        assert response.status_code == 200, f"Bulk revocation should succeed, got {response.status_code}"
        
        data = response.json()
        assert 'message' in data, "Response should contain success message"
        assert 'revoked_count' in data, "Response should contain revoked count"
        
        print(f"✓ Bulk token revocation endpoint works correctly (revoked {data['revoked_count']} tokens)")
        
    def test_logout_endpoint(self):
        """Test logout endpoint."""
        print("\n--- Testing Logout Endpoint ---")
        
        # Get fresh tokens
        tokens = self.test_login_endpoint()
        
        # Test logout
        response = self.client.post('/api/v1/auth/logout/', {
            'revoke_all': False
        }, content_type='application/json',
           HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        
        assert response.status_code == 200, f"Logout should succeed, got {response.status_code}"
        
        data = response.json()
        assert 'message' in data, "Response should contain success message"
        
        print("✓ Logout endpoint works correctly")
        
        # Verify token is now invalid
        validation_response = self.client.get('/api/v1/auth/validate/', 
                                            HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
        
        assert validation_response.status_code == 401, "Token should be invalid after logout"
        print("✓ Token is invalid after logout")
        
    def test_token_introspection(self):
        """Test token introspection endpoint."""
        print("\n--- Testing Token Introspection ---")
        
        # Get fresh tokens
        tokens = self.test_login_endpoint()
        
        # Test introspection
        response = self.client.post('/api/v1/auth/introspect/', {
            'token': tokens['access_token']
        }, content_type='application/json')
        
        assert response.status_code == 200, f"Introspection should succeed, got {response.status_code}"
        
        data = response.json()
        assert 'active' in data, "Response should contain active status"
        assert data['active'] == True, "Token should be active"
        
        print("✓ Token introspection endpoint works correctly")
        
    def run_all_tests(self):
        """Run all API tests."""
        print("=" * 60)
        print("JWT TOKEN REVOCATION API TESTS")
        print("=" * 60)
        
        try:
            self.setup()
            self.test_login_endpoint()
            self.test_token_validation()
            self.test_token_introspection()
            self.test_single_token_revocation()
            self.test_revoke_all_user_tokens()
            self.test_device_token_revocation()
            self.test_bulk_token_revocation()
            self.test_logout_endpoint()
            
            print("\n" + "=" * 60)
            print("✅ ALL API TESTS PASSED!")
            print("Token revocation API endpoints are working correctly.")
            print("=" * 60)
            
        except Exception as e:
            print(f"\n❌ API TEST FAILED: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
            
        return True
    
    def cleanup(self):
        """Clean up test data."""
        print("\nCleaning up test data...")
        try:
            if self.user:
                self.user.delete()
            print("✓ Test data cleaned up")
        except Exception as e:
            print(f"⚠️  Cleanup warning: {str(e)}")


def main():
    """Main test function."""
    test = TokenRevocationAPITest()
    try:
        success = test.run_all_tests()
        return 0 if success else 1
    finally:
        test.cleanup()


if __name__ == '__main__':
    sys.exit(main())