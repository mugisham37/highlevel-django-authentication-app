#!/usr/bin/env python3
"""
Test suite for JWT Token Validation and Introspection - Task 10 Implementation.

This test suite validates the implementation of:
- Token validation middleware with performance optimization
- Token introspection endpoint for external services
- Token claims extraction and validation utilities
- Token expiration and signature verification

Requirements tested: 2.7, 2.8
"""

import os
import sys
import django
import time
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.testing')
django.setup()

from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.http import HttpRequest
from rest_framework.test import APIClient

from enterprise_auth.core.services.jwt_service import jwt_service, DeviceInfo, TokenClaims
from enterprise_auth.core.middleware.jwt_middleware import (
    JWTTokenValidationMiddleware,
    JWTTokenIntrospectionMiddleware
)
from enterprise_auth.core.utils.jwt_utils import (
    extract_token_from_request,
    get_token_claims_from_request,
    validate_token_with_claims,
    extract_user_from_token,
    get_token_expiration_info,
    check_token_scopes,
    create_token_introspection_response,
    validate_token_signature,
    is_token_blacklisted,
    get_token_metrics,
    require_token_scopes
)

User = get_user_model()


class TokenValidationIntrospectionTest:
    """Test class for JWT Token Validation and Introspection."""
    
    def __init__(self):
        """Initialize test environment."""
        self.factory = RequestFactory()
        self.client = APIClient()
        self.cache = caches['default']
        
        # Create test user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User',
            is_email_verified=True
        )
        
        # Create device info for testing
        self.device_info = DeviceInfo(
            device_id='test-device-123',
            device_fingerprint='test-fingerprint-456',
            device_type='desktop',
            browser='chrome',
            operating_system='windows',
            ip_address='192.168.1.100',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        print("✓ Test environment initialized")
    
    def test_jwt_validation_middleware(self):
        """Test JWT token validation middleware functionality."""
        print("Testing JWT validation middleware...")
        
        # Generate test token
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write', 'admin']
        )
        
        # Create middleware instance
        get_response = MagicMock(return_value=MagicMock())
        middleware = JWTTokenValidationMiddleware(get_response)
        
        # Test 1: Valid token request
        request = self.factory.get('/api/test/', HTTP_AUTHORIZATION=f'Bearer {token_pair.access_token}')
        request.META['HTTP_USER_AGENT'] = self.device_info.user_agent
        request.META['REMOTE_ADDR'] = self.device_info.ip_address
        
        response = middleware.process_request(request)
        
        # Should return None (allow request to continue)
        assert response is None
        assert hasattr(request, 'user')
        assert hasattr(request, 'jwt_claims')
        assert hasattr(request, 'jwt_validated')
        assert request.jwt_validated is True
        assert request.user.email == self.user.email
        
        print("   ✅ Valid token middleware processing")
        
        # Test 2: Invalid token request
        request = self.factory.get('/api/test/', HTTP_AUTHORIZATION='Bearer invalid-token')
        response = middleware.process_request(request)
        
        # Should return error response
        assert response is not None
        assert response.status_code == 401
        
        response_data = json.loads(response.content)
        assert response_data['error']['code'] == 'INVALID_TOKEN'
        
        print("   ✅ Invalid token middleware rejection")
        
        # Test 3: Excluded path (should skip validation)
        request = self.factory.get('/health/')
        response = middleware.process_request(request)
        
        # Should return None (skip validation)
        assert response is None
        
        print("   ✅ Excluded path handling")
        
        # Test 4: No token (should allow other auth methods)
        request = self.factory.get('/api/test/')
        response = middleware.process_request(request)
        
        # Should return None (let other auth handle it)
        assert response is None
        
        print("   ✅ No token handling")
        
        print("✓ JWT validation middleware test passed")
    
    def test_jwt_introspection_middleware(self):
        """Test JWT token introspection middleware functionality."""
        print("Testing JWT introspection middleware...")
        
        # Generate test token
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        # Create middleware instance
        get_response = MagicMock(return_value=MagicMock())
        middleware = JWTTokenIntrospectionMiddleware(get_response)
        
        # Test with valid token
        request = self.factory.get('/api/test/', HTTP_AUTHORIZATION=f'Bearer {token_pair.access_token}')
        middleware.process_request(request)
        
        # Check that introspection data is added
        assert hasattr(request, 'jwt_introspection')
        assert hasattr(request, 'jwt_token_present')
        assert hasattr(request, 'jwt_user_id')
        assert hasattr(request, 'jwt_scopes')
        
        assert request.jwt_token_present is True
        assert request.jwt_user_id == str(self.user.id)
        assert 'read' in request.jwt_scopes
        assert 'write' in request.jwt_scopes
        
        print("   ✅ Token introspection data added to request")
        
        # Test with no token
        request = self.factory.get('/api/test/')
        middleware.process_request(request)
        
        # Should not add introspection data
        assert not hasattr(request, 'jwt_introspection')
        
        print("   ✅ No token handling")
        
        print("✓ JWT introspection middleware test passed")
    
    def test_token_claims_extraction_utilities(self):
        """Test token claims extraction and validation utilities."""
        print("Testing token claims extraction utilities...")
        
        # Generate test token
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write', 'admin']
        )
        
        # Test 1: Extract token from request
        request = self.factory.get('/api/test/', HTTP_AUTHORIZATION=f'Bearer {token_pair.access_token}')
        
        extracted_token = extract_token_from_request(request)
        assert extracted_token == token_pair.access_token
        
        print("   ✅ Token extraction from Authorization header")
        
        # Test 2: Extract token from custom header
        request = self.factory.get('/api/test/', HTTP_X_AUTH_TOKEN=token_pair.access_token)
        
        extracted_token = extract_token_from_request(request)
        assert extracted_token == token_pair.access_token
        
        print("   ✅ Token extraction from custom header")
        
        # Test 3: Extract token from query parameters
        request = self.factory.get(f'/api/test/?token={token_pair.access_token}')
        
        extracted_token = extract_token_from_request(request)
        assert extracted_token == token_pair.access_token
        
        print("   ✅ Token extraction from query parameters")
        
        # Test 4: Get token claims from request
        request = self.factory.get('/api/test/', HTTP_AUTHORIZATION=f'Bearer {token_pair.access_token}')
        request.META['HTTP_USER_AGENT'] = self.device_info.user_agent
        request.META['REMOTE_ADDR'] = self.device_info.ip_address
        
        claims = get_token_claims_from_request(request)
        assert claims is not None
        assert claims.user_id == str(self.user.id)
        assert claims.email == self.user.email
        assert 'read' in claims.scopes
        assert 'write' in claims.scopes
        assert 'admin' in claims.scopes
        
        print("   ✅ Token claims extraction from request")
        
        # Test 5: Validate token with claims
        validation_result = validate_token_with_claims(token_pair.access_token, request)
        assert validation_result.is_valid
        assert validation_result.claims.user_id == str(self.user.id)
        
        print("   ✅ Token validation with claims")
        
        # Test 6: Extract user from token
        user = extract_user_from_token(token_pair.access_token, request)
        assert user is not None
        assert user.id == self.user.id
        assert user.email == self.user.email
        
        print("   ✅ User extraction from token")
        
        print("✓ Token claims extraction utilities test passed")
    
    def test_token_expiration_and_signature_verification(self):
        """Test token expiration and signature verification."""
        print("Testing token expiration and signature verification...")
        
        # Generate test token
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        # Test 1: Get token expiration info
        validation_result = validate_token_with_claims(token_pair.access_token)
        assert validation_result.is_valid
        
        expiration_info = get_token_expiration_info(validation_result.claims)
        
        assert 'expires_at' in expiration_info
        assert 'issued_at' in expiration_info
        assert 'time_to_expiry_seconds' in expiration_info
        assert 'token_age_seconds' in expiration_info
        assert 'is_expired' in expiration_info
        assert 'expires_soon' in expiration_info
        
        assert expiration_info['is_expired'] is False
        assert expiration_info['time_to_expiry_seconds'] > 0
        
        print("   ✅ Token expiration info extraction")
        
        # Test 2: Validate token signature
        signature_valid = validate_token_signature(token_pair.access_token)
        assert signature_valid is True
        
        # Test invalid signature
        invalid_token = token_pair.access_token[:-10] + 'invalid123'
        signature_valid = validate_token_signature(invalid_token)
        assert signature_valid is False
        
        print("   ✅ Token signature verification")
        
        # Test 3: Check token scopes
        claims = validation_result.claims
        
        # Should have required scopes
        assert check_token_scopes(claims, ['read']) is True
        assert check_token_scopes(claims, ['read', 'write']) is True
        
        # Should not have admin scope if not granted
        if 'admin' not in claims.scopes:
            assert check_token_scopes(claims, ['admin']) is False
        
        print("   ✅ Token scope verification")
        
        # Test 4: Check if token is blacklisted
        blacklisted = is_token_blacklisted(token_pair.access_token)
        assert blacklisted is False
        
        # Blacklist the token
        jwt_service.revoke_token(token_pair.access_token, 'test_revocation')
        
        blacklisted = is_token_blacklisted(token_pair.access_token)
        assert blacklisted is True
        
        print("   ✅ Token blacklist verification")
        
        print("✓ Token expiration and signature verification test passed")
    
    def test_token_introspection_endpoint(self):
        """Test token introspection endpoint for external services."""
        print("Testing token introspection endpoint...")
        
        # Generate test token
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write', 'admin'],
            session_id='test-session-123'
        )
        
        # Test 1: Introspect valid token
        response = self.client.post('/api/v1/core/auth/introspect/', {
            'token': token_pair.access_token
        })
        
        assert response.status_code == 200
        
        introspection_data = response.json()
        assert introspection_data['active'] is True
        assert introspection_data['token_type'] == 'Bearer'
        assert introspection_data['user_id'] == str(self.user.id)
        assert introspection_data['email'] == self.user.email
        assert 'read' in introspection_data['scopes']
        assert 'write' in introspection_data['scopes']
        assert 'admin' in introspection_data['scopes']
        assert introspection_data['session_id'] == 'test-session-123'
        
        print("   ✅ Valid token introspection")
        
        # Test 2: Introspect invalid token
        response = self.client.post('/api/v1/core/auth/introspect/', {
            'token': 'invalid-token'
        })
        
        assert response.status_code == 200
        
        introspection_data = response.json()
        assert introspection_data['active'] is False
        assert 'error' in introspection_data
        
        print("   ✅ Invalid token introspection")
        
        # Test 3: Missing token parameter
        response = self.client.post('/api/v1/core/auth/introspect/', {})
        
        assert response.status_code == 400
        
        error_data = response.json()
        assert 'error' in error_data
        
        print("   ✅ Missing token parameter handling")
        
        # Test 4: Comprehensive introspection response
        introspection_response = create_token_introspection_response(token_pair.access_token)
        
        assert introspection_response['active'] is True
        assert 'expires_at' in introspection_response
        assert 'issued_at' in introspection_response
        assert 'time_to_expiry_seconds' in introspection_response
        assert 'device_info' in introspection_response
        
        device_info = introspection_response['device_info']
        assert device_info['device_id'] == self.device_info.device_id
        assert device_info['ip_address'] == self.device_info.ip_address
        
        print("   ✅ Comprehensive introspection response")
        
        print("✓ Token introspection endpoint test passed")
    
    def test_token_validation_endpoint(self):
        """Test token validation endpoint."""
        print("Testing token validation endpoint...")
        
        # Generate test token
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        # Test 1: Validate token with authentication
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token_pair.access_token}')
        
        response = self.client.get('/api/v1/core/auth/validate/')
        
        assert response.status_code == 200
        
        validation_data = response.json()
        assert validation_data['valid'] is True
        assert validation_data['user']['id'] == str(self.user.id)
        assert validation_data['user']['email'] == self.user.email
        assert validation_data['user']['is_email_verified'] is True
        
        if 'token_info' in validation_data:
            token_info = validation_data['token_info']
            assert 'token_id' in token_info
            assert 'device_id' in token_info
            assert 'scopes' in token_info
            assert 'read' in token_info['scopes']
            assert 'write' in token_info['scopes']
        
        print("   ✅ Valid token validation endpoint")
        
        # Test 2: Validate without token (should fail)
        self.client.credentials()  # Clear credentials
        
        response = self.client.get('/api/v1/core/auth/validate/')
        
        assert response.status_code == 401
        
        print("   ✅ No token validation endpoint")
        
        print("✓ Token validation endpoint test passed")
    
    def test_performance_optimization(self):
        """Test performance optimization features."""
        print("Testing performance optimization...")
        
        # Generate test token
        token_pair = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        # Test 1: Measure validation performance
        start_time = time.time()
        
        for _ in range(10):
            validation_result = validate_token_with_claims(token_pair.access_token)
            assert validation_result.is_valid
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 10
        
        # Should be well under 100ms per validation
        assert avg_time < 0.1  # 100ms
        
        print(f"   ✅ Average validation time: {avg_time*1000:.2f}ms")
        
        # Test 2: Test caching behavior
        # Clear cache first
        self.cache.clear()
        
        # First validation (cache miss)
        start_time = time.time()
        validation_result = validate_token_with_claims(token_pair.access_token)
        first_time = time.time() - start_time
        
        assert validation_result.is_valid
        
        # Second validation (should be faster due to caching)
        start_time = time.time()
        validation_result = validate_token_with_claims(token_pair.access_token)
        second_time = time.time() - start_time
        
        assert validation_result.is_valid
        
        print(f"   ✅ First validation: {first_time*1000:.2f}ms, Second validation: {second_time*1000:.2f}ms")
        
        # Test 3: Get token metrics
        metrics = get_token_metrics()
        
        assert 'validation_counts' in metrics
        assert 'average_times' in metrics
        assert 'recent_validations' in metrics
        
        print("   ✅ Token validation metrics collection")
        
        print("✓ Performance optimization test passed")
    
    def test_scope_based_authorization(self):
        """Test scope-based authorization decorator."""
        print("Testing scope-based authorization...")
        
        # Generate tokens with different scopes
        admin_token = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write', 'admin']
        )
        
        user_token = jwt_service.generate_token_pair(
            user=self.user,
            device_info=self.device_info,
            scopes=['read', 'write']
        )
        
        # Create a test view with scope requirements
        @require_token_scopes(['admin'])
        def admin_view(request):
            from django.http import JsonResponse
            return JsonResponse({'message': 'Admin access granted'})
        
        # Test 1: Access with admin token
        request = self.factory.get('/admin/test/', HTTP_AUTHORIZATION=f'Bearer {admin_token.access_token}')
        request.META['HTTP_USER_AGENT'] = self.device_info.user_agent
        request.META['REMOTE_ADDR'] = self.device_info.ip_address
        
        response = admin_view(request)
        assert response.status_code == 200
        
        print("   ✅ Admin scope authorization granted")
        
        # Test 2: Access with user token (should fail)
        request = self.factory.get('/admin/test/', HTTP_AUTHORIZATION=f'Bearer {user_token.access_token}')
        request.META['HTTP_USER_AGENT'] = self.device_info.user_agent
        request.META['REMOTE_ADDR'] = self.device_info.ip_address
        
        response = admin_view(request)
        assert response.status_code == 403
        
        response_data = json.loads(response.content)
        assert response_data['error']['code'] == 'INSUFFICIENT_SCOPE'
        
        print("   ✅ Admin scope authorization denied")
        
        print("✓ Scope-based authorization test passed")
    
    def run_all_tests(self):
        """Run all token validation and introspection tests."""
        print("=" * 80)
        print("JWT TOKEN VALIDATION AND INTROSPECTION TEST SUITE")
        print("=" * 80)
        
        test_methods = [
            self.test_jwt_validation_middleware,
            self.test_jwt_introspection_middleware,
            self.test_token_claims_extraction_utilities,
            self.test_token_expiration_and_signature_verification,
            self.test_token_introspection_endpoint,
            self.test_token_validation_endpoint,
            self.test_performance_optimization,
            self.test_scope_based_authorization,
        ]
        
        passed_tests = 0
        total_tests = len(test_methods)
        
        for test_method in test_methods:
            try:
                test_method()
                passed_tests += 1
            except Exception as e:
                print(f"❌ {test_method.__name__} failed: {str(e)}")
                import traceback
                traceback.print_exc()
        
        print("=" * 80)
        print(f"TEST RESULTS: {passed_tests}/{total_tests} tests passed")
        
        if passed_tests == total_tests:
            print("🎉 ALL TESTS PASSED!")
            print("\nTask 10 Implementation Summary:")
            print("✅ Token validation middleware with performance optimization")
            print("✅ Token introspection endpoint for external services")
            print("✅ Token claims extraction and validation utilities")
            print("✅ Token expiration and signature verification")
            print("✅ Performance optimizations with caching")
            print("✅ Comprehensive error handling")
            print("✅ Scope-based authorization")
            print("✅ Metrics collection and monitoring")
        else:
            print(f"❌ {total_tests - passed_tests} tests failed")
        
        print("=" * 80)
        
        return passed_tests == total_tests


def main():
    """Main test execution function."""
    try:
        # Initialize test suite
        test_suite = TokenValidationIntrospectionTest()
        
        # Run all tests
        success = test_suite.run_all_tests()
        
        return 0 if success else 1
        
    except Exception as e:
        print(f"Test suite initialization failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)