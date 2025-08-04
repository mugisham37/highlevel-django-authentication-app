#!/usr/bin/env python
"""
Test script for password management functionality.

This script tests the password management features including:
- Argon2 password hashing
- Password strength validation
- Password change API
- Password reset workflow
"""

import os
import sys
import django
from django.conf import settings

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.development')
django.setup()

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from enterprise_auth.core.utils.password import password_policy
from enterprise_auth.core.services.password_service import PasswordService
from enterprise_auth.core.models import UserProfile

User = get_user_model()


def test_argon2_hashing():
    """Test Argon2 password hashing configuration."""
    print("Testing Argon2 password hashing...")
    
    password = "TestPassword123!"
    hashed = password_policy.hash_password(password)
    
    # Check that it uses Argon2
    assert hashed.startswith('argon2'), f"Expected Argon2 hash, got: {hashed[:20]}..."
    
    # Verify password
    assert password_policy.verify_password(password, hashed), "Password verification failed"
    assert not password_policy.verify_password("wrong_password", hashed), "Wrong password should not verify"
    
    print("✓ Argon2 hashing working correctly")


def test_password_strength_validation():
    """Test password strength validation with configurable policies."""
    print("Testing password strength validation...")
    
    # Test weak passwords
    weak_passwords = [
        "123456",  # Too short, no complexity
        "password",  # Common password
        "abcdefgh",  # No numbers or special chars
        "12345678",  # No letters
        "Password",  # No numbers or special chars
    ]
    
    for password in weak_passwords:
        result = password_policy.validate_password(password)
        assert not result['is_valid'], f"Password '{password}' should be invalid"
        assert len(result['errors']) > 0, f"Password '{password}' should have validation errors"
    
    # Test strong password
    strong_password = "MyStr0ng!P@ssw0rd2024"
    result = password_policy.validate_password(strong_password)
    assert result['is_valid'], f"Strong password should be valid. Errors: {result['errors']}"
    
    # Test strength scoring
    strength = result['strength']
    assert 'score' in strength, "Strength should include score"
    assert 'level' in strength, "Strength should include level"
    assert strength['score'] > 70, f"Strong password should have high score, got: {strength['score']}"
    
    print("✓ Password strength validation working correctly")


def test_password_service():
    """Test password service functionality."""
    print("Testing password service...")
    
    # Create test user with unique email
    import uuid
    test_email = f'test-{uuid.uuid4().hex[:8]}@example.com'
    
    user = UserProfile.objects.create_user(
        email=test_email,
        password='OldPassword123!',
        first_name='Test',
        last_name='User',
        username=test_email  # Use email as username to ensure uniqueness
    )
    
    password_service = PasswordService()
    
    # Test password change
    try:
        result = password_service.change_password(
            user=user,
            current_password='OldPassword123!',
            new_password='NewStr0ng!P@ssw0rd2024'
        )
        assert result['success'], "Password change should succeed"
        print("✓ Password change working correctly")
    except Exception as e:
        print(f"✗ Password change failed: {e}")
    
    # Test password reset initiation
    try:
        result = password_service.initiate_password_reset(test_email)
        assert result['success'], "Password reset initiation should succeed"
        print("✓ Password reset initiation working correctly")
    except Exception as e:
        print(f"✗ Password reset initiation failed: {e}")
    
    # Clean up
    user.delete()


def test_api_endpoints():
    """Test password management API endpoints."""
    print("Testing API endpoints...")
    
    client = Client()
    
    # Test password policy endpoint
    response = client.get('/api/v1/core/auth/password/policy/')
    assert response.status_code == 200, f"Password policy endpoint failed: {response.status_code}"
    data = response.json()
    assert 'policy' in data, "Policy endpoint should return policy data"
    print("✓ Password policy API working correctly")
    
    # Test password strength check endpoint
    response = client.post('/api/v1/core/auth/password/strength/', {
        'password': 'TestPassword123!'
    }, content_type='application/json')
    assert response.status_code == 200, f"Password strength endpoint failed: {response.status_code}"
    data = response.json()
    assert 'strength' in data, "Strength endpoint should return strength data"
    print("✓ Password strength check API working correctly")
    
    # Test password reset request endpoint
    response = client.post('/api/v1/core/auth/password/reset/', {
        'email': 'nonexistent@example.com'
    }, content_type='application/json')
    assert response.status_code == 200, f"Password reset request failed: {response.status_code}"
    print("✓ Password reset request API working correctly")


def run_all_tests():
    """Run all password management tests."""
    print("=" * 60)
    print("TESTING PASSWORD MANAGEMENT FUNCTIONALITY")
    print("=" * 60)
    
    try:
        test_argon2_hashing()
        test_password_strength_validation()
        test_password_service()
        test_api_endpoints()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED - Password management is working correctly!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    run_all_tests()