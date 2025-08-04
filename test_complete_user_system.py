#!/usr/bin/env python
"""
Comprehensive test script for the enterprise authentication user system.
"""

import os
import sys
import django
import json
from django.test import Client

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.development')
django.setup()

def cleanup_test_data():
    """Clean up any existing test data."""
    from enterprise_auth.core.models import UserProfile
    
    # Delete test user if exists
    UserProfile.objects.filter(email='test@example.com').delete()
    print("🧹 Cleaned up existing test data")

def test_complete_user_workflow():
    """Test the complete user workflow from registration to profile management."""
    print("🚀 Testing Complete User Workflow")
    print("="*60)
    
    client = Client()
    
    # Step 1: User Registration
    print("\n1️⃣ Testing User Registration...")
    registration_data = {
        'email': 'test@example.com',
        'first_name': 'Jane',
        'last_name': 'Smith',
        'password': 'SuperSecure123!@#',
        'password_confirm': 'SuperSecure123!@#',
        'terms_accepted': True,
        'privacy_policy_accepted': True,
        'organization': 'Tech Innovations Inc',
        'department': 'Product Engineering',
        'employee_id': 'TI-2024-001',
        'job_title': 'Senior Full Stack Developer',
        'timezone': 'America/Los_Angeles',
        'language': 'en',
        'marketing_consent': True,
    }
    
    response = client.post(
        '/api/v1/core/auth/register/',
        data=json.dumps(registration_data),
        content_type='application/json'
    )
    
    assert response.status_code == 201, f"Registration failed: {response.content}"
    user_data = response.json()
    user_id = user_data['user']['id']
    
    print(f"   ✅ User registered successfully")
    print(f"   📧 Email: {user_data['user']['email']}")
    print(f"   👤 Name: {user_data['user']['full_name']}")
    print(f"   🏢 Enterprise: {user_data['user']['has_enterprise_profile']}")
    print(f"   📧 Verified: {user_data['user']['is_email_verified']}")
    
    # Step 2: Email Verification
    print("\n2️⃣ Testing Email Verification...")
    
    # Get the user and generate a verification token
    from enterprise_auth.core.models import UserProfile
    user = UserProfile.objects.get(id=user_id)
    
    # Generate verification token
    import secrets
    import string
    token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    user.set_email_verification_token(token)
    
    verification_data = {
        'user_id': user_id,
        'token': token
    }
    
    response = client.post(
        '/api/v1/core/auth/verify-email/',
        data=json.dumps(verification_data),
        content_type='application/json'
    )
    
    assert response.status_code == 200, f"Email verification failed: {response.content}"
    print(f"   ✅ Email verified successfully")
    
    # Verify user is now verified
    user.refresh_from_db()
    assert user.is_email_verified == True
    print(f"   📧 User email verification status: {user.is_email_verified}")
    
    # Step 3: Profile Management
    print("\n3️⃣ Testing Profile Management...")
    
    # Force login the user
    client.force_login(user)
    
    # Get profile
    response = client.get('/api/v1/core/user/profile/me/')
    assert response.status_code == 200, f"Profile retrieval failed: {response.content}"
    
    profile_data = response.json()
    print(f"   ✅ Profile retrieved successfully")
    print(f"   📋 Profile details:")
    print(f"      - ID: {profile_data['id']}")
    print(f"      - Email: {profile_data['email']}")
    print(f"      - Organization: {profile_data['organization']}")
    print(f"      - Department: {profile_data['department']}")
    print(f"      - Employee ID: {profile_data['employee_id']}")
    print(f"      - Job Title: {profile_data['job_title']}")
    print(f"      - Timezone: {profile_data['timezone']}")
    print(f"      - Fully Verified: {profile_data['is_fully_verified']}")
    
    # Update profile
    update_data = {
        'job_title': 'Lead Full Stack Developer',
        'department': 'Engineering Leadership',
        'timezone': 'America/New_York',
        'marketing_consent': False,
    }
    
    response = client.patch(
        '/api/v1/core/user/profile/me/',
        data=json.dumps(update_data),
        content_type='application/json'
    )
    
    assert response.status_code == 200, f"Profile update failed: {response.content}"
    updated_data = response.json()
    print(f"   ✅ Profile updated successfully")
    print(f"   📝 Updated fields:")
    print(f"      - Job Title: {updated_data['user']['job_title']}")
    print(f"      - Department: {updated_data['user']['department']}")
    print(f"      - Timezone: {updated_data['user']['timezone']}")
    print(f"      - Marketing Consent: {updated_data['user']['marketing_consent']}")
    
    # Step 4: Test User Manager Methods
    print("\n4️⃣ Testing User Manager Methods...")
    
    # Test enterprise user query
    enterprise_users = UserProfile.objects.get_enterprise_users('Tech Innovations Inc')
    assert enterprise_users.count() == 1
    print(f"   ✅ Enterprise users query: {enterprise_users.count()} users found")
    
    # Test verified users query
    verified_users = UserProfile.objects.get_verified_users()
    assert user in verified_users
    print(f"   ✅ Verified users query: User found in verified users")
    
    # Test user search
    search_results = UserProfile.objects.search_users('Jane')
    assert user in search_results
    print(f"   ✅ User search: Found user by first name")
    
    search_results = UserProfile.objects.search_users('Tech Innovations')
    assert user in search_results
    print(f"   ✅ User search: Found user by organization")
    
    # Step 5: Test User Model Properties and Methods
    print("\n5️⃣ Testing User Model Properties...")
    
    user.refresh_from_db()
    
    print(f"   📊 User Properties:")
    print(f"      - Full Name: {user.get_full_name()}")
    print(f"      - Short Name: {user.get_short_name()}")
    print(f"      - Is Account Locked: {user.is_account_locked}")
    print(f"      - Is Fully Verified: {user.is_fully_verified}")
    print(f"      - Has Enterprise Profile: {user.has_enterprise_profile}")
    print(f"      - Is Active User: {user.is_active_user}")
    
    # Test account locking
    user.lock_account(30)  # Lock for 30 minutes
    assert user.is_account_locked == True
    print(f"   🔒 Account locked successfully")
    
    user.unlock_account()
    assert user.is_account_locked == False
    print(f"   🔓 Account unlocked successfully")
    
    # Step 6: Test Validation
    print("\n6️⃣ Testing Validation...")
    
    # Test duplicate email registration
    response = client.post(
        '/api/v1/core/auth/register/',
        data=json.dumps(registration_data),
        content_type='application/json'
    )
    
    assert response.status_code == 400
    error_data = response.json()
    assert 'email' in error_data
    print(f"   ✅ Duplicate email validation: {error_data['email'][0]}")
    
    # Test invalid email verification
    invalid_verification = {
        'user_id': user_id,
        'token': 'invalid_token'
    }
    
    response = client.post(
        '/api/v1/core/auth/verify-email/',
        data=json.dumps(invalid_verification),
        content_type='application/json'
    )
    
    assert response.status_code == 400
    print(f"   ✅ Invalid token validation: Properly rejected")
    
    print("\n" + "="*60)
    print("🎉 All tests passed! User system is working correctly.")
    print("="*60)
    
    return user

def test_user_identity_system():
    """Test the user identity (OAuth) system."""
    print("\n🔗 Testing User Identity System")
    print("="*60)
    
    from enterprise_auth.core.models import UserProfile, UserIdentity
    
    # Get the test user
    user = UserProfile.objects.get(email='test@example.com')
    
    # Test linking a social account
    print("\n1️⃣ Testing Social Account Linking...")
    
    provider_data = {
        'id': '123456789',
        'email': 'test@example.com',
        'name': 'Jane Smith',
        'username': 'janesmith',
        'avatar_url': 'https://example.com/avatar.jpg'
    }
    
    identity = UserIdentity.objects.link_social_account(
        user=user,
        provider='github',
        provider_user_id='123456789',
        provider_data=provider_data,
        access_token='github_access_token_123',
        expires_in=3600
    )
    
    print(f"   ✅ GitHub account linked successfully")
    print(f"   🔗 Identity ID: {identity.id}")
    print(f"   🏷️  Provider: {identity.provider}")
    print(f"   👤 Provider User ID: {identity.provider_user_id}")
    print(f"   📧 Provider Email: {identity.provider_email}")
    print(f"   ⭐ Is Primary: {identity.is_primary}")
    print(f"   ✅ Is Verified: {identity.is_verified}")
    
    # Test getting user identities
    print("\n2️⃣ Testing Identity Retrieval...")
    
    identities = UserIdentity.objects.get_user_identities(user)
    assert identities.count() == 1
    print(f"   ✅ Found {identities.count()} linked identity")
    
    primary_identity = UserIdentity.objects.get_primary_identity(user, 'github')
    assert primary_identity == identity
    print(f"   ✅ Primary GitHub identity retrieved")
    
    # Test finding user by provider account
    found_user = UserIdentity.objects.find_user_by_provider_account('github', '123456789')
    assert found_user == user
    print(f"   ✅ User found by provider account")
    
    # Test token management
    print("\n3️⃣ Testing Token Management...")
    
    # Test token expiration
    print(f"   🕐 Token expired: {identity.is_token_expired}")
    
    # Test token retrieval
    access_token = identity.get_access_token()
    assert access_token == 'github_access_token_123'
    print(f"   🔑 Access token retrieved successfully")
    
    # Test updating provider data
    new_data = {'bio': 'Full Stack Developer', 'location': 'San Francisco'}
    identity.update_provider_data(new_data)
    identity.refresh_from_db()
    
    assert 'bio' in identity.provider_data
    print(f"   ✅ Provider data updated successfully")
    
    print("\n" + "="*60)
    print("🎉 Identity system tests passed!")
    print("="*60)

if __name__ == '__main__':
    print("🚀 Starting Comprehensive Enterprise Auth Tests")
    print("="*80)
    
    # Clean up before testing
    cleanup_test_data()
    
    # Run comprehensive tests
    user = test_complete_user_workflow()
    test_user_identity_system()
    
    print("\n" + "="*80)
    print("✨ All comprehensive tests completed successfully!")
    print("🎯 Task 5 implementation is working perfectly!")
    print("="*80)