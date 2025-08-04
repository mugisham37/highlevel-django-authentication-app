#!/usr/bin/env python
"""
Simple test script to verify user registration functionality.
"""

import os
import sys
import django
import json
from django.test import Client
from django.urls import reverse

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.development')
django.setup()

def test_user_registration():
    """Test user registration API endpoint."""
    client = Client()
    
    # Test data
    registration_data = {
        'email': 'test@example.com',
        'first_name': 'John',
        'last_name': 'Doe',
        'password': 'SecurePassword123!',
        'password_confirm': 'SecurePassword123!',
        'terms_accepted': True,
        'privacy_policy_accepted': True,
        'organization': 'Test Company',
        'department': 'Engineering',
        'employee_id': 'EMP001',
        'job_title': 'Software Engineer',
    }
    
    print("Testing user registration...")
    print(f"Registration data: {json.dumps(registration_data, indent=2)}")
    
    try:
        # Make POST request to registration endpoint
        response = client.post(
            '/api/v1/core/auth/register/',
            data=json.dumps(registration_data),
            content_type='application/json'
        )
        
        print(f"\nResponse status: {response.status_code}")
        print(f"Response data: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 201:
            print("\n✅ User registration successful!")
            
            # Test getting user profile
            from enterprise_auth.core.models import UserProfile
            user = UserProfile.objects.get(email='test@example.com')
            print(f"\n📋 Created user details:")
            print(f"   ID: {user.id}")
            print(f"   Email: {user.email}")
            print(f"   Full name: {user.get_full_name()}")
            print(f"   Organization: {user.organization}")
            print(f"   Department: {user.department}")
            print(f"   Employee ID: {user.employee_id}")
            print(f"   Email verified: {user.is_email_verified}")
            print(f"   Has enterprise profile: {user.has_enterprise_profile}")
            
        else:
            print(f"\n❌ User registration failed with status {response.status_code}")
            
    except Exception as e:
        print(f"\n❌ Error during registration test: {e}")
        import traceback
        traceback.print_exc()

def test_email_verification():
    """Test email verification functionality."""
    print("\n" + "="*50)
    print("Testing email verification...")
    
    try:
        from enterprise_auth.core.models import UserProfile
        user = UserProfile.objects.get(email='test@example.com')
        
        # Generate verification token
        import secrets
        import string
        token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        user.set_email_verification_token(token)
        
        print(f"Generated verification token: {token}")
        
        # Test verification
        client = Client()
        verification_data = {
            'user_id': str(user.id),
            'token': token
        }
        
        response = client.post(
            '/api/v1/core/auth/verify-email/',
            data=json.dumps(verification_data),
            content_type='application/json'
        )
        
        print(f"Verification response status: {response.status_code}")
        print(f"Verification response data: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✅ Email verification successful!")
            
            # Check if user is now verified
            user.refresh_from_db()
            print(f"User email verified: {user.is_email_verified}")
        else:
            print(f"❌ Email verification failed with status {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error during verification test: {e}")
        import traceback
        traceback.print_exc()

def test_user_profile_api():
    """Test user profile API endpoints."""
    print("\n" + "="*50)
    print("Testing user profile API...")
    
    try:
        from enterprise_auth.core.models import UserProfile
        user = UserProfile.objects.get(email='test@example.com')
        
        # Create a client and force login
        client = Client()
        client.force_login(user)
        
        # Test profile retrieval (use 'me' as a special endpoint)
        response = client.get('/api/v1/core/user/profile/me/')
        
        print(f"Profile retrieval status: {response.status_code}")
        if response.status_code == 200:
            print(f"Profile data: {json.dumps(response.json(), indent=2)}")
            print("✅ Profile retrieval successful!")
        else:
            print(f"❌ Profile retrieval failed with status {response.status_code}")
            
        # Test profile update
        update_data = {
            'job_title': 'Senior Software Engineer',
            'timezone': 'America/New_York'
        }
        
        response = client.patch(
            '/api/v1/core/user/profile/me/',
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        print(f"\nProfile update status: {response.status_code}")
        if response.status_code == 200:
            print(f"Updated profile data: {json.dumps(response.json(), indent=2)}")
            print("✅ Profile update successful!")
        else:
            print(f"❌ Profile update failed with status {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error during profile API test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    print("🚀 Starting Enterprise Auth User Registration Tests")
    print("="*60)
    
    test_user_registration()
    test_email_verification()
    test_user_profile_api()
    
    print("\n" + "="*60)
    print("✨ Tests completed!")