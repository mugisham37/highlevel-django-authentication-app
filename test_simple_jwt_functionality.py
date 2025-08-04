#!/usr/bin/env python
"""
Simple test to verify JWT functionality works.
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.development')
django.setup()

from django.contrib.auth import get_user_model
from enterprise_auth.core.services.jwt_service import jwt_service, DeviceInfo

User = get_user_model()

def test_jwt_basic_functionality():
    """Test basic JWT functionality."""
    print("Testing basic JWT functionality...")
    
    # Create or get test user
    try:
        user = User.objects.get(email='test@example.com')
    except User.DoesNotExist:
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
    
    print(f"✓ User: {user.email}")
    
    # Create device info
    device_info = DeviceInfo(
        device_id='test-device-123',
        device_fingerprint='test-fingerprint-456',
        device_type='desktop',
        browser='Chrome',
        operating_system='Windows',
        ip_address='192.168.1.100',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    )
    
    print("✓ Device info created")
    
    # Generate token pair
    try:
        token_pair = jwt_service.generate_token_pair(
            user=user,
            device_info=device_info,
            scopes=['read', 'write']
        )
        print("✓ Token pair generated successfully")
        print(f"  Access token: {token_pair.access_token[:50]}...")
        print(f"  Refresh token: {token_pair.refresh_token[:50]}...")
    except Exception as e:
        print(f"❌ Failed to generate token pair: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    # Validate access token
    try:
        validation_result = jwt_service.validate_access_token(
            token_pair.access_token,
            device_info.device_fingerprint
        )
        
        if validation_result.is_valid:
            print("✓ Access token validation successful")
            print(f"  User ID: {validation_result.claims.user_id}")
            print(f"  Email: {validation_result.claims.email}")
            print(f"  Token ID: {validation_result.claims.token_id}")
        else:
            print(f"❌ Access token validation failed: {validation_result.error_message}")
            return False
    except Exception as e:
        print(f"❌ Access token validation error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test token revocation
    try:
        success = jwt_service.revoke_token(token_pair.access_token, 'test_revocation')
        if success:
            print("✓ Token revocation successful")
        else:
            print("❌ Token revocation failed")
            return False
    except Exception as e:
        print(f"❌ Token revocation error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    # Verify token is now invalid
    try:
        validation_result = jwt_service.validate_access_token(
            token_pair.access_token,
            device_info.device_fingerprint
        )
        
        if not validation_result.is_valid:
            print("✓ Revoked token is now invalid")
            print(f"  Status: {validation_result.status.value}")
        else:
            print("❌ Revoked token is still valid")
            return False
    except Exception as e:
        print(f"❌ Revoked token validation error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test user token revocation
    try:
        # Generate new token pair
        token_pair_2 = jwt_service.generate_token_pair(
            user=user,
            device_info=device_info,
            scopes=['read', 'write']
        )
        print("✓ Generated second token pair")
        
        # Revoke all user tokens
        success = jwt_service.revoke_all_user_tokens(str(user.id), 'test_user_revocation')
        if success:
            print("✓ User token revocation successful")
        else:
            print("❌ User token revocation failed")
            return False
        
        # Verify token is now invalid
        validation_result = jwt_service.validate_access_token(
            token_pair_2.access_token,
            device_info.device_fingerprint
        )
        
        if not validation_result.is_valid:
            print("✓ User tokens are now invalid after user revocation")
            print(f"  Status: {validation_result.status.value}")
        else:
            print("❌ User tokens are still valid after user revocation")
            return False
            
    except Exception as e:
        print(f"❌ User token revocation error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n✅ All JWT functionality tests passed!")
    return True

if __name__ == '__main__':
    success = test_jwt_basic_functionality()
    sys.exit(0 if success else 1)