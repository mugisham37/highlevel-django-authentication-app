"""
Tests for social account linking service.

This module contains comprehensive tests for the social account linking
functionality including secure linking, email verification, anti-takeover
protection, and proper cleanup.
"""

import uuid
from datetime import timedelta
from unittest.mock import Mock, patch

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone

from ..exceptions import (
    ValidationError,
    TokenInvalidError,
    TokenExpiredError,
    OAuthError,
)
from ..models.user import UserIdentity
from ..services.social_account_linking_service import (
    SocialAccountLinkingService,
    social_linking_service,
)

User = get_user_model()


class SocialAccountLinkingServiceTest(TestCase):
    """Test cases for SocialAccountLinkingService."""
    
    def setUp(self):
        """Set up test data."""
        self.service = SocialAccountLinkingService()
        
        # Create test user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            is_email_verified=True,
            username='testuser'
        )
        
        # Create another user for conflict testing
        self.other_user = User.objects.create_user(
            email='other@example.com',
            password='testpass123',
            first_name='Other',
            last_name='User',
            is_email_verified=True,
            username='otheruser'
        )
        
        # Sample provider user data
        self.provider_user_data = {
            'provider_user_id': '12345',
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'profile_picture_url': 'https://example.com/avatar.jpg',
            'verified_email': True,
            'locale': 'en',
            'timezone': 'UTC',
        }
        
        # Sample token data
        self.token_data = {
            'access_token': 'access_token_123',
            'refresh_token': 'refresh_token_123',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'scope': 'read write',
        }
    
    def tearDown(self):
        """Clean up after tests."""
        cache.clear()
    
    def test_validate_linking_request_success(self):
        """Test successful validation of linking request."""
        result = self.service._validate_linking_request(
            self.user, 'google', self.provider_user_data
        )
        
        self.assertTrue(result['valid'])
    
    def test_validate_linking_request_inactive_user(self):
        """Test validation fails for inactive user."""
        self.user.is_active = False
        self.user.save()
        
        result = self.service._validate_linking_request(
            self.user, 'google', self.provider_user_data
        )
        
        self.assertFalse(result['valid'])
        self.assertEqual(result['details']['reason'], 'account_inactive')
    
    def test_validate_linking_request_deleted_user(self):
        """Test validation fails for deleted user."""
        self.user.is_deleted = True
        self.user.save()
        
        result = self.service._validate_linking_request(
            self.user, 'google', self.provider_user_data
        )
        
        self.assertFalse(result['valid'])
        self.assertEqual(result['details']['reason'], 'account_deleted')
    
    @override_settings(MAX_IDENTITIES_PER_PROVIDER=1)
    def test_validate_linking_request_max_provider_identities(self):
        """Test validation fails when max identities per provider exceeded."""
        # Create existing identity for the same provider
        UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='existing_id',
            provider_username='existing_user'
        )
        
        result = self.service._validate_linking_request(
            self.user, 'google', self.provider_user_data
        )
        
        self.assertFalse(result['valid'])
        self.assertEqual(result['details']['reason'], 'max_provider_identities')
    
    @override_settings(MAX_TOTAL_IDENTITIES_PER_USER=1)
    def test_validate_linking_request_max_total_identities(self):
        """Test validation fails when max total identities exceeded."""
        # Create existing identity for different provider
        UserIdentity.objects.create(
            user=self.user,
            provider='github',
            provider_user_id='existing_id',
            provider_username='existing_user'
        )
        
        result = self.service._validate_linking_request(
            self.user, 'google', self.provider_user_data
        )
        
        self.assertFalse(result['valid'])
        self.assertEqual(result['details']['reason'], 'max_total_identities')
    
    def test_validate_linking_request_missing_required_field(self):
        """Test validation fails when required field is missing."""
        invalid_data = self.provider_user_data.copy()
        del invalid_data['provider_user_id']
        
        result = self.service._validate_linking_request(
            self.user, 'google', invalid_data
        )
        
        self.assertFalse(result['valid'])
        self.assertEqual(result['details']['reason'], 'missing_required_field')
        self.assertEqual(result['details']['field'], 'provider_user_id')
    
    def test_find_existing_identity_found(self):
        """Test finding existing identity."""
        # Create existing identity
        identity = UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser'
        )
        
        found_identity = self.service._find_existing_identity('google', '12345')
        
        self.assertEqual(found_identity, identity)
    
    def test_find_existing_identity_not_found(self):
        """Test finding non-existent identity."""
        found_identity = self.service._find_existing_identity('google', '12345')
        
        self.assertIsNone(found_identity)
    
    def test_check_email_conflict_no_conflict(self):
        """Test email conflict check with no conflict."""
        result = self.service._check_email_conflict(self.user, 'test@example.com')
        
        self.assertFalse(result['has_conflict'])
    
    def test_check_email_conflict_belongs_to_other_user(self):
        """Test email conflict when email belongs to another user."""
        result = self.service._check_email_conflict(self.user, 'other@example.com')
        
        self.assertTrue(result['has_conflict'])
        self.assertEqual(result['conflict_type'], 'email_belongs_to_other_user')
    
    def test_check_email_conflict_email_mismatch(self):
        """Test email conflict when emails don't match."""
        result = self.service._check_email_conflict(self.user, 'different@example.com')
        
        self.assertTrue(result['has_conflict'])
        self.assertEqual(result['conflict_type'], 'email_mismatch')
    
    @patch('enterprise_auth.core.services.social_account_linking_service.oauth_service')
    @override_settings(REQUIRE_EMAIL_VERIFICATION_FOR_LINKING=False)
    def test_initiate_account_linking_direct_success(self, mock_oauth_service):
        """Test successful direct account linking without email verification."""
        # Mock OAuth service
        mock_identity = Mock()
        mock_identity.id = uuid.uuid4()
        mock_identity.provider = 'google'
        mock_identity.provider_user_id = '12345'
        mock_identity.provider_username = 'testuser'
        mock_identity.provider_email = 'test@example.com'
        mock_identity.is_primary = False
        mock_identity.is_verified = True
        mock_identity.linked_at = timezone.now()
        
        mock_oauth_service.link_user_identity.return_value = mock_identity
        
        result = self.service.initiate_account_linking(
            user=self.user,
            provider_name='google',
            provider_user_data=self.provider_user_data,
            token_data=self.token_data,
            require_email_verification=False
        )
        
        self.assertEqual(result['status'], 'linked')
        self.assertIn('identity', result)
        mock_oauth_service.link_user_identity.assert_called_once()
    
    def test_initiate_account_linking_already_linked(self):
        """Test account linking when identity is already linked to same user."""
        # Create existing identity
        existing_identity = UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser'
        )
        
        result = self.service.initiate_account_linking(
            user=self.user,
            provider_name='google',
            provider_user_data=self.provider_user_data,
            token_data=self.token_data
        )
        
        self.assertEqual(result['status'], 'already_linked')
        self.assertEqual(result['identity_id'], str(existing_identity.id))
    
    def test_initiate_account_linking_takeover_attempt(self):
        """Test account linking prevents takeover attempts."""
        # Create existing identity linked to different user
        UserIdentity.objects.create(
            user=self.other_user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser'
        )
        
        with self.assertRaises(OAuthError) as context:
            self.service.initiate_account_linking(
                user=self.user,
                provider_name='google',
                provider_user_data=self.provider_user_data,
                token_data=self.token_data
            )
        
        self.assertIn('already linked to another user', str(context.exception))
    
    @patch('enterprise_auth.core.tasks.email_tasks.send_social_linking_verification_email')
    @override_settings(REQUIRE_EMAIL_VERIFICATION_FOR_LINKING=True)
    def test_initiate_account_linking_email_verification(self, mock_email_task):
        """Test account linking initiates email verification."""
        mock_email_task.delay.return_value = Mock(id='task_123')
        
        result = self.service.initiate_account_linking(
            user=self.user,
            provider_name='google',
            provider_user_data=self.provider_user_data,
            token_data=self.token_data
        )
        
        self.assertEqual(result['status'], 'verification_required')
        self.assertIn('verification_token', result)
        self.assertIn('expires_at', result)
        mock_email_task.delay.assert_called_once()
    
    @patch('enterprise_auth.core.services.social_account_linking_service.oauth_service')
    def test_verify_and_complete_linking_success(self, mock_oauth_service):
        """Test successful verification and completion of linking."""
        # Mock OAuth service
        mock_identity = Mock()
        mock_identity.id = uuid.uuid4()
        mock_identity.provider = 'google'
        mock_identity.provider_user_id = '12345'
        mock_identity.provider_username = 'testuser'
        mock_identity.provider_email = 'test@example.com'
        mock_identity.is_primary = False
        mock_identity.is_verified = True
        mock_identity.linked_at = timezone.now()
        
        mock_oauth_service.link_user_identity.return_value = mock_identity
        
        # Store linking data in cache
        linking_token = self.service.generate_linking_token()
        linking_data = {
            'user_id': str(self.user.id),
            'provider_name': 'google',
            'provider_user_data': self.provider_user_data,
            'token_data': self.token_data,
            'created_at': timezone.now().isoformat(),
            'expires_at': (timezone.now() + timedelta(hours=1)).isoformat()
        }
        
        from ..utils.encryption import encrypt_sensitive_data
        cache_key = f'social_linking:{linking_token}'
        cache.set(cache_key, encrypt_sensitive_data(linking_data), timeout=3600)
        
        result = self.service.verify_and_complete_linking(
            user_id=str(self.user.id),
            linking_token=linking_token
        )
        
        self.assertEqual(result['status'], 'linked')
        self.assertIn('identity', result)
        mock_oauth_service.link_user_identity.assert_called_once()
        
        # Verify cache is cleaned up
        self.assertIsNone(cache.get(cache_key))
    
    def test_verify_and_complete_linking_invalid_token(self):
        """Test verification fails with invalid token."""
        with self.assertRaises(TokenInvalidError):
            self.service.verify_and_complete_linking(
                user_id=str(self.user.id),
                linking_token='invalid_token'
            )
    
    def test_verify_and_complete_linking_expired_token(self):
        """Test verification fails with expired token."""
        # Store expired linking data in cache
        linking_token = self.service.generate_linking_token()
        linking_data = {
            'user_id': str(self.user.id),
            'provider_name': 'google',
            'provider_user_data': self.provider_user_data,
            'token_data': self.token_data,
            'created_at': (timezone.now() - timedelta(hours=2)).isoformat(),
            'expires_at': (timezone.now() - timedelta(hours=1)).isoformat()
        }
        
        from ..utils.encryption import encrypt_sensitive_data
        cache_key = f'social_linking:{linking_token}'
        cache.set(cache_key, encrypt_sensitive_data(linking_data), timeout=3600)
        
        with self.assertRaises(TokenExpiredError):
            self.service.verify_and_complete_linking(
                user_id=str(self.user.id),
                linking_token=linking_token
            )
        
        # Verify cache is cleaned up
        self.assertIsNone(cache.get(cache_key))
    
    def test_verify_and_complete_linking_user_mismatch(self):
        """Test verification fails with user ID mismatch."""
        # Store linking data with different user ID
        linking_token = self.service.generate_linking_token()
        linking_data = {
            'user_id': str(self.other_user.id),
            'provider_name': 'google',
            'provider_user_data': self.provider_user_data,
            'token_data': self.token_data,
            'created_at': timezone.now().isoformat(),
            'expires_at': (timezone.now() + timedelta(hours=1)).isoformat()
        }
        
        from ..utils.encryption import encrypt_sensitive_data
        cache_key = f'social_linking:{linking_token}'
        cache.set(cache_key, encrypt_sensitive_data(linking_data), timeout=3600)
        
        with self.assertRaises(TokenInvalidError):
            self.service.verify_and_complete_linking(
                user_id=str(self.user.id),
                linking_token=linking_token
            )
    
    @patch('enterprise_auth.core.services.social_account_linking_service.oauth_service')
    def test_unlink_social_account_success(self, mock_oauth_service):
        """Test successful social account unlinking."""
        # Create identity to unlink
        identity = UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser',
            provider_email='test@example.com'
        )
        
        # Mock OAuth service
        mock_provider = Mock()
        mock_oauth_service.get_provider.return_value = mock_provider
        
        result = self.service.unlink_social_account(
            user=self.user,
            provider_name='google'
        )
        
        self.assertEqual(result['status'], 'unlinked')
        self.assertIn('unlinked_identity', result)
        
        # Verify identity is deleted
        self.assertFalse(UserIdentity.objects.filter(id=identity.id).exists())
    
    def test_unlink_social_account_not_found(self):
        """Test unlinking non-existent social account."""
        result = self.service.unlink_social_account(
            user=self.user,
            provider_name='google'
        )
        
        self.assertEqual(result['status'], 'not_found')
    
    def test_unlink_social_account_last_auth_method(self):
        """Test unlinking fails when it's the last authentication method."""
        # Create identity (only auth method)
        UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser'
        )
        
        # Remove password
        self.user.password = ''
        self.user.save()
        
        with self.assertRaises(ValidationError) as context:
            self.service.unlink_social_account(
                user=self.user,
                provider_name='google'
            )
        
        self.assertIn('last authentication method', str(context.exception))
    
    def test_get_user_linked_accounts(self):
        """Test getting user's linked accounts."""
        # Create multiple identities
        identity1 = UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser1',
            is_primary=True
        )
        
        identity2 = UserIdentity.objects.create(
            user=self.user,
            provider='github',
            provider_user_id='67890',
            provider_username='testuser2'
        )
        
        linked_accounts = self.service.get_user_linked_accounts(self.user)
        
        self.assertEqual(len(linked_accounts), 2)
        
        # Check first account (should be ordered by last_used desc)
        account1 = linked_accounts[0]
        self.assertEqual(account1['provider'], 'github')
        self.assertEqual(account1['provider_user_id'], '67890')
        self.assertTrue(account1['can_unlink'])
        
        account2 = linked_accounts[1]
        self.assertEqual(account2['provider'], 'google')
        self.assertEqual(account2['provider_user_id'], '12345')
        self.assertTrue(account2['can_unlink'])
    
    def test_can_unlink_identity_with_password(self):
        """Test can unlink identity when user has password."""
        identity = UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser'
        )
        
        can_unlink = self.service._can_unlink_identity(self.user, identity)
        
        self.assertTrue(can_unlink)
    
    def test_can_unlink_identity_multiple_identities(self):
        """Test can unlink identity when user has multiple identities."""
        identity1 = UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser1'
        )
        
        identity2 = UserIdentity.objects.create(
            user=self.user,
            provider='github',
            provider_user_id='67890',
            provider_username='testuser2'
        )
        
        can_unlink = self.service._can_unlink_identity(self.user, identity1)
        
        self.assertTrue(can_unlink)
    
    def test_cannot_unlink_last_identity_without_password(self):
        """Test cannot unlink last identity when user has no password."""
        identity = UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser'
        )
        
        # Remove password
        self.user.password = ''
        self.user.save()
        
        can_unlink = self.service._can_unlink_identity(self.user, identity)
        
        self.assertFalse(can_unlink)
    
    def test_get_linking_statistics(self):
        """Test getting linking statistics."""
        # Create test data
        UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='12345',
            provider_username='testuser1',
            is_verified=True,
            is_primary=True
        )
        
        UserIdentity.objects.create(
            user=self.user,
            provider='github',
            provider_user_id='67890',
            provider_username='testuser2',
            is_verified=False
        )
        
        UserIdentity.objects.create(
            user=self.other_user,
            provider='google',
            provider_user_id='11111',
            provider_username='otheruser'
        )
        
        stats = self.service.get_linking_statistics()
        
        self.assertEqual(stats['total_identities'], 3)
        self.assertEqual(stats['verified_identities'], 1)
        self.assertEqual(stats['primary_identities'], 1)
        self.assertEqual(stats['users_with_multiple_identities'], 1)
        self.assertEqual(len(stats['provider_breakdown']), 2)
    
    def test_generate_linking_token(self):
        """Test linking token generation."""
        token1 = self.service.generate_linking_token()
        token2 = self.service.generate_linking_token()
        
        self.assertIsInstance(token1, str)
        self.assertIsInstance(token2, str)
        self.assertNotEqual(token1, token2)
        self.assertGreater(len(token1), 50)  # Should be reasonably long


class SocialAccountLinkingIntegrationTest(TestCase):
    """Integration tests for social account linking."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            is_email_verified=True,
            username='testuser'
        )
    
    def test_full_linking_workflow_with_verification(self):
        """Test complete linking workflow with email verification."""
        # This would be an integration test that tests the full workflow
        # from initiation through email verification to completion
        pass
    
    def test_full_unlinking_workflow(self):
        """Test complete unlinking workflow with cleanup."""
        # This would test the full unlinking process including
        # token revocation and audit logging
        pass