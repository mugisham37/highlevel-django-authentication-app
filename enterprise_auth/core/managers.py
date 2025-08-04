"""
Custom managers for enterprise authentication system.

This module contains custom managers for user models that provide
enhanced functionality for user creation, email verification, and
enterprise features.
"""

import secrets
import string
from typing import Optional, Dict, Any

from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class UserProfileManager(BaseUserManager):
    """
    Custom manager for UserProfile model with email verification workflow.
    
    Provides methods for creating users with proper validation,
    email verification setup, and enterprise features.
    """
    
    def _create_user(self, email: str, password: str, **extra_fields) -> 'UserProfile':
        """
        Create and save a user with the given email and password.
        
        Args:
            email: User's email address
            password: User's password
            **extra_fields: Additional fields for the user
            
        Returns:
            Created UserProfile instance
            
        Raises:
            ValueError: If email is not provided or invalid
            ValidationError: If validation fails
        """
        if not email:
            raise ValueError(_('The Email field must be set'))
        
        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_('Invalid email address format'))
        
        # Normalize email
        email = self.normalize_email(email)
        
        # Validate required fields
        if not extra_fields.get('first_name'):
            raise ValueError(_('First name is required'))
        if not extra_fields.get('last_name'):
            raise ValueError(_('Last name is required'))
        
        # Create user instance
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        
        return user
    
    def create_user(self, email: str, password: str = None, **extra_fields) -> 'UserProfile':
        """
        Create a regular user with email verification workflow.
        
        Args:
            email: User's email address
            password: User's password
            **extra_fields: Additional fields for the user
            
        Returns:
            Created UserProfile instance
        """
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault('is_active', True)  # User is active but email not verified
        
        return self._create_user(email, password, **extra_fields)
    
    def create_superuser(self, email: str, password: str = None, **extra_fields) -> 'UserProfile':
        """
        Create a superuser with all permissions.
        
        Args:
            email: Superuser's email address
            password: Superuser's password
            **extra_fields: Additional fields for the superuser
            
        Returns:
            Created UserProfile instance
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_email_verified', True)  # Superuser email is auto-verified
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        
        return self._create_user(email, password, **extra_fields)
    
    def create_user_with_verification(
        self, 
        email: str, 
        password: str, 
        send_verification: bool = True,
        **extra_fields
    ) -> 'UserProfile':
        """
        Create a user and set up email verification workflow.
        
        Args:
            email: User's email address
            password: User's password
            send_verification: Whether to send verification email
            **extra_fields: Additional fields for the user
            
        Returns:
            Created UserProfile instance with verification token set
        """
        with transaction.atomic():
            user = self.create_user(email, password, **extra_fields)
            
            # Generate and set email verification token
            verification_token = self._generate_verification_token()
            user.set_email_verification_token(verification_token)
            
            if send_verification:
                self._send_verification_email(user, verification_token)
            
            return user
    
    def create_enterprise_user(
        self,
        email: str,
        password: str,
        organization: str,
        department: Optional[str] = None,
        employee_id: Optional[str] = None,
        job_title: Optional[str] = None,
        **extra_fields
    ) -> 'UserProfile':
        """
        Create a user with enterprise profile information.
        
        Args:
            email: User's email address
            password: User's password
            organization: Organization name
            department: Department name
            employee_id: Employee ID
            job_title: Job title
            **extra_fields: Additional fields for the user
            
        Returns:
            Created UserProfile instance with enterprise fields
        """
        extra_fields.update({
            'organization': organization,
            'department': department,
            'employee_id': employee_id,
            'job_title': job_title,
        })
        
        return self.create_user_with_verification(email, password, **extra_fields)
    
    def verify_email(self, user_id: str, token: str) -> bool:
        """
        Verify a user's email address using the verification token.
        
        Args:
            user_id: User's ID
            token: Verification token
            
        Returns:
            True if verification successful, False otherwise
        """
        try:
            user = self.get(id=user_id, is_email_verified=False)
            if user.verify_email_token(token):
                user.mark_email_verified()
                return True
        except self.model.DoesNotExist:
            pass
        
        return False
    
    def resend_verification_email(self, email: str) -> bool:
        """
        Resend verification email to a user.
        
        Args:
            email: User's email address
            
        Returns:
            True if email was sent, False if user not found or already verified
        """
        try:
            user = self.get(email=email, is_email_verified=False)
            
            # Check if we can resend (rate limiting)
            if user.email_verification_sent_at:
                time_since_last = timezone.now() - user.email_verification_sent_at
                if time_since_last.total_seconds() < 300:  # 5 minutes
                    return False
            
            # Generate new token and send email
            verification_token = self._generate_verification_token()
            user.set_email_verification_token(verification_token)
            self._send_verification_email(user, verification_token)
            
            return True
        except self.model.DoesNotExist:
            return False
    
    def get_by_email(self, email: str) -> Optional['UserProfile']:
        """
        Get user by email address.
        
        Args:
            email: Email address to search for
            
        Returns:
            UserProfile instance or None if not found
        """
        try:
            return self.get(email=self.normalize_email(email))
        except self.model.DoesNotExist:
            return None
    
    def get_verified_users(self):
        """
        Get queryset of users with verified email addresses.
        
        Returns:
            QuerySet of verified users
        """
        return self.filter(is_email_verified=True, is_active=True)
    
    def get_enterprise_users(self, organization: Optional[str] = None):
        """
        Get queryset of enterprise users.
        
        Args:
            organization: Filter by organization name
            
        Returns:
            QuerySet of enterprise users
        """
        queryset = self.filter(organization__isnull=False)
        if organization:
            queryset = queryset.filter(organization=organization)
        return queryset
    
    def get_users_by_provider(self, provider: str):
        """
        Get users who have linked accounts with a specific OAuth provider.
        
        Args:
            provider: OAuth provider name
            
        Returns:
            QuerySet of users with the specified provider
        """
        return self.filter(identities__provider=provider).distinct()
    
    def search_users(self, query: str):
        """
        Search users by email, name, or organization.
        
        Args:
            query: Search query string
            
        Returns:
            QuerySet of matching users
        """
        return self.filter(
            models.Q(email__icontains=query) |
            models.Q(first_name__icontains=query) |
            models.Q(last_name__icontains=query) |
            models.Q(organization__icontains=query)
        ).distinct()
    
    def get_locked_accounts(self):
        """
        Get queryset of currently locked accounts.
        
        Returns:
            QuerySet of locked accounts
        """
        return self.filter(
            account_locked_until__isnull=False,
            account_locked_until__gt=timezone.now()
        )
    
    def unlock_expired_accounts(self) -> int:
        """
        Unlock accounts where the lock period has expired.
        
        Returns:
            Number of accounts unlocked
        """
        expired_locks = self.filter(
            account_locked_until__isnull=False,
            account_locked_until__lte=timezone.now()
        )
        
        count = expired_locks.count()
        expired_locks.update(
            account_locked_until=None,
            failed_login_attempts=0
        )
        
        return count
    
    def cleanup_unverified_users(self, days: int = 7) -> int:
        """
        Clean up unverified user accounts older than specified days.
        
        Args:
            days: Number of days after which to clean up unverified accounts
            
        Returns:
            Number of accounts cleaned up
        """
        cutoff_date = timezone.now() - timezone.timedelta(days=days)
        unverified_users = self.filter(
            is_email_verified=False,
            created_at__lt=cutoff_date
        )
        
        count = unverified_users.count()
        unverified_users.delete()
        
        return count
    
    def _generate_verification_token(self) -> str:
        """
        Generate a secure verification token.
        
        Returns:
            Random verification token
        """
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))
    
    def _send_verification_email(self, user: 'UserProfile', token: str) -> None:
        """
        Send verification email to user.
        
        Args:
            user: User to send email to
            token: Verification token
        """
        # Import here to avoid circular imports
        from enterprise_auth.core.tasks.email_tasks import send_verification_email
        
        # Send email asynchronously
        send_verification_email.delay(user.id, token)


class UserIdentityManager(models.Manager):
    """
    Custom manager for UserIdentity model.
    
    Provides methods for managing OAuth provider identities and
    preventing account takeover attacks.
    """
    
    def link_social_account(
        self,
        user: 'UserProfile',
        provider: str,
        provider_user_id: str,
        provider_data: Dict[str, Any],
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        expires_in: Optional[int] = None
    ) -> 'UserIdentity':
        """
        Link a social account to a user with security checks.
        
        Args:
            user: User to link the account to
            provider: OAuth provider name
            provider_user_id: User ID from the provider
            provider_data: Additional data from the provider
            access_token: OAuth access token
            refresh_token: OAuth refresh token
            expires_in: Token expiration time in seconds
            
        Returns:
            Created or updated UserIdentity instance
            
        Raises:
            ValidationError: If account is already linked to another user
        """
        # Check if this provider account is already linked to another user
        existing_identity = self.filter(
            provider=provider,
            provider_user_id=provider_user_id
        ).exclude(user=user).first()
        
        if existing_identity:
            raise ValidationError(
                f"This {provider} account is already linked to another user."
            )
        
        # Get or create the identity
        identity, created = self.get_or_create(
            user=user,
            provider=provider,
            provider_user_id=provider_user_id,
            defaults={
                'provider_username': provider_data.get('username', ''),
                'provider_email': provider_data.get('email', ''),
                'provider_data': provider_data,
                'is_verified': True,  # OAuth accounts are considered verified
            }
        )
        
        # Update tokens if provided
        if access_token:
            identity.set_access_token(access_token, expires_in)
        if refresh_token:
            identity.set_refresh_token(refresh_token)
        
        # Update provider data
        if not created:
            identity.update_provider_data(provider_data)
        
        # Set as primary if it's the first identity for this provider
        if not self.filter(user=user, provider=provider, is_primary=True).exists():
            identity.set_as_primary()
        
        return identity
    
    def unlink_social_account(self, user: 'UserProfile', provider: str) -> bool:
        """
        Unlink a social account from a user.
        
        Args:
            user: User to unlink the account from
            provider: OAuth provider name
            
        Returns:
            True if account was unlinked, False if not found
        """
        try:
            identity = self.get(user=user, provider=provider)
            identity.delete()
            return True
        except self.model.DoesNotExist:
            return False
    
    def get_user_identities(self, user: 'UserProfile'):
        """
        Get all identities for a user.
        
        Args:
            user: User to get identities for
            
        Returns:
            QuerySet of user identities
        """
        return self.filter(user=user).order_by('provider', '-is_primary')
    
    def get_primary_identity(self, user: 'UserProfile', provider: str) -> Optional['UserIdentity']:
        """
        Get the primary identity for a user and provider.
        
        Args:
            user: User to get identity for
            provider: OAuth provider name
            
        Returns:
            Primary UserIdentity or None if not found
        """
        try:
            return self.get(user=user, provider=provider, is_primary=True)
        except self.model.DoesNotExist:
            return None
    
    def find_user_by_provider_account(
        self, 
        provider: str, 
        provider_user_id: str
    ) -> Optional['UserProfile']:
        """
        Find a user by their provider account.
        
        Args:
            provider: OAuth provider name
            provider_user_id: User ID from the provider
            
        Returns:
            UserProfile if found, None otherwise
        """
        try:
            identity = self.get(provider=provider, provider_user_id=provider_user_id)
            return identity.user
        except self.model.DoesNotExist:
            return None
    
    def get_expired_tokens(self):
        """
        Get identities with expired access tokens.
        
        Returns:
            QuerySet of identities with expired tokens
        """
        return self.filter(
            token_expires_at__isnull=False,
            token_expires_at__lt=timezone.now()
        )
    
    def refresh_expired_tokens(self) -> int:
        """
        Refresh expired access tokens where possible.
        
        Returns:
            Number of tokens refreshed
        """
        expired_identities = self.get_expired_tokens().filter(
            refresh_token__isnull=False
        )
        
        refreshed_count = 0
        for identity in expired_identities:
            # Import here to avoid circular imports
            from enterprise_auth.core.services.oauth_service import OAuthService
            
            oauth_service = OAuthService()
            if oauth_service.refresh_token(identity):
                refreshed_count += 1
        
        return refreshed_count
    
    def cleanup_unused_identities(self, days: int = 90) -> int:
        """
        Clean up identities that haven't been used for a specified period.
        
        Args:
            days: Number of days of inactivity before cleanup
            
        Returns:
            Number of identities cleaned up
        """
        cutoff_date = timezone.now() - timezone.timedelta(days=days)
        unused_identities = self.filter(last_used__lt=cutoff_date)
        
        count = unused_identities.count()
        unused_identities.delete()
        
        return count