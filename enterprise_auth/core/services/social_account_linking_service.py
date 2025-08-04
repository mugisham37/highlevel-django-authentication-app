"""
Social account linking service for enterprise authentication system.

This service provides secure social account linking functionality with email verification,
anti-takeover protection, and comprehensive audit logging.
"""

import logging
import secrets
from typing import Dict, List, Optional, Tuple
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from ..exceptions import (
    OAuthError,
    ValidationError,
    AuthenticationError,
    TokenExpiredError,
    TokenInvalidError,
    RateLimitExceededError,
)
from ..models.user import UserIdentity
from ..services.oauth_service import oauth_service
from ..services.email_verification_service import EmailVerificationService
from ..services.audit_service import audit_service
from ..utils.encryption import encrypt_sensitive_data, decrypt_sensitive_data

User = get_user_model()
logger = logging.getLogger(__name__)


class SocialAccountLinkingService:
    """
    Service for managing secure social account linking operations.
    
    Provides functionality for linking and unlinking OAuth provider accounts
    with comprehensive security measures including email verification,
    anti-takeover protection, and audit logging.
    """
    
    def __init__(self):
        """Initialize social account linking service."""
        self.email_verification_service = EmailVerificationService()
        self.linking_token_expiry_hours = getattr(settings, 'SOCIAL_LINKING_TOKEN_EXPIRY_HOURS', 1)
        self.max_identities_per_provider = getattr(settings, 'MAX_IDENTITIES_PER_PROVIDER', 1)
        self.max_total_identities = getattr(settings, 'MAX_TOTAL_IDENTITIES_PER_USER', 10)
        self.require_email_verification = getattr(settings, 'REQUIRE_EMAIL_VERIFICATION_FOR_LINKING', True)
    
    def generate_linking_token(self) -> str:
        """
        Generate a cryptographically secure linking token.
        
        Returns:
            Secure random token string
        """
        return secrets.token_urlsafe(64)
    
    @transaction.atomic
    def initiate_account_linking(
        self,
        user: User,
        provider_name: str,
        provider_user_data: Dict,
        token_data: Dict,
        require_email_verification: Optional[bool] = None
    ) -> Dict:
        """
        Initiate secure account linking process.
        
        Args:
            user: User to link account to
            provider_name: OAuth provider name
            provider_user_data: Normalized user data from provider
            token_data: OAuth token data
            require_email_verification: Override email verification requirement
            
        Returns:
            Dictionary with linking status and next steps
            
        Raises:
            OAuthError: If linking cannot be initiated
            ValidationError: If validation fails
        """
        # Check if email verification is required
        needs_verification = (
            require_email_verification 
            if require_email_verification is not None 
            else self.require_email_verification
        )
        
        # Validate linking request
        validation_result = self._validate_linking_request(
            user, provider_name, provider_user_data
        )
        
        if not validation_result['valid']:
            raise ValidationError(
                validation_result['message'],
                details=validation_result.get('details', {})
            )
        
        # Check for existing identity with same provider user ID
        existing_identity = self._find_existing_identity(
            provider_name, provider_user_data['provider_user_id']
        )
        
        if existing_identity:
            if existing_identity.user == user:
                # Identity already linked to this user
                logger.info(
                    f"Account linking attempted for already linked identity",
                    extra={
                        'user_id': user.id,
                        'provider': provider_name,
                        'provider_user_id': provider_user_data['provider_user_id']
                    }
                )
                return {
                    'status': 'already_linked',
                    'message': _('This account is already linked to your profile'),
                    'identity_id': str(existing_identity.id),
                    'linked_at': existing_identity.linked_at.isoformat()
                }
            else:
                # Identity linked to different user - potential takeover attempt
                logger.warning(
                    f"Account linking attempted for identity linked to different user",
                    extra={
                        'requesting_user_id': user.id,
                        'existing_user_id': existing_identity.user.id,
                        'provider': provider_name,
                        'provider_user_id': provider_user_data['provider_user_id']
                    }
                )
                
                # Audit the takeover attempt
                audit_service.log_authentication_event(
                    event_type='account_takeover_attempt',
                    user=user,
                    description=f'Attempted to link {provider_name} account already linked to another user',
                    severity='high',
                    metadata={
                        'provider': provider_name,
                        'provider_user_id': provider_user_data['provider_user_id'],
                        'existing_user_id': str(existing_identity.user.id),
                        'provider_email': provider_user_data.get('email')
                    }
                )
                
                raise OAuthError(
                    _('This social account is already linked to another user'),
                    details={
                        'reason': 'account_already_linked',
                        'provider': provider_name
                    }
                )
        
        # Check email conflict for anti-takeover protection
        if provider_user_data.get('email'):
            email_conflict = self._check_email_conflict(
                user, provider_user_data['email']
            )
            
            if email_conflict['has_conflict']:
                logger.warning(
                    f"Email conflict detected during account linking",
                    extra={
                        'user_id': user.id,
                        'provider': provider_name,
                        'provider_email': provider_user_data['email'],
                        'conflict_type': email_conflict['conflict_type']
                    }
                )
                
                # Audit the email conflict
                audit_service.log_authentication_event(
                    event_type='email_conflict_linking',
                    user=user,
                    description=f'Email conflict detected during {provider_name} account linking',
                    severity='medium',
                    metadata={
                        'provider': provider_name,
                        'provider_email': provider_user_data['email'],
                        'conflict_type': email_conflict['conflict_type'],
                        'user_email': user.email
                    }
                )
                
                if needs_verification:
                    # Require email verification to proceed
                    return self._initiate_email_verification_linking(
                        user, provider_name, provider_user_data, token_data
                    )
                else:
                    raise ValidationError(
                        _('Email address conflict detected. Please verify your email to proceed.'),
                        details={'conflict_type': email_conflict['conflict_type']}
                    )
        
        # Proceed with direct linking if no verification needed
        if not needs_verification:
            return self._complete_account_linking(
                user, provider_name, provider_user_data, token_data
            )
        
        # Initiate email verification process
        return self._initiate_email_verification_linking(
            user, provider_name, provider_user_data, token_data
        )
    
    def _validate_linking_request(
        self, 
        user: User, 
        provider_name: str, 
        provider_user_data: Dict
    ) -> Dict:
        """
        Validate account linking request.
        
        Args:
            user: User requesting linking
            provider_name: OAuth provider name
            provider_user_data: Provider user data
            
        Returns:
            Dictionary with validation result
        """
        # Check if user account is active
        if not user.is_active:
            return {
                'valid': False,
                'message': _('User account is not active'),
                'details': {'reason': 'account_inactive'}
            }
        
        # Check if user is deleted
        if getattr(user, 'is_deleted', False):
            return {
                'valid': False,
                'message': _('User account is deleted'),
                'details': {'reason': 'account_deleted'}
            }
        
        # Check maximum identities per provider
        existing_count = UserIdentity.objects.filter(
            user=user,
            provider=provider_name
        ).count()
        
        if existing_count >= self.max_identities_per_provider:
            return {
                'valid': False,
                'message': _('Maximum number of accounts for this provider already linked'),
                'details': {
                    'reason': 'max_provider_identities',
                    'max_allowed': self.max_identities_per_provider,
                    'current_count': existing_count
                }
            }
        
        # Check maximum total identities
        total_identities = UserIdentity.objects.filter(user=user).count()
        
        if total_identities >= self.max_total_identities:
            return {
                'valid': False,
                'message': _('Maximum number of linked accounts reached'),
                'details': {
                    'reason': 'max_total_identities',
                    'max_allowed': self.max_total_identities,
                    'current_count': total_identities
                }
            }
        
        # Validate provider user data
        required_fields = ['provider_user_id']
        for field in required_fields:
            if not provider_user_data.get(field):
                return {
                    'valid': False,
                    'message': _('Invalid provider user data'),
                    'details': {'reason': 'missing_required_field', 'field': field}
                }
        
        return {'valid': True}
    
    def _find_existing_identity(
        self, 
        provider_name: str, 
        provider_user_id: str
    ) -> Optional[UserIdentity]:
        """
        Find existing identity by provider and user ID.
        
        Args:
            provider_name: OAuth provider name
            provider_user_id: Provider's user ID
            
        Returns:
            UserIdentity if found, None otherwise
        """
        try:
            return UserIdentity.objects.select_related('user').get(
                provider=provider_name,
                provider_user_id=provider_user_id
            )
        except UserIdentity.DoesNotExist:
            return None
    
    def _check_email_conflict(self, user: User, provider_email: str) -> Dict:
        """
        Check for email conflicts that could indicate takeover attempts.
        
        Args:
            user: User requesting linking
            provider_email: Email from OAuth provider
            
        Returns:
            Dictionary with conflict information
        """
        if not provider_email:
            return {'has_conflict': False}
        
        provider_email = provider_email.lower().strip()
        user_email = user.email.lower().strip()
        
        # Check if provider email matches user email
        if provider_email == user_email:
            return {'has_conflict': False}
        
        # Check if provider email belongs to another user
        try:
            other_user = User.objects.get(
                email=provider_email,
                is_deleted=False
            )
            
            if other_user != user:
                return {
                    'has_conflict': True,
                    'conflict_type': 'email_belongs_to_other_user',
                    'provider_email': provider_email,
                    'user_email': user_email
                }
        except User.DoesNotExist:
            pass
        
        # Check if user email differs significantly from provider email
        # This could indicate a potential takeover attempt
        return {
            'has_conflict': True,
            'conflict_type': 'email_mismatch',
            'provider_email': provider_email,
            'user_email': user_email
        }
    
    def _initiate_email_verification_linking(
        self,
        user: User,
        provider_name: str,
        provider_user_data: Dict,
        token_data: Dict
    ) -> Dict:
        """
        Initiate email verification process for account linking.
        
        Args:
            user: User requesting linking
            provider_name: OAuth provider name
            provider_user_data: Provider user data
            token_data: OAuth token data
            
        Returns:
            Dictionary with verification initiation status
        """
        # Generate linking token
        linking_token = self.generate_linking_token()
        
        # Store linking data temporarily (encrypted)
        linking_data = {
            'user_id': str(user.id),
            'provider_name': provider_name,
            'provider_user_data': provider_user_data,
            'token_data': token_data,
            'created_at': timezone.now().isoformat(),
            'expires_at': (timezone.now() + timedelta(hours=self.linking_token_expiry_hours)).isoformat()
        }
        
        # Store in cache with expiration
        from django.core.cache import cache
        cache_key = f'social_linking:{linking_token}'
        cache.set(
            cache_key,
            encrypt_sensitive_data(linking_data),
            timeout=self.linking_token_expiry_hours * 3600
        )
        
        # Send verification email
        from ..tasks.email_tasks import send_social_linking_verification_email
        send_social_linking_verification_email.delay(
            str(user.id),
            provider_name,
            linking_token,
            provider_user_data.get('email', ''),
            provider_user_data.get('username', '')
        )
        
        logger.info(
            f"Email verification initiated for social account linking",
            extra={
                'user_id': user.id,
                'provider': provider_name,
                'provider_user_id': provider_user_data['provider_user_id']
            }
        )
        
        return {
            'status': 'verification_required',
            'message': _('Email verification required. Please check your email and click the verification link.'),
            'verification_token': linking_token,
            'expires_at': linking_data['expires_at'],
            'provider': provider_name
        }
    
    @transaction.atomic
    def verify_and_complete_linking(
        self,
        user_id: str,
        linking_token: str
    ) -> Dict:
        """
        Verify email and complete account linking.
        
        Args:
            user_id: User ID
            linking_token: Linking verification token
            
        Returns:
            Dictionary with linking completion status
            
        Raises:
            TokenInvalidError: If token is invalid
            TokenExpiredError: If token is expired
        """
        # Retrieve linking data from cache
        from django.core.cache import cache
        cache_key = f'social_linking:{linking_token}'
        encrypted_data = cache.get(cache_key)
        
        if not encrypted_data:
            logger.warning(f"Invalid or expired linking token: {linking_token}")
            raise TokenInvalidError(_('Invalid or expired verification token'))
        
        try:
            linking_data = decrypt_sensitive_data(encrypted_data)
        except Exception as e:
            logger.error(f"Failed to decrypt linking data: {e}")
            raise TokenInvalidError(_('Invalid verification token'))
        
        # Validate token data
        if linking_data.get('user_id') != user_id:
            logger.warning(f"User ID mismatch in linking token: {linking_token}")
            raise TokenInvalidError(_('Invalid verification token'))
        
        # Check expiration
        expires_at = timezone.datetime.fromisoformat(linking_data['expires_at'].replace('Z', '+00:00'))
        if timezone.now() > expires_at:
            logger.warning(f"Expired linking token: {linking_token}")
            cache.delete(cache_key)
            raise TokenExpiredError(_('Verification token has expired'))
        
        # Get user
        try:
            user = User.objects.get(id=user_id, is_deleted=False)
        except User.DoesNotExist:
            logger.warning(f"User not found for linking verification: {user_id}")
            raise TokenInvalidError(_('Invalid verification token'))
        
        # Complete the linking
        result = self._complete_account_linking(
            user,
            linking_data['provider_name'],
            linking_data['provider_user_data'],
            linking_data['token_data']
        )
        
        # Clean up cache
        cache.delete(cache_key)
        
        logger.info(
            f"Social account linking completed via email verification",
            extra={
                'user_id': user.id,
                'provider': linking_data['provider_name'],
                'identity_id': result.get('identity_id')
            }
        )
        
        return result
    
    @transaction.atomic
    def _complete_account_linking(
        self,
        user: User,
        provider_name: str,
        provider_user_data: Dict,
        token_data: Dict
    ) -> Dict:
        """
        Complete the account linking process.
        
        Args:
            user: User to link account to
            provider_name: OAuth provider name
            provider_user_data: Provider user data
            token_data: OAuth token data
            
        Returns:
            Dictionary with linking completion status
        """
        # Create normalized user data object
        from ..services.oauth_provider import NormalizedUserData, TokenData
        
        normalized_data = NormalizedUserData(
            provider_user_id=provider_user_data['provider_user_id'],
            email=provider_user_data.get('email'),
            username=provider_user_data.get('username'),
            first_name=provider_user_data.get('first_name'),
            last_name=provider_user_data.get('last_name'),
            profile_picture_url=provider_user_data.get('profile_picture_url'),
            verified_email=provider_user_data.get('verified_email', False),
            locale=provider_user_data.get('locale'),
            timezone=provider_user_data.get('timezone'),
            raw_data=provider_user_data
        )
        
        token_obj = TokenData(
            access_token=token_data.get('access_token'),
            refresh_token=token_data.get('refresh_token'),
            expires_in=token_data.get('expires_in'),
            token_type=token_data.get('token_type', 'Bearer'),
            scope=token_data.get('scope')
        )
        
        # Link the identity
        identity = oauth_service.link_user_identity(
            user=user,
            provider_name=provider_name,
            token_data=token_obj,
            user_data=normalized_data,
            is_primary=False  # Linked accounts are not primary by default
        )
        
        # Audit the successful linking
        audit_service.log_authentication_event(
            event_type='social_account_linked',
            user=user,
            description=f'Successfully linked {provider_name} account',
            severity='low',
            metadata={
                'provider': provider_name,
                'provider_user_id': provider_user_data['provider_user_id'],
                'provider_email': provider_user_data.get('email'),
                'identity_id': str(identity.id)
            }
        )
        
        return {
            'status': 'linked',
            'message': _('Social account linked successfully'),
            'identity': {
                'id': str(identity.id),
                'provider': identity.provider,
                'provider_user_id': identity.provider_user_id,
                'provider_username': identity.provider_username,
                'provider_email': identity.provider_email,
                'is_primary': identity.is_primary,
                'is_verified': identity.is_verified,
                'linked_at': identity.linked_at.isoformat()
            }
        }
    
    @transaction.atomic
    def unlink_social_account(
        self,
        user: User,
        provider_name: str,
        identity_id: Optional[str] = None
    ) -> Dict:
        """
        Unlink social account from user with proper cleanup.
        
        Args:
            user: User to unlink account from
            provider_name: OAuth provider name
            identity_id: Specific identity ID to unlink (optional)
            
        Returns:
            Dictionary with unlinking status
            
        Raises:
            ValidationError: If unlinking is not allowed
        """
        # Find identity to unlink
        query_filters = {'user': user, 'provider': provider_name}
        if identity_id:
            query_filters['id'] = identity_id
        
        try:
            identity = UserIdentity.objects.get(**query_filters)
        except UserIdentity.DoesNotExist:
            logger.warning(
                f"Attempted to unlink non-existent identity",
                extra={
                    'user_id': user.id,
                    'provider': provider_name,
                    'identity_id': identity_id
                }
            )
            return {
                'status': 'not_found',
                'message': _('Social account not found or not linked to your account')
            }
        
        # Check if this is the only authentication method
        user_identities_count = UserIdentity.objects.filter(user=user).count()
        has_password = bool(user.password)
        
        if user_identities_count == 1 and not has_password:
            logger.warning(
                f"Attempted to unlink last authentication method",
                extra={
                    'user_id': user.id,
                    'provider': provider_name,
                    'identity_id': str(identity.id)
                }
            )
            
            raise ValidationError(
                _('Cannot unlink the last authentication method. Please set a password or link another account first.'),
                details={'reason': 'last_auth_method'}
            )
        
        # Store identity info for audit log
        identity_info = {
            'id': str(identity.id),
            'provider': identity.provider,
            'provider_user_id': identity.provider_user_id,
            'provider_username': identity.provider_username,
            'provider_email': identity.provider_email,
            'linked_at': identity.linked_at.isoformat(),
            'last_used': identity.last_used.isoformat() if identity.last_used else None
        }
        
        # Revoke OAuth tokens if possible
        try:
            access_token = identity.get_access_token()
            if access_token:
                provider = oauth_service.get_provider(provider_name)
                provider.revoke_token(access_token)
                logger.info(f"Revoked OAuth tokens for unlinked identity: {identity.id}")
        except Exception as e:
            logger.warning(
                f"Failed to revoke OAuth tokens during unlinking: {e}",
                extra={
                    'identity_id': str(identity.id),
                    'provider': provider_name
                }
            )
        
        # Delete the identity
        identity.delete()
        
        # Audit the unlinking
        audit_service.log_authentication_event(
            event_type='social_account_unlinked',
            user=user,
            description=f'Successfully unlinked {provider_name} account',
            severity='low',
            metadata={
                'provider': provider_name,
                'identity_info': identity_info
            }
        )
        
        logger.info(
            f"Social account unlinked successfully",
            extra={
                'user_id': user.id,
                'provider': provider_name,
                'identity_id': identity_info['id']
            }
        )
        
        return {
            'status': 'unlinked',
            'message': _('Social account unlinked successfully'),
            'unlinked_identity': identity_info
        }
    
    def get_user_linked_accounts(self, user: User) -> List[Dict]:
        """
        Get all linked social accounts for a user.
        
        Args:
            user: User to get linked accounts for
            
        Returns:
            List of linked account information
        """
        identities = UserIdentity.objects.filter(user=user).order_by('-last_used')
        
        linked_accounts = []
        for identity in identities:
            linked_accounts.append({
                'id': str(identity.id),
                'provider': identity.provider,
                'provider_user_id': identity.provider_user_id,
                'provider_username': identity.provider_username,
                'provider_email': identity.provider_email,
                'is_primary': identity.is_primary,
                'is_verified': identity.is_verified,
                'linked_at': identity.linked_at.isoformat(),
                'last_used': identity.last_used.isoformat() if identity.last_used else None,
                'can_unlink': self._can_unlink_identity(user, identity)
            })
        
        return linked_accounts
    
    def _can_unlink_identity(self, user: User, identity: UserIdentity) -> bool:
        """
        Check if an identity can be unlinked.
        
        Args:
            user: User who owns the identity
            identity: Identity to check
            
        Returns:
            True if identity can be unlinked
        """
        # Count total authentication methods
        user_identities_count = UserIdentity.objects.filter(user=user).count()
        has_password = bool(user.password)
        
        # Must have at least one other authentication method
        return user_identities_count > 1 or has_password
    
    def get_linking_statistics(self) -> Dict:
        """
        Get social account linking statistics for monitoring.
        
        Returns:
            Dictionary with linking statistics
        """
        try:
            from django.db.models import Count, Q
            
            # Get linking statistics
            stats = UserIdentity.objects.aggregate(
                total_identities=Count('id'),
                verified_identities=Count('id', filter=Q(is_verified=True)),
                primary_identities=Count('id', filter=Q(is_primary=True))
            )
            
            # Get provider breakdown
            provider_stats = list(
                UserIdentity.objects.values('provider')
                .annotate(count=Count('id'))
                .order_by('-count')
            )
            
            # Get users with multiple identities
            users_with_multiple = User.objects.annotate(
                identity_count=Count('identities')
            ).filter(identity_count__gt=1).count()
            
            return {
                'total_identities': stats['total_identities'],
                'verified_identities': stats['verified_identities'],
                'primary_identities': stats['primary_identities'],
                'users_with_multiple_identities': users_with_multiple,
                'provider_breakdown': provider_stats,
                'max_identities_per_provider': self.max_identities_per_provider,
                'max_total_identities': self.max_total_identities,
                'generated_at': timezone.now().isoformat()
            }
            
        except Exception as exc:
            logger.error(f"Failed to generate linking statistics: {exc}")
            return {
                'error': 'Failed to generate statistics',
                'generated_at': timezone.now().isoformat()
            }


# Global social account linking service instance
social_linking_service = SocialAccountLinkingService()