"""
Authentication views for enterprise authentication system.

This module contains API views for user registration, email verification,
and profile management with comprehensive validation and security features.
"""

from typing import Dict, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from rest_framework.mixins import CreateModelMixin, RetrieveModelMixin, UpdateModelMixin

from ..models import UserProfile, UserIdentity
from ..serializers import (
    UserRegistrationSerializer,
    UserProfileSerializer,
    UserIdentitySerializer,
    EmailVerificationSerializer,
    ResendVerificationSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    PasswordStrengthCheckSerializer,
)

User = get_user_model()


class UserRegistrationView(APIView):
    """
    API view for user registration with comprehensive validation.
    
    Handles user registration with email verification workflow,
    enterprise profile information, and security features.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request: Request) -> Response:
        """
        Register a new user account.
        
        Args:
            request: HTTP request with registration data
            
        Returns:
            Response with registration status and user information
        """
        serializer = UserRegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Create user with verification workflow
                user = serializer.save()
                
                # Prepare response data
                response_data = {
                    'message': _('Registration successful. Please check your email for verification instructions.'),
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'full_name': user.get_full_name(),
                        'is_email_verified': user.is_email_verified,
                        'has_enterprise_profile': user.has_enterprise_profile,
                    },
                    'next_steps': [
                        _('Check your email for a verification link'),
                        _('Click the verification link to activate your account'),
                        _('Complete your profile setup if needed'),
                    ]
                }
                
                return Response(
                    response_data,
                    status=status.HTTP_201_CREATED
                )
                
            except Exception as e:
                return Response(
                    {
                        'error': _('Registration failed. Please try again.'),
                        'details': str(e) if settings.DEBUG else None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class EmailVerificationView(APIView):
    """
    API view for email verification.
    
    Handles email verification using tokens sent to users.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request: Request) -> Response:
        """
        Verify user email address.
        
        Args:
            request: HTTP request with verification data
            
        Returns:
            Response with verification status
        """
        from ..services.email_verification_service import EmailVerificationService
        from ..exceptions import TokenInvalidError, TokenExpiredError
        
        serializer = EmailVerificationSerializer(data=request.data)
        
        if serializer.is_valid():
            user_id = serializer.validated_data['user_id']
            token = serializer.validated_data['token']
            
            email_service = EmailVerificationService()
            
            try:
                result = email_service.verify_email(str(user_id), token)
                
                return Response(
                    {
                        'message': result['message'],
                        'status': result['status'],
                        'user_id': result['user_id'],
                        'verified_at': result.get('verified_at')
                    },
                    status=status.HTTP_200_OK
                )
                
            except (TokenInvalidError, TokenExpiredError) as e:
                return Response(
                    {
                        'error': str(e),
                        'status': 'invalid_token'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            except Exception as e:
                return Response(
                    {
                        'error': _('Unable to verify email. Please try again later.'),
                        'details': str(e) if settings.DEBUG else None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class ResendVerificationView(APIView):
    """
    API view for resending email verification.
    
    Handles resending verification emails with rate limiting.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request: Request) -> Response:
        """
        Resend email verification.
        
        Args:
            request: HTTP request with email address
            
        Returns:
            Response with resend status
        """
        from ..services.email_verification_service import EmailVerificationService
        from ..exceptions import RateLimitExceededError
        
        serializer = ResendVerificationSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            email_service = EmailVerificationService()
            
            try:
                result = email_service.resend_verification_email(email)
                
                response_status = status.HTTP_200_OK
                if not result['success'] and result.get('status') == 'rate_limited':
                    response_status = status.HTTP_429_TOO_MANY_REQUESTS
                
                return Response(
                    {
                        'message': result['message'],
                        'status': result['status'],
                        'email_sent': result.get('email_sent', False),
                        'expires_at': result.get('expires_at'),
                        'retry_after_minutes': result.get('retry_after_minutes')
                    },
                    status=response_status
                )
                
            except Exception as e:
                return Response(
                    {
                        'error': _('Unable to send verification email. Please try again later.'),
                        'details': str(e) if settings.DEBUG else None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class UserProfileViewSet(GenericViewSet, RetrieveModelMixin, UpdateModelMixin):
    """
    ViewSet for user profile management.
    
    Provides endpoints for retrieving and updating user profile information.
    """
    
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        """
        Return the current user's profile.
        
        Returns:
            Current user's UserProfile instance
        """
        return self.request.user
    
    @action(detail=False, methods=['get', 'put', 'patch'])
    def me(self, request: Request) -> Response:
        """
        Get or update current user's profile.
        
        Args:
            request: HTTP request
            
        Returns:
            Response with user profile data
        """
        if request.method == 'GET':
            serializer = self.get_serializer(request.user)
            return Response(serializer.data)
        
        elif request.method in ['PUT', 'PATCH']:
            partial = request.method == 'PATCH'
            serializer = self.get_serializer(
                request.user, 
                data=request.data, 
                partial=partial
            )
            
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        'message': _('Profile updated successfully.'),
                        'user': serializer.data
                    },
                    status=status.HTTP_200_OK
                )
            
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def retrieve(self, request: Request, *args, **kwargs) -> Response:
        """
        Retrieve current user's profile.
        
        Args:
            request: HTTP request
            
        Returns:
            Response with user profile data
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
    def update(self, request: Request, *args, **kwargs) -> Response:
        """
        Update current user's profile.
        
        Args:
            request: HTTP request with profile data
            
        Returns:
            Response with updated profile data
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    'message': _('Profile updated successfully.'),
                    'user': serializer.data
                },
                status=status.HTTP_200_OK
            )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )
    
    def partial_update(self, request: Request, *args, **kwargs) -> Response:
        """
        Partially update current user's profile.
        
        Args:
            request: HTTP request with partial profile data
            
        Returns:
            Response with updated profile data
        """
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)
    
    @action(detail=False, methods=['get'])
    def identities(self, request: Request) -> Response:
        """
        Get user's linked social identities.
        
        Args:
            request: HTTP request
            
        Returns:
            Response with linked identities
        """
        identities = UserIdentity.objects.get_user_identities(request.user)
        serializer = UserIdentitySerializer(identities, many=True)
        
        return Response(
            {
                'identities': serializer.data,
                'count': identities.count()
            },
            status=status.HTTP_200_OK
        )
    
    @action(detail=False, methods=['post'])
    def change_password(self, request: Request) -> Response:
        """
        Change user's password.
        
        Args:
            request: HTTP request with password data
            
        Returns:
            Response with password change status
        """
        from ..serializers import PasswordChangeSerializer
        from ..services.password_service import PasswordService
        from ..exceptions import (
            InvalidCredentialsError,
            AccountLockedError,
            PasswordPolicyError
        )
        
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            current_password = serializer.validated_data['current_password']
            new_password = serializer.validated_data['new_password']
            password_service = PasswordService()
            
            try:
                result = password_service.change_password(
                    user=request.user,
                    current_password=current_password,
                    new_password=new_password
                )
                
                return Response(
                    {
                        'message': result['message'],
                        'status': 'changed',
                        'strength_score': result['strength_score'],
                        'changed_at': result['changed_at']
                    },
                    status=status.HTTP_200_OK
                )
                
            except InvalidCredentialsError as e:
                return Response(
                    {
                        'error': str(e),
                        'status': 'invalid_credentials'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            except AccountLockedError as e:
                return Response(
                    {
                        'error': str(e),
                        'status': 'account_locked',
                        'locked_until': e.details.get('locked_until')
                    },
                    status=status.HTTP_423_LOCKED
                )
                
            except PasswordPolicyError as e:
                return Response(
                    {
                        'error': str(e),
                        'validation_errors': e.details.get('validation_errors', []),
                        'status': 'policy_violation'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            except Exception as e:
                return Response(
                    {
                        'error': _('Unable to change password. Please try again later.'),
                        'details': str(e) if settings.DEBUG else None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class PasswordResetRequestView(APIView):
    """
    API view for password reset request.
    
    Handles password reset initiation with secure token generation.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request: Request) -> Response:
        """
        Initiate password reset workflow.
        
        Args:
            request: HTTP request with email address
            
        Returns:
            Response with reset initiation status
        """
        from ..serializers import PasswordResetRequestSerializer
        from ..services.password_service import PasswordService
        
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password_service = PasswordService()
            
            try:
                result = password_service.initiate_password_reset(email)
                
                return Response(
                    {
                        'message': result['message'],
                        'status': 'initiated' if result['success'] else 'failed'
                    },
                    status=status.HTTP_200_OK if result['success'] else status.HTTP_429_TOO_MANY_REQUESTS
                )
                
            except Exception as e:
                return Response(
                    {
                        'error': _('Unable to process password reset request. Please try again later.'),
                        'details': str(e) if settings.DEBUG else None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class PasswordResetConfirmView(APIView):
    """
    API view for password reset confirmation.
    
    Handles password reset completion with token validation.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request: Request) -> Response:
        """
        Complete password reset workflow.
        
        Args:
            request: HTTP request with token and new password
            
        Returns:
            Response with reset completion status
        """
        from ..serializers import PasswordResetConfirmSerializer
        from ..services.password_service import PasswordService
        from ..exceptions import (
            TokenInvalidError, 
            TokenExpiredError, 
            PasswordPolicyError
        )
        
        serializer = PasswordResetConfirmSerializer(data=request.data)
        
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            password_service = PasswordService()
            
            try:
                result = password_service.reset_password(token, new_password)
                
                return Response(
                    {
                        'message': result['message'],
                        'status': 'completed',
                        'strength_score': result['strength_score']
                    },
                    status=status.HTTP_200_OK
                )
                
            except (TokenInvalidError, TokenExpiredError) as e:
                return Response(
                    {
                        'error': str(e),
                        'status': 'invalid_token'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            except PasswordPolicyError as e:
                return Response(
                    {
                        'error': str(e),
                        'validation_errors': e.details.get('validation_errors', []),
                        'status': 'policy_violation'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            except Exception as e:
                return Response(
                    {
                        'error': _('Unable to reset password. Please try again later.'),
                        'details': str(e) if settings.DEBUG else None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class PasswordResetValidateTokenView(APIView):
    """
    API view for password reset token validation.
    
    Validates reset tokens without consuming them.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request: Request) -> Response:
        """
        Validate password reset token.
        
        Args:
            request: HTTP request with token
            
        Returns:
            Response with token validation status
        """
        from ..services.password_service import PasswordService
        
        token = request.data.get('token')
        if not token:
            return Response(
                {
                    'error': _('Token is required'),
                    'valid': False
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        password_service = PasswordService()
        result = password_service.validate_reset_token(token)
        
        return Response(
            result,
            status=status.HTTP_200_OK if result['valid'] else status.HTTP_400_BAD_REQUEST
        )


class PasswordStrengthCheckView(APIView):
    """
    API view for password strength checking.
    
    Provides real-time password strength feedback.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request: Request) -> Response:
        """
        Check password strength.
        
        Args:
            request: HTTP request with password
            
        Returns:
            Response with strength analysis
        """
        from ..serializers import PasswordStrengthCheckSerializer
        from ..services.password_service import PasswordService
        
        serializer = PasswordStrengthCheckSerializer(data=request.data)
        
        if serializer.is_valid():
            password = serializer.validated_data['password']
            password_service = PasswordService()
            
            # Get user context if authenticated
            user = request.user if request.user.is_authenticated else None
            
            result = password_service.check_password_strength(password, user)
            
            return Response(result, status=status.HTTP_200_OK)
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class PasswordPolicyView(APIView):
    """
    API view for password policy information.
    
    Provides current password policy requirements.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def get(self, request: Request) -> Response:
        """
        Get password policy information.
        
        Args:
            request: HTTP request
            
        Returns:
            Response with policy information
        """
        from ..services.password_service import PasswordService
        
        password_service = PasswordService()
        policy_info = password_service.get_password_policy_info()
        
        return Response(
            {
                'policy': policy_info,
                'message': _('Current password policy requirements')
            },
            status=status.HTTP_200_OK
        )


class EmailVerificationStatusView(APIView):
    """
    API view for checking email verification status.
    
    Provides verification status information for authenticated users.
    """
    
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request: Request) -> Response:
        """
        Get email verification status for current user.
        
        Args:
            request: HTTP request
            
        Returns:
            Response with verification status information
        """
        from ..services.email_verification_service import EmailVerificationService
        
        email_service = EmailVerificationService()
        status_info = email_service.get_verification_status(request.user)
        
        return Response(status_info, status=status.HTTP_200_OK)


class EmailVerificationValidateTokenView(APIView):
    """
    API view for validating email verification tokens.
    
    Validates verification tokens without consuming them.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request: Request) -> Response:
        """
        Validate email verification token.
        
        Args:
            request: HTTP request with token data
            
        Returns:
            Response with token validation status
        """
        from ..services.email_verification_service import EmailVerificationService
        
        user_id = request.data.get('user_id')
        token = request.data.get('token')
        
        if not user_id or not token:
            return Response(
                {
                    'error': _('User ID and token are required'),
                    'valid': False
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        email_service = EmailVerificationService()
        result = email_service.validate_verification_token(str(user_id), token)
        
        response_status = status.HTTP_200_OK if result['valid'] else status.HTTP_400_BAD_REQUEST
        return Response(result, status=response_status)


class EmailVerificationStatsView(APIView):
    """
    API view for email verification statistics.
    
    Provides verification statistics for monitoring and analytics.
    """
    
    permission_classes = [permissions.IsAdminUser]
    
    def get(self, request: Request) -> Response:
        """
        Get email verification statistics.
        
        Args:
            request: HTTP request
            
        Returns:
            Response with verification statistics
        """
        from ..services.email_verification_service import EmailVerificationService
        
        email_service = EmailVerificationService()
        stats = email_service.get_verification_statistics()
        
        return Response(
            {
                'statistics': stats,
                'message': _('Email verification statistics')
            },
            status=status.HTTP_200_OK
        )