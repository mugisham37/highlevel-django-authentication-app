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
        serializer = EmailVerificationSerializer(data=request.data)
        
        if serializer.is_valid():
            return Response(
                {
                    'message': _('Email verified successfully. Your account is now active.'),
                    'status': 'verified'
                },
                status=status.HTTP_200_OK
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
        serializer = ResendVerificationSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            # Attempt to resend verification email
            if UserProfile.objects.resend_verification_email(email):
                return Response(
                    {
                        'message': _('Verification email sent successfully. Please check your inbox.'),
                        'status': 'sent'
                    },
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {
                        'error': _('Unable to send verification email. Please try again later.'),
                        'status': 'failed'
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS
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
        
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.clear_password_reset_token()
            user.save()
            
            return Response(
                {
                    'message': _('Password changed successfully.'),
                    'status': 'changed'
                },
                status=status.HTTP_200_OK
            )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )