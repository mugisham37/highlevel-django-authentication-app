"""
Backup Codes MFA API views for enterprise authentication system.

This module provides REST API endpoints for backup codes management
including generation, validation, regeneration, and monitoring.
"""

from typing import Dict, Any

from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from ..authentication import JWTAuthentication
from ..exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError,
)
from ..serializers import (
    BackupCodesGenerationSerializer,
    BackupCodeValidationSerializer,
    BackupCodesRegenerationSerializer,
)
from ..services import backup_codes_service
from ..utils.request_utils import get_client_ip, get_user_agent


@method_decorator([csrf_exempt, never_cache], name='dispatch')
class BackupCodesViewSet(ViewSet):
    """
    ViewSet for managing MFA backup codes.
    
    Provides endpoints for generating, validating, regenerating,
    and monitoring backup codes with comprehensive security features.
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get_request_metadata(self, request: Request) -> Dict[str, Any]:
        """
        Extract request metadata for logging and security.
        
        Args:
            request: HTTP request object
            
        Returns:
            Dictionary containing request metadata
        """
        return {
            'ip_address': get_client_ip(request),
            'user_agent': get_user_agent(request),
            'session_id': request.session.session_key if hasattr(request, 'session') else None
        }
    
    @action(detail=False, methods=['post'], url_path='generate')
    def generate_backup_codes(self, request: Request) -> Response:
        """
        Generate new backup codes for the authenticated user.
        
        POST /api/v1/mfa/backup-codes/generate/
        
        Request body:
        {
            "count": 10,  // Optional, defaults to configured count
            "force_regenerate": false  // Optional, defaults to false
        }
        
        Returns:
            Response with generated backup codes and metadata
        """
        try:
            serializer = BackupCodesGenerationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            metadata = self.get_request_metadata(request)
            
            result = backup_codes_service.generate_backup_codes(
                user=request.user,
                count=serializer.validated_data.get('count'),
                force_regenerate=serializer.validated_data.get('force_regenerate', False),
                **metadata
            )
            
            return Response({
                'success': True,
                'message': 'Backup codes generated successfully',
                'data': result
            }, status=status.HTTP_201_CREATED)
            
        except MFAError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'MFA_ERROR',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'], url_path='validate')
    def validate_backup_code(self, request: Request) -> Response:
        """
        Validate a backup code for the authenticated user.
        
        POST /api/v1/mfa/backup-codes/validate/
        
        Request body:
        {
            "backup_code": "ABCD1234"
        }
        
        Returns:
            Response with validation result and remaining codes info
        """
        try:
            serializer = BackupCodeValidationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            metadata = self.get_request_metadata(request)
            
            result = backup_codes_service.validate_backup_code(
                user=request.user,
                backup_code=serializer.validated_data['backup_code'],
                **metadata
            )
            
            return Response({
                'success': True,
                'message': 'Backup code validated successfully',
                'data': result
            }, status=status.HTTP_200_OK)
            
        except MFARateLimitError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'message': str(e)
                }
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except MFADeviceNotFoundError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'DEVICE_NOT_FOUND',
                    'message': str(e)
                }
            }, status=status.HTTP_404_NOT_FOUND)
        except MFAVerificationError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'VERIFICATION_FAILED',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        except MFAError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'MFA_ERROR',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'], url_path='regenerate')
    def regenerate_backup_codes(self, request: Request) -> Response:
        """
        Regenerate backup codes for the authenticated user.
        
        POST /api/v1/mfa/backup-codes/regenerate/
        
        Request body:
        {
            "reason": "user_request"  // Optional reason for regeneration
        }
        
        Returns:
            Response with new backup codes and metadata
        """
        try:
            serializer = BackupCodesRegenerationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            metadata = self.get_request_metadata(request)
            
            result = backup_codes_service.regenerate_backup_codes(
                user=request.user,
                reason=serializer.validated_data.get('reason', 'user_request'),
                **metadata
            )
            
            return Response({
                'success': True,
                'message': 'Backup codes regenerated successfully',
                'data': result
            }, status=status.HTTP_200_OK)
            
        except MFADeviceNotFoundError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'DEVICE_NOT_FOUND',
                    'message': str(e)
                }
            }, status=status.HTTP_404_NOT_FOUND)
        except MFAError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'MFA_ERROR',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['get'], url_path='status')
    def get_backup_codes_status(self, request: Request) -> Response:
        """
        Get backup codes status for the authenticated user.
        
        GET /api/v1/mfa/backup-codes/status/
        
        Returns:
            Response with backup codes status information
        """
        try:
            result = backup_codes_service.get_backup_codes_status(request.user)
            
            return Response({
                'success': True,
                'data': result
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['get'], url_path='statistics')
    def get_usage_statistics(self, request: Request) -> Response:
        """
        Get backup codes usage statistics for the authenticated user.
        
        GET /api/v1/mfa/backup-codes/statistics/?days=30
        
        Query parameters:
        - days: Number of days to look back (default: 30)
        
        Returns:
            Response with usage statistics
        """
        try:
            days = int(request.query_params.get('days', 30))
            
            # Validate days parameter
            if days < 1 or days > 365:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'INVALID_PARAMETER',
                        'message': 'Days parameter must be between 1 and 365'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            result = backup_codes_service.get_usage_statistics(
                user=request.user,
                days=days
            )
            
            return Response({
                'success': True,
                'data': result
            }, status=status.HTTP_200_OK)
            
        except ValueError:
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_PARAMETER',
                    'message': 'Days parameter must be a valid integer'
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator([csrf_exempt, never_cache], name='dispatch')
class BackupCodeValidationView(APIView):
    """
    Standalone view for backup code validation.
    
    This view can be used during authentication flows where
    the user needs to validate a backup code as part of MFA.
    """
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """
        Validate a backup code for MFA authentication.
        
        POST /api/v1/mfa/validate-backup-code/
        
        Request body:
        {
            "backup_code": "ABCD1234"
        }
        
        Returns:
            Response with validation result
        """
        try:
            serializer = BackupCodeValidationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            metadata = {
                'ip_address': get_client_ip(request),
                'user_agent': get_user_agent(request),
                'session_id': request.session.session_key if hasattr(request, 'session') else None
            }
            
            result = backup_codes_service.validate_backup_code(
                user=request.user,
                backup_code=serializer.validated_data['backup_code'],
                **metadata
            )
            
            return Response({
                'success': True,
                'message': 'Backup code validated successfully',
                'data': {
                    'valid': result['valid'],
                    'remaining_codes': result['remaining_codes'],
                    'warning': result.get('warning'),
                    'used_at': result['used_at']
                }
            }, status=status.HTTP_200_OK)
            
        except MFARateLimitError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'message': str(e)
                }
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except MFADeviceNotFoundError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'DEVICE_NOT_FOUND',
                    'message': str(e)
                }
            }, status=status.HTTP_404_NOT_FOUND)
        except MFAVerificationError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'VERIFICATION_FAILED',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        except MFAError as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'MFA_ERROR',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)