"""
Session management API views.

This module provides REST API endpoints for session lifecycle management
including session listing, termination, and statistics.
"""

import logging
from typing import Dict, Any
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.request import Request
from django.http import JsonResponse
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q

from ..models.session import UserSession, SessionActivity
from ..models.user import UserProfile
from ..services.session_service import (
    SessionService,
    terminate_user_session,
    extend_session_expiration,
    get_session_statistics,
)
from ..serializers import UserSessionSerializer, SessionActivitySerializer
from ..exceptions import SessionNotFoundError, SessionInvalidError


logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_user_sessions(request: Request) -> Response:
    """
    List sessions for the authenticated user.
    
    Query Parameters:
    - active_only: boolean (default: true) - Only return active sessions
    - page: int - Page number for pagination
    - page_size: int - Number of sessions per page (max 100)
    
    Returns:
        JSON response with paginated session list
    """
    try:
        user = request.user
        active_only = request.GET.get('active_only', 'true').lower() == 'true'
        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('page_size', 20)), 100)
        
        # Get user sessions
        sessions_query = UserSession.objects.filter(user=user).select_related('device_info')
        
        if active_only:
            sessions_query = sessions_query.filter(status='active')
        
        sessions_query = sessions_query.order_by('-last_activity')
        
        # Paginate results
        paginator = Paginator(sessions_query, page_size)
        sessions_page = paginator.get_page(page)
        
        # Serialize sessions
        serializer = UserSessionSerializer(sessions_page.object_list, many=True)
        
        return Response({
            'sessions': serializer.data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': paginator.num_pages,
                'total_sessions': paginator.count,
                'has_next': sessions_page.has_next(),
                'has_previous': sessions_page.has_previous(),
            }
        })
        
    except Exception as e:
        logger.error(f"Error listing user sessions: {e}")
        return Response(
            {'error': 'Failed to retrieve sessions'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_session_details(request: Request, session_id: str) -> Response:
    """
    Get detailed information about a specific session.
    
    Args:
        session_id: Session ID to retrieve
        
    Returns:
        JSON response with session details
    """
    try:
        user = request.user
        
        # Get session (ensure it belongs to the user)
        session = UserSession.objects.select_related('device_info').get(
            session_id=session_id,
            user=user
        )
        
        # Serialize session
        serializer = UserSessionSerializer(session)
        session_data = serializer.data
        
        # Add risk analysis
        session_service = SessionService()
        risk_analysis = session_service.analyze_session_risk(session)
        session_data['risk_analysis'] = risk_analysis
        
        # Add recent activities
        recent_activities = SessionActivity.objects.filter(
            session=session
        ).order_by('-timestamp')[:10]
        
        activity_serializer = SessionActivitySerializer(recent_activities, many=True)
        session_data['recent_activities'] = activity_serializer.data
        
        return Response(session_data)
        
    except UserSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Error getting session details: {e}")
        return Response(
            {'error': 'Failed to retrieve session details'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def terminate_session(request: Request, session_id: str) -> Response:
    """
    Terminate a specific session.
    
    Args:
        session_id: Session ID to terminate
        
    Returns:
        JSON response confirming termination
    """
    try:
        user = request.user
        
        # Verify session belongs to user
        try:
            session = UserSession.objects.get(session_id=session_id, user=user)
        except UserSession.DoesNotExist:
            return Response(
                {'error': 'Session not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Terminate session
        success = terminate_user_session(
            session_id=session_id,
            terminated_by=user,
            reason='user_requested_termination'
        )
        
        if success:
            logger.info(f"User {user.email} terminated session {session_id}")
            return Response({
                'message': 'Session terminated successfully',
                'session_id': session_id
            })
        else:
            return Response(
                {'error': 'Failed to terminate session'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    except Exception as e:
        logger.error(f"Error terminating session: {e}")
        return Response(
            {'error': 'Failed to terminate session'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def terminate_all_sessions(request: Request) -> Response:
    """
    Terminate all sessions for the authenticated user except the current one.
    
    Returns:
        JSON response with termination count
    """
    try:
        user = request.user
        current_session_id = getattr(request, 'user_session', None)
        current_session_id = current_session_id.session_id if current_session_id else None
        
        # Get session service
        session_service = SessionService()
        
        # Terminate all other sessions
        terminated_count = session_service.terminate_user_sessions(
            user=user,
            exclude_session_id=current_session_id,
            reason='user_requested_bulk_termination'
        )
        
        logger.info(f"User {user.email} terminated {terminated_count} sessions")
        
        return Response({
            'message': f'Terminated {terminated_count} sessions',
            'terminated_count': terminated_count
        })
        
    except Exception as e:
        logger.error(f"Error terminating all sessions: {e}")
        return Response(
            {'error': 'Failed to terminate sessions'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def extend_current_session(request: Request) -> Response:
    """
    Extend the current session expiration.
    
    Request Body:
    - hours: int (default: 24) - Number of hours to extend
    
    Returns:
        JSON response confirming extension
    """
    try:
        user = request.user
        hours = request.data.get('hours', 24)
        
        # Validate hours parameter
        if not isinstance(hours, int) or hours < 1 or hours > 168:  # Max 1 week
            return Response(
                {'error': 'Hours must be between 1 and 168'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get current session
        current_session = getattr(request, 'user_session', None)
        if not current_session:
            return Response(
                {'error': 'No active session found'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Extend session
        success = extend_session_expiration(current_session.session_id, hours)
        
        if success:
            # Refresh session object
            current_session.refresh_from_db()
            
            return Response({
                'message': f'Session extended by {hours} hours',
                'new_expiration': current_session.expires_at.isoformat(),
                'hours_extended': hours
            })
        else:
            return Response(
                {'error': 'Failed to extend session'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    except Exception as e:
        logger.error(f"Error extending session: {e}")
        return Response(
            {'error': 'Failed to extend session'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_session_activities(request: Request, session_id: str) -> Response:
    """
    Get activities for a specific session.
    
    Query Parameters:
    - page: int - Page number for pagination
    - page_size: int - Number of activities per page (max 100)
    - activity_type: str - Filter by activity type
    
    Args:
        session_id: Session ID to get activities for
        
    Returns:
        JSON response with paginated activities
    """
    try:
        user = request.user
        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('page_size', 50)), 100)
        activity_type = request.GET.get('activity_type')
        
        # Verify session belongs to user
        try:
            session = UserSession.objects.get(session_id=session_id, user=user)
        except UserSession.DoesNotExist:
            return Response(
                {'error': 'Session not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get activities
        activities_query = SessionActivity.objects.filter(session=session)
        
        if activity_type:
            activities_query = activities_query.filter(activity_type=activity_type)
        
        activities_query = activities_query.order_by('-timestamp')
        
        # Paginate results
        paginator = Paginator(activities_query, page_size)
        activities_page = paginator.get_page(page)
        
        # Serialize activities
        serializer = SessionActivitySerializer(activities_page.object_list, many=True)
        
        return Response({
            'activities': serializer.data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': paginator.num_pages,
                'total_activities': paginator.count,
                'has_next': activities_page.has_next(),
                'has_previous': activities_page.has_previous(),
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting session activities: {e}")
        return Response(
            {'error': 'Failed to retrieve session activities'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_session_statistics(request: Request) -> Response:
    """
    Get session statistics for the authenticated user.
    
    Returns:
        JSON response with user session statistics
    """
    try:
        user = request.user
        
        # Get user-specific statistics
        stats = get_session_statistics(user)
        
        return Response(stats)
        
    except Exception as e:
        logger.error(f"Error getting user session statistics: {e}")
        return Response(
            {'error': 'Failed to retrieve session statistics'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_session(request: Request) -> Response:
    """
    Get information about the current session.
    
    Returns:
        JSON response with current session details
    """
    try:
        current_session = getattr(request, 'user_session', None)
        
        if not current_session:
            return Response(
                {'error': 'No active session found'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Serialize current session
        serializer = UserSessionSerializer(current_session)
        session_data = serializer.data
        
        # Add risk analysis
        session_service = SessionService()
        risk_analysis = session_service.analyze_session_risk(current_session)
        session_data['risk_analysis'] = risk_analysis
        
        return Response(session_data)
        
    except Exception as e:
        logger.error(f"Error getting current session: {e}")
        return Response(
            {'error': 'Failed to retrieve current session'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# Admin-only views for session management

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_get_session_statistics(request: Request) -> Response:
    """
    Get global session statistics (admin only).
    
    Returns:
        JSON response with global session statistics
    """
    try:
        # Check if user is admin/staff
        if not request.user.is_staff:
            return Response(
                {'error': 'Admin access required'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get global statistics
        stats = get_session_statistics()
        
        return Response(stats)
        
    except Exception as e:
        logger.error(f"Error getting admin session statistics: {e}")
        return Response(
            {'error': 'Failed to retrieve session statistics'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_terminate_user_sessions(request: Request, user_id: int) -> Response:
    """
    Terminate all sessions for a specific user (admin only).
    
    Args:
        user_id: ID of user whose sessions to terminate
        
    Returns:
        JSON response with termination count
    """
    try:
        # Check if user is admin/staff
        if not request.user.is_staff:
            return Response(
                {'error': 'Admin access required'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get target user
        try:
            target_user = UserProfile.objects.get(id=user_id)
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get session service
        session_service = SessionService()
        
        # Terminate all sessions for the user
        terminated_count = session_service.terminate_user_sessions(
            user=target_user,
            reason='admin_requested_termination'
        )
        
        logger.info(
            f"Admin {request.user.email} terminated {terminated_count} sessions "
            f"for user {target_user.email}"
        )
        
        return Response({
            'message': f'Terminated {terminated_count} sessions for user {target_user.email}',
            'terminated_count': terminated_count,
            'user_email': target_user.email
        })
        
    except Exception as e:
        logger.error(f"Error terminating user sessions: {e}")
        return Response(
            {'error': 'Failed to terminate user sessions'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )