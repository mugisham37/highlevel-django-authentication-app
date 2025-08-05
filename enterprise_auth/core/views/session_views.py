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


# Enhanced concurrent session management views

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_concurrent_session_policy(request: Request) -> Response:
    """
    Get concurrent session policy information for the authenticated user.
    
    Returns:
        JSON response with policy information and current session status
    """
    try:
        user = request.user
        session_service = SessionService()
        
        policy_info = session_service.get_concurrent_session_policy_info(user)
        
        return Response(policy_info)
        
    except Exception as e:
        logger.error(f"Error getting concurrent session policy: {e}")
        return Response(
            {'error': 'Failed to retrieve session policy information'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def terminate_sessions_by_criteria(request: Request) -> Response:
    """
    Terminate sessions based on specific criteria.
    
    Request Body:
    - criteria: str - Termination criteria ('oldest', 'lowest_risk', 'untrusted_devices', 'suspicious')
    - count: int (optional) - Number of sessions to terminate (default: all matching)
    - exclude_current: bool (default: true) - Whether to exclude current session
    
    Returns:
        JSON response with termination results
    """
    try:
        user = request.user
        criteria = request.data.get('criteria')
        count = request.data.get('count')
        exclude_current = request.data.get('exclude_current', True)
        
        if not criteria:
            return Response(
                {'error': 'Criteria parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        valid_criteria = ['oldest', 'lowest_risk', 'untrusted_devices', 'suspicious', 'by_location', 'by_device']
        if criteria not in valid_criteria:
            return Response(
                {'error': f'Invalid criteria. Must be one of: {valid_criteria}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get current session to exclude if requested
        current_session_id = None
        if exclude_current:
            current_session = getattr(request, 'user_session', None)
            current_session_id = current_session.session_id if current_session else None
        
        # Get sessions to terminate based on criteria
        sessions_query = UserSession.objects.filter(user=user, status='active')
        
        if current_session_id:
            sessions_query = sessions_query.exclude(session_id=current_session_id)
        
        if criteria == 'oldest':
            sessions_to_terminate = sessions_query.order_by('last_activity')
        elif criteria == 'lowest_risk':
            sessions_to_terminate = sessions_query.order_by('risk_score')
        elif criteria == 'untrusted_devices':
            sessions_to_terminate = sessions_query.filter(is_trusted_device=False).order_by('last_activity')
        elif criteria == 'suspicious':
            sessions_to_terminate = sessions_query.filter(status='suspicious').order_by('last_activity')
        elif criteria == 'by_location':
            location = request.data.get('location')
            if not location:
                return Response(
                    {'error': 'Location parameter required for by_location criteria'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            sessions_to_terminate = sessions_query.filter(
                Q(country__icontains=location) | 
                Q(city__icontains=location) | 
                Q(region__icontains=location)
            ).order_by('last_activity')
        elif criteria == 'by_device':
            device_type = request.data.get('device_type')
            if not device_type:
                return Response(
                    {'error': 'Device type parameter required for by_device criteria'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            sessions_to_terminate = sessions_query.filter(
                device_info__device_type=device_type
            ).order_by('last_activity')
        
        # Limit count if specified
        if count and isinstance(count, int) and count > 0:
            sessions_to_terminate = sessions_to_terminate[:count]
        
        # Terminate sessions
        terminated_sessions = []
        for session in sessions_to_terminate:
            success = terminate_user_session(
                session_id=session.session_id,
                terminated_by=user,
                reason=f'user_requested_termination_by_{criteria}'
            )
            
            if success:
                terminated_sessions.append({
                    'session_id': session.session_id,
                    'device_type': session.device_info.device_type,
                    'location': session.location_string,
                    'last_activity': session.last_activity.isoformat(),
                    'risk_score': session.risk_score,
                })
        
        logger.info(f"User {user.email} terminated {len(terminated_sessions)} sessions by criteria: {criteria}")
        
        return Response({
            'message': f'Terminated {len(terminated_sessions)} sessions',
            'criteria': criteria,
            'terminated_count': len(terminated_sessions),
            'terminated_sessions': terminated_sessions
        })
        
    except Exception as e:
        logger.error(f"Error terminating sessions by criteria: {e}")
        return Response(
            {'error': 'Failed to terminate sessions'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detect_session_sharing(request: Request) -> Response:
    """
    Analyze current sessions for potential sharing patterns.
    
    Returns:
        JSON response with session sharing analysis
    """
    try:
        user = request.user
        session_service = SessionService()
        
        # Get active sessions
        active_sessions = UserSession.objects.filter(
            user=user,
            status='active'
        ).select_related('device_info')
        
        if active_sessions.count() <= 1:
            return Response({
                'sharing_detected': False,
                'message': 'No potential session sharing detected (only one active session)',
                'active_sessions_count': active_sessions.count()
            })
        
        # Analyze sessions for sharing patterns
        from django.utils import timezone
        from datetime import timedelta
        
        threshold_time = timezone.now() - timedelta(minutes=session_service.session_sharing_threshold_minutes)
        recent_sessions = active_sessions.filter(last_activity__gte=threshold_time)
        
        # Group by device and location
        device_groups = {}
        location_groups = {}
        
        for session in recent_sessions:
            # Group by device
            device_fp = session.device_info.device_fingerprint
            if device_fp not in device_groups:
                device_groups[device_fp] = []
            device_groups[device_fp].append(session)
            
            # Group by location
            if session.latitude and session.longitude:
                location_key = f"{session.country}_{session.city}"
                if location_key not in location_groups:
                    location_groups[location_key] = []
                location_groups[location_key].append(session)
        
        # Analyze patterns
        sharing_indicators = []
        
        # Check for multiple sessions per device
        for device_fp, sessions in device_groups.items():
            if len(sessions) > session_service.max_concurrent_sessions_per_device:
                sharing_indicators.append({
                    'type': 'multiple_sessions_per_device',
                    'device_fingerprint': device_fp[:8] + '...',
                    'session_count': len(sessions),
                    'max_allowed': session_service.max_concurrent_sessions_per_device,
                    'sessions': [s.session_id for s in sessions]
                })
        
        # Check for concurrent sessions from distant locations
        if len(location_groups) > 1:
            locations = list(location_groups.keys())
            for i, location1 in enumerate(locations):
                for location2 in locations[i+1:]:
                    sessions1 = location_groups[location1]
                    sessions2 = location_groups[location2]
                    
                    # Check for concurrent activity
                    for s1 in sessions1:
                        for s2 in sessions2:
                            time_diff = abs((s1.last_activity - s2.last_activity).total_seconds())
                            if time_diff < session_service.session_sharing_threshold_minutes * 60:
                                sharing_indicators.append({
                                    'type': 'concurrent_distant_locations',
                                    'location1': s1.location_string,
                                    'location2': s2.location_string,
                                    'session1_id': s1.session_id,
                                    'session2_id': s2.session_id,
                                    'time_difference_seconds': time_diff
                                })
        
        sharing_detected = len(sharing_indicators) > 0
        
        return Response({
            'sharing_detected': sharing_detected,
            'active_sessions_count': active_sessions.count(),
            'recent_sessions_count': recent_sessions.count(),
            'sharing_indicators': sharing_indicators,
            'analysis_threshold_minutes': session_service.session_sharing_threshold_minutes,
            'recommendations': [
                'Review suspicious sessions and terminate if necessary',
                'Enable additional security measures like MFA',
                'Monitor for continued suspicious activity'
            ] if sharing_detected else [
                'No immediate action required',
                'Continue monitoring session activity'
            ]
        })
        
    except Exception as e:
        logger.error(f"Error detecting session sharing: {e}")
        return Response(
            {'error': 'Failed to analyze session sharing'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resolve_session_conflicts(request: Request) -> Response:
    """
    Resolve session conflicts using specified resolution strategy.
    
    Request Body:
    - strategy: str - Resolution strategy ('terminate_duplicates', 'merge_sessions', 'keep_most_recent')
    - auto_resolve: bool (default: false) - Whether to automatically apply resolution
    
    Returns:
        JSON response with conflict resolution results
    """
    try:
        user = request.user
        strategy = request.data.get('strategy', 'terminate_duplicates')
        auto_resolve = request.data.get('auto_resolve', False)
        
        valid_strategies = ['terminate_duplicates', 'keep_most_recent', 'keep_highest_risk', 'keep_trusted_devices']
        if strategy not in valid_strategies:
            return Response(
                {'error': f'Invalid strategy. Must be one of: {valid_strategies}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get active sessions
        active_sessions = UserSession.objects.filter(
            user=user,
            status='active'
        ).select_related('device_info')
        
        if active_sessions.count() <= 1:
            return Response({
                'conflicts_found': False,
                'message': 'No session conflicts detected',
                'active_sessions_count': active_sessions.count()
            })
        
        # Identify conflicts and resolution actions
        conflicts = []
        resolution_actions = []
        
        # Group sessions by device fingerprint to find duplicates
        device_sessions = {}
        for session in active_sessions:
            device_fp = session.device_info.device_fingerprint
            if device_fp not in device_sessions:
                device_sessions[device_fp] = []
            device_sessions[device_fp].append(session)
        
        # Find conflicts (multiple sessions from same device)
        for device_fp, sessions in device_sessions.items():
            if len(sessions) > 1:
                conflict = {
                    'device_fingerprint': device_fp[:8] + '...',
                    'session_count': len(sessions),
                    'sessions': []
                }
                
                for session in sessions:
                    conflict['sessions'].append({
                        'session_id': session.session_id,
                        'last_activity': session.last_activity.isoformat(),
                        'risk_score': session.risk_score,
                        'is_trusted_device': session.is_trusted_device,
                        'location': session.location_string
                    })
                
                conflicts.append(conflict)
                
                # Determine resolution actions based on strategy
                if strategy == 'terminate_duplicates':
                    # Keep the most recent session, terminate others
                    sessions_sorted = sorted(sessions, key=lambda s: s.last_activity, reverse=True)
                    sessions_to_terminate = sessions_sorted[1:]
                    
                elif strategy == 'keep_most_recent':
                    # Same as terminate_duplicates
                    sessions_sorted = sorted(sessions, key=lambda s: s.last_activity, reverse=True)
                    sessions_to_terminate = sessions_sorted[1:]
                    
                elif strategy == 'keep_highest_risk':
                    # Keep session with highest risk score (most important to monitor)
                    sessions_sorted = sorted(sessions, key=lambda s: s.risk_score, reverse=True)
                    sessions_to_terminate = sessions_sorted[1:]
                    
                elif strategy == 'keep_trusted_devices':
                    # Prefer sessions from trusted devices
                    trusted_sessions = [s for s in sessions if s.is_trusted_device]
                    untrusted_sessions = [s for s in sessions if not s.is_trusted_device]
                    
                    if trusted_sessions:
                        # Keep most recent trusted session
                        trusted_sorted = sorted(trusted_sessions, key=lambda s: s.last_activity, reverse=True)
                        sessions_to_terminate = trusted_sorted[1:] + untrusted_sessions
                    else:
                        # No trusted sessions, keep most recent
                        sessions_sorted = sorted(sessions, key=lambda s: s.last_activity, reverse=True)
                        sessions_to_terminate = sessions_sorted[1:]
                
                # Add resolution actions
                for session in sessions_to_terminate:
                    resolution_actions.append({
                        'action': 'terminate',
                        'session_id': session.session_id,
                        'reason': f'conflict_resolution_{strategy}',
                        'device_fingerprint': device_fp[:8] + '...',
                        'last_activity': session.last_activity.isoformat()
                    })
        
        # Apply resolution if auto_resolve is enabled
        applied_actions = []
        if auto_resolve and resolution_actions:
            for action in resolution_actions:
                if action['action'] == 'terminate':
                    success = terminate_user_session(
                        session_id=action['session_id'],
                        terminated_by=user,
                        reason=action['reason']
                    )
                    
                    if success:
                        applied_actions.append(action)
        
        return Response({
            'conflicts_found': len(conflicts) > 0,
            'conflicts_count': len(conflicts),
            'conflicts': conflicts,
            'resolution_strategy': strategy,
            'resolution_actions': resolution_actions,
            'auto_resolve_enabled': auto_resolve,
            'applied_actions': applied_actions,
            'applied_actions_count': len(applied_actions)
        })
        
    except Exception as e:
        logger.error(f"Error resolving session conflicts: {e}")
        return Response(
            {'error': 'Failed to resolve session conflicts'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )