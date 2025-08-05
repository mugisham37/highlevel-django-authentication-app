"""
API views for session security monitoring and forensics.

This module provides REST API endpoints for session security monitoring,
threat analysis, forensic investigation, and security event management.
"""

import logging
from datetime import timedelta
from typing import Dict, Any

from django.http import JsonResponse
from django.utils import timezone
from django.db.models import Q, Count
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ..models.session import UserSession
from ..models.security import SessionSecurityEvent, SecurityEvent, ThreatIntelligence
from ..models.user import UserProfile
from ..services.session_security_service import session_security_service
from ..tasks.session_security_tasks import (
    monitor_active_sessions,
    analyze_session_patterns,
    generate_security_report,
)


logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def monitor_session(request):
    """
    Monitor a specific session for security threats.
    
    POST /api/v1/security/sessions/{session_id}/monitor
    """
    try:
        session_id = request.data.get('session_id')
        if not session_id:
            return Response({
                'error': 'session_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get session
        try:
            session = UserSession.objects.select_related('user', 'device_info').get(
                session_id=session_id
            )
        except UserSession.DoesNotExist:
            return Response({
                'error': 'Session not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check permissions (users can only monitor their own sessions, admins can monitor any)
        if not request.user.is_staff and session.user != request.user:
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Perform monitoring
        monitoring_result = session_security_service.monitor_session_security(session)
        
        return Response({
            'session_id': session_id,
            'monitoring_result': monitoring_result,
            'timestamp': timezone.now().isoformat(),
        })
        
    except Exception as e:
        logger.error(f"Error in monitor_session API: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_session_forensics(request, session_id):
    """
    Get comprehensive forensic data for a session.
    
    GET /api/v1/security/sessions/{session_id}/forensics
    """
    try:
        # Get session
        try:
            session = UserSession.objects.select_related('user', 'device_info').get(
                session_id=session_id
            )
        except UserSession.DoesNotExist:
            return Response({
                'error': 'Session not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check permissions
        if not request.user.is_staff and session.user != request.user:
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get forensic data
        forensic_data = session_security_service.get_session_forensics(session)
        
        return Response(forensic_data)
        
    except Exception as e:
        logger.error(f"Error in get_session_forensics API: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_security_events(request):
    """
    List security events with filtering and pagination.
    
    GET /api/v1/security/events
    """
    try:
        # Build query
        query = Q()
        
        # Filter by user (non-staff can only see their own events)
        if not request.user.is_staff:
            query &= Q(session__user=request.user)
        elif request.GET.get('user_id'):
            query &= Q(session__user__id=request.GET['user_id'])
        
        # Filter by event type
        if request.GET.get('event_type'):
            query &= Q(event_type=request.GET['event_type'])
        
        # Filter by risk level
        if request.GET.get('risk_level'):
            query &= Q(risk_level=request.GET['risk_level'])
        
        # Filter by date range
        if request.GET.get('start_date'):
            start_date = timezone.datetime.fromisoformat(request.GET['start_date'])
            query &= Q(created_at__gte=start_date)
        
        if request.GET.get('end_date'):
            end_date = timezone.datetime.fromisoformat(request.GET['end_date'])
            query &= Q(created_at__lte=end_date)
        
        # Filter by review status
        if request.GET.get('requires_review') == 'true':
            query &= Q(requires_manual_review=True, reviewed_at__isnull=True)
        
        # Get events
        events = SessionSecurityEvent.objects.filter(query).select_related(
            'session__user'
        ).order_by('-created_at')
        
        # Pagination
        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('page_size', 20)), 100)
        
        paginator = Paginator(events, page_size)
        page_obj = paginator.get_page(page)
        
        # Serialize events
        events_data = []
        for event in page_obj:
            events_data.append({
                'id': str(event.id),
                'session_id': event.session.session_id,
                'user_email': event.session.user.email if request.user.is_staff else None,
                'event_type': event.event_type,
                'risk_level': event.risk_level,
                'description': event.description,
                'risk_score': event.risk_score,
                'created_at': event.created_at.isoformat(),
                'anomaly_indicators': event.anomaly_indicators,
                'action_taken': event.action_taken,
                'requires_manual_review': event.requires_manual_review,
                'reviewed_at': event.reviewed_at.isoformat() if event.reviewed_at else None,
            })
        
        return Response({
            'events': events_data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': paginator.num_pages,
                'total_count': paginator.count,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous(),
            }
        })
        
    except Exception as e:
        logger.error(f"Error in list_security_events API: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def review_security_event(request, event_id):
    """
    Mark a security event as reviewed.
    
    POST /api/v1/security/events/{event_id}/review
    """
    try:
        # Get event
        try:
            event = SessionSecurityEvent.objects.select_related('session__user').get(
                id=event_id
            )
        except SessionSecurityEvent.DoesNotExist:
            return Response({
                'error': 'Security event not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check permissions (only staff can review events)
        if not request.user.is_staff:
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get review notes
        notes = request.data.get('notes', '')
        
        # Mark as reviewed
        event.mark_reviewed(request.user, notes)
        
        return Response({
            'event_id': str(event.id),
            'reviewed_by': request.user.email,
            'reviewed_at': event.reviewed_at.isoformat(),
            'notes': notes,
        })
        
    except Exception as e:
        logger.error(f"Error in review_security_event API: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_security_dashboard(request):
    """
    Get security monitoring dashboard data.
    
    GET /api/v1/security/dashboard
    """
    try:
        # Check permissions (only staff can access dashboard)
        if not request.user.is_staff:
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get time range
        days = int(request.GET.get('days', 7))
        since = timezone.now() - timedelta(days=days)
        
        # Collect statistics
        session_events = SessionSecurityEvent.objects.filter(created_at__gte=since)
        sessions = UserSession.objects.filter(created_at__gte=since)
        
        dashboard_data = {
            'period_days': days,
            'generated_at': timezone.now().isoformat(),
            
            # Session statistics
            'session_stats': {
                'total_sessions': sessions.count(),
                'active_sessions': sessions.filter(status='active').count(),
                'high_risk_sessions': sessions.filter(risk_score__gte=70.0).count(),
                'terminated_sessions': sessions.filter(status='terminated').count(),
                'suspicious_sessions': sessions.filter(status='suspicious').count(),
            },
            
            # Security event statistics
            'security_event_stats': {
                'total_events': session_events.count(),
                'critical_events': session_events.filter(risk_level='critical').count(),
                'high_risk_events': session_events.filter(risk_level='high').count(),
                'events_requiring_review': session_events.filter(
                    requires_manual_review=True, 
                    reviewed_at__isnull=True
                ).count(),
            },
            
            # Event type breakdown
            'event_types': dict(
                session_events.values('event_type')
                .annotate(count=Count('id'))
                .values_list('event_type', 'count')
            ),
            
            # Risk level distribution
            'risk_levels': dict(
                session_events.values('risk_level')
                .annotate(count=Count('id'))
                .values_list('risk_level', 'count')
            ),
            
            # Recent high-risk events
            'recent_high_risk_events': [
                {
                    'id': str(event.id),
                    'session_id': event.session.session_id,
                    'event_type': event.event_type,
                    'risk_level': event.risk_level,
                    'risk_score': event.risk_score,
                    'created_at': event.created_at.isoformat(),
                    'description': event.description,
                }
                for event in session_events.filter(
                    risk_level__in=['high', 'critical']
                ).order_by('-created_at')[:10]
            ],
        }
        
        return Response(dashboard_data)
        
    except Exception as e:
        logger.error(f"Error in get_security_dashboard API: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def trigger_monitoring_task(request):
    """
    Trigger background monitoring task.
    
    POST /api/v1/security/monitor/trigger
    """
    try:
        # Check permissions (only staff can trigger monitoring)
        if not request.user.is_staff:
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get parameters
        hours = int(request.data.get('hours', 1))
        high_risk_only = request.data.get('high_risk_only', False)
        
        # Trigger monitoring task
        task = monitor_active_sessions.delay(hours=hours, high_risk_only=high_risk_only)
        
        return Response({
            'task_id': task.id,
            'status': 'started',
            'parameters': {
                'hours': hours,
                'high_risk_only': high_risk_only,
            },
            'started_at': timezone.now().isoformat(),
        })
        
    except Exception as e:
        logger.error(f"Error in trigger_monitoring_task API: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_report(request):
    """
    Generate security monitoring report.
    
    POST /api/v1/security/reports/generate
    """
    try:
        # Check permissions (only staff can generate reports)
        if not request.user.is_staff:
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get parameters
        days = int(request.data.get('days', 7))
        
        # Trigger report generation task
        task = generate_security_report.delay(days=days)
        
        return Response({
            'task_id': task.id,
            'status': 'started',
            'parameters': {
                'days': days,
            },
            'started_at': timezone.now().isoformat(),
        })
        
    except Exception as e:
        logger.error(f"Error in generate_report API: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_sessions_security(request):
    """
    Get security information for user's sessions.
    
    GET /api/v1/security/sessions/my
    """
    try:
        # Get user's sessions
        sessions = UserSession.objects.filter(
            user=request.user
        ).select_related('device_info').order_by('-last_activity')
        
        # Get security events for user's sessions
        security_events = SessionSecurityEvent.objects.filter(
            session__user=request.user
        ).order_by('-created_at')[:20]  # Last 20 events
        
        sessions_data = []
        for session in sessions:
            sessions_data.append({
                'session_id': session.session_id,
                'status': session.status,
                'risk_score': session.risk_score,
                'location': session.location_string,
                'device_type': session.device_info.device_type,
                'browser': session.device_info.browser,
                'is_trusted_device': session.device_info.is_trusted,
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'is_current': session.session_id == request.session.get('session_id'),
            })
        
        events_data = []
        for event in security_events:
            events_data.append({
                'id': str(event.id),
                'session_id': event.session.session_id,
                'event_type': event.event_type,
                'risk_level': event.risk_level,
                'description': event.description,
                'created_at': event.created_at.isoformat(),
                'action_taken': event.action_taken,
            })
        
        return Response({
            'sessions': sessions_data,
            'recent_security_events': events_data,
            'security_summary': {
                'total_sessions': len(sessions_data),
                'high_risk_sessions': len([s for s in sessions_data if s['risk_score'] >= 70.0]),
                'trusted_devices': len([s for s in sessions_data if s['is_trusted_device']]),
                'recent_events_count': len(events_data),
            }
        })
        
    except Exception as e:
        logger.error(f"Error in get_user_sessions_security API: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def terminate_suspicious_session(request, session_id):
    """
    Terminate a suspicious session.
    
    POST /api/v1/security/sessions/{session_id}/terminate
    """
    try:
        # Get session
        try:
            session = UserSession.objects.select_related('user').get(
                session_id=session_id
            )
        except UserSession.DoesNotExist:
            return Response({
                'error': 'Session not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check permissions (users can terminate their own sessions, staff can terminate any)
        if not request.user.is_staff and session.user != request.user:
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get termination reason
        reason = request.data.get('reason', 'user_requested_termination')
        
        # Terminate session
        session.terminate(terminated_by=request.user, reason=reason)
        
        # Log security event
        SessionSecurityEvent.objects.create(
            session=session,
            event_type='session_terminated',
            risk_level='medium',
            description=f'Session terminated by {request.user.email}: {reason}',
            risk_score=session.risk_score,
            detection_algorithm='manual_termination',
            confidence_level=1.0,
            current_session_data={
                'terminated_by': request.user.email,
                'reason': reason,
                'timestamp': timezone.now().isoformat(),
            },
            action_taken='terminate_session',
            action_details={'manual_termination': True},
        )
        
        return Response({
            'session_id': session_id,
            'status': 'terminated',
            'terminated_by': request.user.email,
            'reason': reason,
            'terminated_at': session.terminated_at.isoformat(),
        })
        
    except Exception as e:
        logger.error(f"Error in terminate_suspicious_session API: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)