"""
Celery tasks for session management and cleanup.

This module provides background tasks for session lifecycle management
including automated cleanup of expired sessions and related data.
"""

import logging
from celery import shared_task
from django.utils import timezone
from datetime import timedelta

from ..services.session_service import (
    cleanup_expired_sessions,
    cleanup_old_sessions,
    cleanup_old_session_activities,
    cleanup_orphaned_device_info,
    get_session_statistics,
)


logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def cleanup_expired_sessions_task(self):
    """
    Celery task to cleanup expired sessions.
    
    This task marks expired sessions as expired and clears their cache entries.
    Should be run frequently (e.g., every 15 minutes).
    """
    try:
        cleaned_count = cleanup_expired_sessions()
        
        logger.info(f"Session cleanup task completed: {cleaned_count} expired sessions marked")
        
        return {
            'status': 'success',
            'expired_sessions_marked': cleaned_count,
            'timestamp': timezone.now().isoformat(),
        }
        
    except Exception as exc:
        logger.error(f"Session cleanup task failed: {exc}")
        
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def cleanup_old_sessions_task(self, session_days=90, activity_days=90):
    """
    Celery task to cleanup old sessions and activities.
    
    This task deletes old terminated/expired sessions and their activities.
    Should be run daily.
    
    Args:
        session_days: Number of days to keep old sessions
        activity_days: Number of days to keep session activities
    """
    try:
        results = {}
        
        # Cleanup old sessions
        old_sessions_count = cleanup_old_sessions(session_days)
        results['old_sessions_deleted'] = old_sessions_count
        
        # Cleanup old session activities
        old_activities_count = cleanup_old_session_activities(activity_days)
        results['old_activities_deleted'] = old_activities_count
        
        # Cleanup orphaned device info
        orphaned_devices_count = cleanup_orphaned_device_info()
        results['orphaned_devices_deleted'] = orphaned_devices_count
        
        total_cleaned = old_sessions_count + old_activities_count + orphaned_devices_count
        
        logger.info(
            f"Old session cleanup task completed: "
            f"{old_sessions_count} sessions, "
            f"{old_activities_count} activities, "
            f"{orphaned_devices_count} device records deleted"
        )
        
        results.update({
            'status': 'success',
            'total_items_deleted': total_cleaned,
            'timestamp': timezone.now().isoformat(),
        })
        
        return results
        
    except Exception as exc:
        logger.error(f"Old session cleanup task failed: {exc}")
        
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def generate_session_statistics_task(self):
    """
    Celery task to generate and log session statistics.
    
    This task generates comprehensive session statistics for monitoring
    and alerting purposes. Should be run hourly or daily.
    """
    try:
        stats = get_session_statistics()
        
        # Log key statistics
        logger.info(
            f"Session statistics: "
            f"Total: {stats['total_sessions']}, "
            f"Active: {stats['active_sessions']}, "
            f"Expired: {stats['expired_sessions']}, "
            f"High Risk: {stats.get('high_risk_sessions', 0)}, "
            f"Last 24h: {stats['sessions_last_24h']}"
        )
        
        # Check for anomalies and alert if necessary
        alerts = []
        
        # Alert if too many high-risk sessions
        high_risk_percentage = (
            stats.get('high_risk_sessions', 0) / max(stats['total_sessions'], 1) * 100
        )
        if high_risk_percentage > 10:  # More than 10% high-risk
            alerts.append(f"High percentage of high-risk sessions: {high_risk_percentage:.1f}%")
        
        # Alert if too many active sessions
        if stats['active_sessions'] > 10000:  # Configurable threshold
            alerts.append(f"High number of active sessions: {stats['active_sessions']}")
        
        # Alert if unusual activity spike
        if stats['sessions_last_24h'] > stats['total_sessions'] * 0.5:  # More than 50% of all sessions in last 24h
            alerts.append(f"Unusual session activity spike: {stats['sessions_last_24h']} sessions in last 24h")
        
        if alerts:
            logger.warning(f"Session statistics alerts: {'; '.join(alerts)}")
        
        stats.update({
            'status': 'success',
            'alerts': alerts,
            'timestamp': timezone.now().isoformat(),
        })
        
        return stats
        
    except Exception as exc:
        logger.error(f"Session statistics task failed: {exc}")
        
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def terminate_suspicious_sessions_task(self, risk_threshold=80.0):
    """
    Celery task to automatically terminate suspicious sessions.
    
    This task finds sessions with high risk scores and terminates them
    for security purposes. Should be run frequently.
    
    Args:
        risk_threshold: Risk score threshold for automatic termination
    """
    try:
        from ..models.session import UserSession
        from ..services.session_service import SessionService
        
        # Find high-risk active sessions
        suspicious_sessions = UserSession.objects.filter(
            status='active',
            risk_score__gte=risk_threshold
        )
        
        terminated_count = 0
        session_service = SessionService()
        
        for session in suspicious_sessions:
            # Perform additional risk analysis
            risk_analysis = session_service.analyze_session_risk(session)
            
            # Terminate if risk is confirmed
            if risk_analysis['current_risk_score'] >= risk_threshold:
                success = session_service.terminate_session(
                    session.session_id,
                    reason=f'automatic_termination_high_risk_{risk_analysis["current_risk_score"]:.1f}'
                )
                
                if success:
                    terminated_count += 1
                    logger.warning(
                        f"Automatically terminated high-risk session {session.session_id} "
                        f"for user {session.user.email} (risk score: {risk_analysis['current_risk_score']:.1f})"
                    )
        
        logger.info(f"Suspicious session termination task completed: {terminated_count} sessions terminated")
        
        return {
            'status': 'success',
            'sessions_terminated': terminated_count,
            'risk_threshold': risk_threshold,
            'timestamp': timezone.now().isoformat(),
        }
        
    except Exception as exc:
        logger.error(f"Suspicious session termination task failed: {exc}")
        
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=120 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def update_device_trust_scores_task(self):
    """
    Celery task to update device trust scores.
    
    This task recalculates trust scores for devices and marks
    qualifying devices as trusted. Should be run daily.
    """
    try:
        from ..models.session import DeviceInfo
        from ..services.session_service import SessionService
        
        session_service = SessionService()
        updated_count = 0
        
        # Get devices that are not yet trusted
        untrusted_devices = DeviceInfo.objects.filter(is_trusted=False)
        
        for device in untrusted_devices:
            # Get users who have used this device
            users = device.sessions.values_list('user', flat=True).distinct()
            
            for user_id in users:
                from ..models.user import UserProfile
                try:
                    user = UserProfile.objects.get(id=user_id)
                    trust_score = session_service._calculate_device_trust_score(device, user)
                    
                    # Mark as trusted if score is high enough
                    if trust_score >= session_service.trusted_device_threshold:
                        device.is_trusted = True
                        device.save(update_fields=['is_trusted'])
                        updated_count += 1
                        
                        logger.info(
                            f"Device {device.device_fingerprint[:8]}... marked as trusted "
                            f"for user {user.email} (trust score: {trust_score:.2f})"
                        )
                        break  # Device is now trusted, no need to check other users
                        
                except UserProfile.DoesNotExist:
                    continue
        
        logger.info(f"Device trust update task completed: {updated_count} devices marked as trusted")
        
        return {
            'status': 'success',
            'devices_marked_trusted': updated_count,
            'timestamp': timezone.now().isoformat(),
        }
        
    except Exception as exc:
        logger.error(f"Device trust update task failed: {exc}")
        
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))