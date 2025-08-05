"""
Advanced session management service.

This service provides comprehensive session lifecycle management with
device tracking, risk scoring, and security monitoring capabilities.
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple

from django.db import transaction
from django.db.models import Q
from django.http import HttpRequest
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

from ..models.session import UserSession, DeviceInfo, SessionActivity
from ..models.user import UserProfile
from ..utils.device_fingerprinting import DeviceFingerprinter, generate_device_fingerprint
from ..utils.geolocation import GeolocationService, get_client_ip, enrich_session_with_location


logger = logging.getLogger(__name__)


class SessionService:
    """
    Comprehensive session management service.
    
    Handles session creation, validation, tracking, and security monitoring
    with advanced device fingerprinting and risk assessment.
    """
    
    def __init__(self):
        self.geolocation_service = GeolocationService()
        self.device_fingerprinter = DeviceFingerprinter()
        self.session_timeout_hours = getattr(settings, 'SESSION_TIMEOUT_HOURS', 24)
        self.max_concurrent_sessions = getattr(settings, 'MAX_CONCURRENT_SESSIONS', 5)
        self.trusted_device_threshold = getattr(settings, 'TRUSTED_DEVICE_THRESHOLD', 0.8)
    
    @transaction.atomic
    def create_session(self, user: UserProfile, request: HttpRequest, 
                      login_method: str, additional_data: Optional[Dict[str, Any]] = None) -> UserSession:
        """
        Create a new user session with comprehensive tracking.
        
        Args:
            user: User profile for the session
            request: HTTP request object
            login_method: Authentication method used
            additional_data: Additional client-side data for fingerprinting
            
        Returns:
            Created UserSession instance
        """
        # Generate device fingerprint and extract device info
        fingerprint, device_info_data = generate_device_fingerprint(request, additional_data)
        
        # Get or create device info
        device_info = self._get_or_create_device_info(fingerprint, device_info_data)
        
        # Get client IP and location data
        ip_address = get_client_ip(request)
        location_data = self.geolocation_service.get_location_data(ip_address)
        
        # Generate unique session ID
        session_id = self._generate_session_id()
        
        # Calculate session expiration
        expires_at = timezone.now() + timedelta(hours=self.session_timeout_hours)
        
        # Create session
        session = UserSession.objects.create(
            session_id=session_id,
            user=user,
            device_info=device_info,
            ip_address=ip_address,
            country=location_data.get('country', ''),
            region=location_data.get('region', ''),
            city=location_data.get('city', ''),
            latitude=location_data.get('latitude'),
            longitude=location_data.get('longitude'),
            isp=location_data.get('isp', ''),
            login_method=login_method,
            expires_at=expires_at,
            is_trusted_device=device_info.is_trusted,
        )
        
        # Calculate and update risk score
        risk_score = session.calculate_risk_score()
        session.risk_score = risk_score
        session.save(update_fields=['risk_score', 'risk_factors'])
        
        # Log session creation activity
        self._log_session_activity(
            session=session,
            activity_type='login',
            endpoint=request.path,
            method=request.method,
            additional_data={
                'login_method': login_method,
                'risk_score': risk_score,
                'device_fingerprint': fingerprint,
            }
        )
        
        # Enforce concurrent session limits
        self._enforce_concurrent_session_limits(user)
        
        # Update device trust status if applicable
        self._update_device_trust_status(device_info, user)
        
        logger.info(
            f"Session created for user {user.email} "
            f"(session_id: {session_id}, risk_score: {risk_score:.2f})"
        )
        
        return session
    
    def validate_session(self, session_id: str) -> Tuple[bool, Optional[UserSession], Dict[str, Any]]:
        """
        Validate a session and return validation details.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            Tuple of (is_valid, session_object, validation_details)
        """
        validation_details = {
            'exists': False,
            'active': False,
            'expired': False,
            'terminated': False,
            'risk_level': 'unknown',
        }
        
        try:
            session = UserSession.objects.select_related('user', 'device_info').get(
                session_id=session_id
            )
            validation_details['exists'] = True
            
            # Check if session is active
            if session.is_active:
                validation_details['active'] = True
                validation_details['risk_level'] = self._get_risk_level(session.risk_score)
                
                # Update last activity
                session.update_activity()
                
                return True, session, validation_details
            
            # Check specific reasons for inactivity
            if session.is_expired:
                validation_details['expired'] = True
            
            if session.terminated_at:
                validation_details['terminated'] = True
            
            return False, session, validation_details
            
        except UserSession.DoesNotExist:
            return False, None, validation_details
    
    def terminate_session(self, session_id: str, terminated_by: Optional[UserProfile] = None, 
                         reason: str = '') -> bool:
        """
        Terminate a specific session.
        
        Args:
            session_id: Session ID to terminate
            terminated_by: User who terminated the session
            reason: Reason for termination
            
        Returns:
            True if session was terminated successfully
        """
        try:
            session = UserSession.objects.get(session_id=session_id)
            
            if session.status != 'terminated':
                session.terminate(terminated_by=terminated_by, reason=reason)
                
                # Log termination activity
                self._log_session_activity(
                    session=session,
                    activity_type='logout',
                    additional_data={
                        'termination_reason': reason,
                        'terminated_by': terminated_by.email if terminated_by else 'system',
                    }
                )
                
                # Clear session from cache
                self._clear_session_cache(session_id)
                
                logger.info(f"Session {session_id} terminated by {terminated_by or 'system'}: {reason}")
                
                return True
            
            return False
            
        except UserSession.DoesNotExist:
            return False
    
    def terminate_user_sessions(self, user: UserProfile, exclude_session_id: Optional[str] = None,
                               reason: str = 'bulk_termination') -> int:
        """
        Terminate all active sessions for a user.
        
        Args:
            user: User whose sessions to terminate
            exclude_session_id: Session ID to exclude from termination
            reason: Reason for bulk termination
            
        Returns:
            Number of sessions terminated
        """
        sessions_query = UserSession.objects.filter(
            user=user,
            status='active'
        )
        
        if exclude_session_id:
            sessions_query = sessions_query.exclude(session_id=exclude_session_id)
        
        terminated_count = 0
        for session in sessions_query:
            if self.terminate_session(session.session_id, terminated_by=user, reason=reason):
                terminated_count += 1
        
        logger.info(f"Terminated {terminated_count} sessions for user {user.email}")
        
        return terminated_count
    
    def get_user_sessions(self, user: UserProfile, active_only: bool = True) -> List[UserSession]:
        """
        Get sessions for a user.
        
        Args:
            user: User to get sessions for
            active_only: Whether to return only active sessions
            
        Returns:
            List of UserSession objects
        """
        sessions_query = UserSession.objects.filter(user=user).select_related('device_info')
        
        if active_only:
            sessions_query = sessions_query.filter(status='active')
        
        return list(sessions_query.order_by('-last_activity'))
    
    def analyze_session_risk(self, session: UserSession) -> Dict[str, Any]:
        """
        Perform detailed risk analysis on a session.
        
        Args:
            session: Session to analyze
            
        Returns:
            Detailed risk analysis results
        """
        # Recalculate risk score with current data
        current_risk_score = session.calculate_risk_score()
        
        # Get location anomaly information
        is_location_anomaly, location_details = self.geolocation_service.is_location_anomaly(
            user_id=session.user.id,
            current_location={
                'country': session.country,
                'latitude': session.latitude,
                'longitude': session.longitude,
            }
        )
        
        # Analyze concurrent sessions
        concurrent_sessions = UserSession.objects.filter(
            user=session.user,
            status='active',
            created_at__gte=timezone.now() - timedelta(hours=1)
        ).exclude(id=session.id).count()
        
        # Check for device trust status
        device_trust_score = self._calculate_device_trust_score(session.device_info, session.user)
        
        risk_analysis = {
            'current_risk_score': current_risk_score,
            'risk_level': self._get_risk_level(current_risk_score),
            'risk_factors': session.risk_factors,
            'location_anomaly': {
                'is_anomaly': is_location_anomaly,
                'details': location_details,
            },
            'concurrent_sessions': concurrent_sessions,
            'device_trust_score': device_trust_score,
            'recommendations': self._generate_risk_recommendations(
                current_risk_score, is_location_anomaly, concurrent_sessions, device_trust_score
            ),
        }
        
        return risk_analysis
    
    def _get_or_create_device_info(self, fingerprint: str, device_data: Dict[str, Any]) -> DeviceInfo:
        """
        Get existing device info or create new one.
        
        Args:
            fingerprint: Device fingerprint hash
            device_data: Device information data
            
        Returns:
            DeviceInfo instance
        """
        try:
            device_info = DeviceInfo.objects.get(device_fingerprint=fingerprint)
            
            # Update last seen timestamp
            device_info.last_seen = timezone.now()
            device_info.save(update_fields=['last_seen'])
            
            return device_info
            
        except DeviceInfo.DoesNotExist:
            # Create new device info
            return DeviceInfo.objects.create(
                device_fingerprint=fingerprint,
                device_type=device_data.get('device_type', 'unknown'),
                browser=device_data.get('browser', ''),
                operating_system=device_data.get('operating_system', ''),
                screen_resolution=device_data.get('screen_resolution', ''),
                timezone_offset=device_data.get('timezone_offset'),
                language=device_data.get('language', ''),
                user_agent=device_data.get('user_agent', ''),
                device_characteristics=device_data.get('device_characteristics', {}),
            )
    
    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        return f"sess_{uuid.uuid4().hex}"
    
    def _enforce_concurrent_session_limits(self, user: UserProfile) -> None:
        """
        Enforce concurrent session limits for a user.
        
        Args:
            user: User to enforce limits for
        """
        active_sessions = UserSession.objects.filter(
            user=user,
            status='active'
        ).order_by('last_activity')
        
        if active_sessions.count() > self.max_concurrent_sessions:
            # Terminate oldest sessions
            sessions_to_terminate = active_sessions[:active_sessions.count() - self.max_concurrent_sessions]
            
            for session in sessions_to_terminate:
                self.terminate_session(
                    session.session_id,
                    reason='concurrent_session_limit_exceeded'
                )
    
    def _update_device_trust_status(self, device_info: DeviceInfo, user: UserProfile) -> None:
        """
        Update device trust status based on usage patterns.
        
        Args:
            device_info: Device to evaluate
            user: User associated with the device
        """
        if device_info.is_trusted:
            return  # Already trusted
        
        # Check if device should be trusted based on usage
        device_sessions = UserSession.objects.filter(
            user=user,
            device_info=device_info,
            status__in=['active', 'terminated']
        )
        
        # Trust criteria
        session_count = device_sessions.count()
        days_used = (timezone.now() - device_info.first_seen).days
        
        # Trust if device has been used multiple times over several days
        if session_count >= 5 and days_used >= 7:
            # Additional check: no high-risk sessions from this device
            high_risk_sessions = device_sessions.filter(risk_score__gte=70.0)
            
            if not high_risk_sessions.exists():
                device_info.is_trusted = True
                device_info.save(update_fields=['is_trusted'])
                
                logger.info(f"Device {device_info.device_fingerprint[:8]}... marked as trusted for user {user.email}")
    
    def _calculate_device_trust_score(self, device_info: DeviceInfo, user: UserProfile) -> float:
        """
        Calculate trust score for a device.
        
        Args:
            device_info: Device to evaluate
            user: User associated with the device
            
        Returns:
            Trust score between 0.0 and 1.0
        """
        if device_info.is_trusted:
            return 1.0
        
        trust_score = 0.0
        
        # Factor 1: Usage frequency (40% weight)
        device_sessions = UserSession.objects.filter(
            user=user,
            device_info=device_info
        )
        session_count = device_sessions.count()
        
        if session_count >= 10:
            trust_score += 0.4
        elif session_count >= 5:
            trust_score += 0.2
        elif session_count >= 2:
            trust_score += 0.1
        
        # Factor 2: Usage duration (30% weight)
        days_used = (timezone.now() - device_info.first_seen).days
        
        if days_used >= 30:
            trust_score += 0.3
        elif days_used >= 14:
            trust_score += 0.2
        elif days_used >= 7:
            trust_score += 0.1
        
        # Factor 3: Risk history (30% weight)
        from django.db.models import Avg
        avg_risk_score = device_sessions.aggregate(
            avg_risk=Avg('risk_score')
        )['avg_risk'] or 0.0
        
        if avg_risk_score < 20.0:
            trust_score += 0.3
        elif avg_risk_score < 40.0:
            trust_score += 0.2
        elif avg_risk_score < 60.0:
            trust_score += 0.1
        
        return min(trust_score, 1.0)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """
        Convert numeric risk score to risk level.
        
        Args:
            risk_score: Numeric risk score (0-100)
            
        Returns:
            Risk level string
        """
        if risk_score >= 80.0:
            return 'critical'
        elif risk_score >= 60.0:
            return 'high'
        elif risk_score >= 40.0:
            return 'medium'
        elif risk_score >= 20.0:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_risk_recommendations(self, risk_score: float, is_location_anomaly: bool,
                                     concurrent_sessions: int, device_trust_score: float) -> List[str]:
        """
        Generate risk-based recommendations.
        
        Args:
            risk_score: Current risk score
            is_location_anomaly: Whether location is anomalous
            concurrent_sessions: Number of concurrent sessions
            device_trust_score: Device trust score
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        if risk_score >= 80.0:
            recommendations.append("Consider terminating session immediately")
            recommendations.append("Require additional authentication")
        elif risk_score >= 60.0:
            recommendations.append("Monitor session closely")
            recommendations.append("Consider requiring MFA verification")
        
        if is_location_anomaly:
            recommendations.append("Verify user identity due to unusual location")
        
        if concurrent_sessions > 3:
            recommendations.append("Review concurrent sessions for suspicious activity")
        
        if device_trust_score < 0.3:
            recommendations.append("Device is not trusted - consider additional verification")
        
        return recommendations
    
    def _log_session_activity(self, session: UserSession, activity_type: str,
                             endpoint: str = '', method: str = '',
                             additional_data: Optional[Dict[str, Any]] = None) -> None:
        """
        Log session activity for audit and analysis.
        
        Args:
            session: Session to log activity for
            activity_type: Type of activity
            endpoint: API endpoint or page
            method: HTTP method
            additional_data: Additional activity data
        """
        SessionActivity.objects.create(
            session=session,
            activity_type=activity_type,
            endpoint=endpoint,
            method=method,
            user_agent=session.device_info.user_agent,
            ip_address=session.ip_address,
            activity_data=additional_data or {},
        )
    
    def _clear_session_cache(self, session_id: str) -> None:
        """
        Clear session-related cache entries.
        
        Args:
            session_id: Session ID to clear from cache
        """
        cache_keys = [
            f"session:{session_id}",
            f"session_validation:{session_id}",
        ]
        
        cache.delete_many(cache_keys)
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions and mark them as expired.
        
        Returns:
            Number of sessions cleaned up
        """
        from django.db.models import Q
        
        # Find sessions that are expired but not yet marked as such
        expired_sessions = UserSession.objects.filter(
            Q(expires_at__lt=timezone.now()) & 
            Q(status='active')
        )
        
        cleanup_count = 0
        for session in expired_sessions:
            session.status = 'expired'
            session.save(update_fields=['status'])
            
            # Log expiration activity
            self._log_session_activity(
                session=session,
                activity_type='logout',
                additional_data={
                    'termination_reason': 'session_expired',
                    'terminated_by': 'system',
                }
            )
            
            # Clear session from cache
            self._clear_session_cache(session.session_id)
            
            cleanup_count += 1
        
        if cleanup_count > 0:
            logger.info(f"Cleaned up {cleanup_count} expired sessions")
        
        return cleanup_count
    
    def cleanup_old_sessions(self, days: int = 90) -> int:
        """
        Clean up old terminated/expired sessions.
        
        Args:
            days: Number of days to keep sessions
            
        Returns:
            Number of sessions deleted
        """
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Delete old terminated and expired sessions
        old_sessions = UserSession.objects.filter(
            status__in=['terminated', 'expired'],
            created_at__lt=cutoff_date
        )
        
        deleted_count = old_sessions.count()
        old_sessions.delete()
        
        if deleted_count > 0:
            logger.info(f"Deleted {deleted_count} old sessions older than {days} days")
        
        return deleted_count
    
    def cleanup_old_session_activities(self, days: int = 90) -> int:
        """
        Clean up old session activities.
        
        Args:
            days: Number of days to keep activities
            
        Returns:
            Number of activities deleted
        """
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Delete old session activities
        old_activities = SessionActivity.objects.filter(
            timestamp__lt=cutoff_date
        )
        
        deleted_count = old_activities.count()
        old_activities.delete()
        
        if deleted_count > 0:
            logger.info(f"Deleted {deleted_count} old session activities older than {days} days")
        
        return deleted_count
    
    def cleanup_orphaned_device_info(self) -> int:
        """
        Clean up device info records that have no associated sessions.
        
        Returns:
            Number of device info records deleted
        """
        # Find device info records with no sessions
        orphaned_devices = DeviceInfo.objects.filter(
            sessions__isnull=True,
            last_seen__lt=timezone.now() - timedelta(days=30)
        )
        
        deleted_count = orphaned_devices.count()
        orphaned_devices.delete()
        
        if deleted_count > 0:
            logger.info(f"Deleted {deleted_count} orphaned device info records")
        
        return deleted_count
    
    def extend_session_expiration(self, session_id: str, hours: int = 24) -> bool:
        """
        Extend session expiration time.
        
        Args:
            session_id: Session ID to extend
            hours: Number of hours to extend
            
        Returns:
            True if session was extended successfully
        """
        try:
            session = UserSession.objects.get(session_id=session_id, status='active')
            session.extend_expiration(hours)
            
            # Log extension activity
            self._log_session_activity(
                session=session,
                activity_type='session_extended',
                additional_data={
                    'extended_hours': hours,
                    'new_expiration': session.expires_at.isoformat(),
                }
            )
            
            logger.info(f"Extended session {session_id} by {hours} hours")
            return True
            
        except UserSession.DoesNotExist:
            return False
    
    def get_session_statistics(self, user: Optional[UserProfile] = None) -> Dict[str, Any]:
        """
        Get session statistics.
        
        Args:
            user: Optional user to get statistics for (if None, get global stats)
            
        Returns:
            Dictionary containing session statistics
        """
        from django.db.models import Count, Avg
        
        sessions_query = UserSession.objects.all()
        if user:
            sessions_query = sessions_query.filter(user=user)
        
        # Basic counts
        stats = {
            'total_sessions': sessions_query.count(),
            'active_sessions': sessions_query.filter(status='active').count(),
            'expired_sessions': sessions_query.filter(status='expired').count(),
            'terminated_sessions': sessions_query.filter(status='terminated').count(),
            'suspicious_sessions': sessions_query.filter(status='suspicious').count(),
        }
        
        # Risk statistics
        risk_stats = sessions_query.aggregate(
            avg_risk_score=Avg('risk_score'),
            high_risk_sessions=Count('id', filter=Q(risk_score__gte=70.0)),
            medium_risk_sessions=Count('id', filter=Q(risk_score__gte=40.0, risk_score__lt=70.0)),
            low_risk_sessions=Count('id', filter=Q(risk_score__lt=40.0)),
        )
        stats.update(risk_stats)
        
        # Device statistics
        device_stats = sessions_query.values('device_info__device_type').annotate(
            count=Count('id')
        ).order_by('-count')
        stats['device_types'] = list(device_stats)
        
        # Geographic statistics
        geo_stats = sessions_query.exclude(country='').values('country').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        stats['top_countries'] = list(geo_stats)
        
        # Recent activity
        recent_sessions = sessions_query.filter(
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        stats['sessions_last_24h'] = recent_sessions
        
        return stats


# Convenience functions for common operations

def create_user_session(user: UserProfile, request: HttpRequest, login_method: str,
                       additional_data: Optional[Dict[str, Any]] = None) -> UserSession:
    """
    Convenience function to create a user session.
    
    Args:
        user: User profile
        request: HTTP request
        login_method: Authentication method
        additional_data: Additional fingerprinting data
        
    Returns:
        Created UserSession
    """
    service = SessionService()
    return service.create_session(user, request, login_method, additional_data)


def validate_user_session(session_id: str) -> Tuple[bool, Optional[UserSession], Dict[str, Any]]:
    """
    Convenience function to validate a session.
    
    Args:
        session_id: Session ID to validate
        
    Returns:
        Tuple of (is_valid, session, validation_details)
    """
    service = SessionService()
    return service.validate_session(session_id)


def terminate_user_session(session_id: str, terminated_by: Optional[UserProfile] = None,
                          reason: str = '') -> bool:
    """
    Convenience function to terminate a session.
    
    Args:
        session_id: Session ID to terminate
        terminated_by: User who terminated the session
        reason: Termination reason
        
    Returns:
        True if terminated successfully
    """
    service = SessionService()
    return service.terminate_session(session_id, terminated_by, reason)


def cleanup_expired_sessions() -> int:
    """
    Convenience function to cleanup expired sessions.
    
    Returns:
        Number of sessions cleaned up
    """
    service = SessionService()
    return service.cleanup_expired_sessions()


def cleanup_old_sessions(days: int = 90) -> int:
    """
    Convenience function to cleanup old sessions.
    
    Args:
        days: Number of days to keep sessions
        
    Returns:
        Number of sessions deleted
    """
    service = SessionService()
    return service.cleanup_old_sessions(days)


def cleanup_old_session_activities(days: int = 90) -> int:
    """
    Convenience function to cleanup old session activities.
    
    Args:
        days: Number of days to keep activities
        
    Returns:
        Number of activities cleaned up
    """
    service = SessionService()
    return service.cleanup_old_session_activities(days)


def cleanup_orphaned_device_info() -> int:
    """
    Convenience function to cleanup orphaned device info records.
    
    Returns:
        Number of device info records deleted
    """
    service = SessionService()
    return service.cleanup_orphaned_device_info()


def extend_session_expiration(session_id: str, hours: int = 24) -> bool:
    """
    Convenience function to extend session expiration.
    
    Args:
        session_id: Session ID to extend
        hours: Number of hours to extend
        
    Returns:
        True if extended successfully
    """
    service = SessionService()
    return service.extend_session_expiration(session_id, hours)


def get_session_statistics(user: Optional[UserProfile] = None) -> Dict[str, Any]:
    """
    Convenience function to get session statistics.
    
    Args:
        user: Optional user to get statistics for
        
    Returns:
        Dictionary containing session statistics
    """
    service = SessionService()
    return service.get_session_statistics(user)