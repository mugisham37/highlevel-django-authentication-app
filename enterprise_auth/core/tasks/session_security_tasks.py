"""
Celery tasks for session security monitoring.

This module provides background tasks for automated session security
monitoring, threat detection, and response actions.
"""

import logging
from datetime import timedelta
from typing import Dict, Any, List

from celery import shared_task
from django.utils import timezone
from django.db.models import Q
from django.conf import settings

from ..models.session import UserSession
from ..models.security import SessionSecurityEvent, SecurityEvent
from ..services.session_security_service import session_security_service


logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def monitor_active_sessions(self, hours: int = 1, high_risk_only: bool = False):
    """
    Monitor active sessions for security threats and anomalies.
    
    Args:
        hours: Monitor sessions active within last N hours
        high_risk_only: Only monitor high-risk sessions
        
    Returns:
        Dictionary with monitoring results
    """
    try:
        logger.info(f"Starting automated session security monitoring (hours={hours})")
        
        # Build query for sessions to monitor
        query = Q(status='active')
        
        # Filter by activity timeframe
        since = timezone.now() - timedelta(hours=hours)
        query &= Q(last_activity__gte=since)
        
        # Filter by high risk only
        if high_risk_only:
            query &= Q(risk_score__gte=70.0)
        
        sessions = UserSession.objects.filter(query).select_related(
            'user', 'device_info'
        )
        
        results = {
            'task_id': self.request.id,
            'started_at': timezone.now().isoformat(),
            'total_sessions': sessions.count(),
            'sessions_monitored': 0,
            'anomalies_detected': 0,
            'threats_detected': 0,
            'actions_taken': 0,
            'high_risk_sessions': 0,
            'errors': 0,
            'session_summaries': [],
        }
        
        # Monitor each session
        for session in sessions:
            try:
                monitoring_result = session_security_service.monitor_session_security(session)
                
                results['sessions_monitored'] += 1
                
                # Update counters
                if monitoring_result['anomalies_detected']:
                    results['anomalies_detected'] += len(monitoring_result['anomalies_detected'])
                
                if monitoring_result['threats_detected']:
                    results['threats_detected'] += len(monitoring_result['threats_detected'])
                
                if monitoring_result['actions_taken']:
                    results['actions_taken'] += len(monitoring_result['actions_taken'])
                
                if monitoring_result['risk_score'] >= 70.0:
                    results['high_risk_sessions'] += 1
                
                # Store summary for significant sessions
                if (monitoring_result['anomalies_detected'] or 
                    monitoring_result['threats_detected'] or
                    monitoring_result['risk_score'] >= 70.0):
                    
                    results['session_summaries'].append({
                        'session_id': session.session_id,
                        'user_id': str(session.user.id),
                        'risk_score': monitoring_result['risk_score'],
                        'anomalies_count': len(monitoring_result['anomalies_detected']),
                        'threats_count': len(monitoring_result['threats_detected']),
                        'actions_count': len(monitoring_result['actions_taken']),
                    })
                
            except Exception as e:
                results['errors'] += 1
                logger.error(
                    f"Error monitoring session {session.session_id}: {str(e)}",
                    extra={
                        'task_id': self.request.id,
                        'session_id': session.session_id,
                        'error': str(e),
                    }
                )
        
        results['completed_at'] = timezone.now().isoformat()
        
        logger.info(
            f"Session security monitoring completed: "
            f"{results['sessions_monitored']} sessions monitored, "
            f"{results['anomalies_detected']} anomalies, "
            f"{results['threats_detected']} threats, "
            f"{results['actions_taken']} actions taken",
            extra={'task_id': self.request.id, 'results': results}
        )
        
        return results
        
    except Exception as e:
        logger.error(
            f"Error in session monitoring task: {str(e)}",
            extra={'task_id': self.request.id, 'error': str(e)}
        )
        raise self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=3)
def analyze_session_patterns(self, user_id: str = None, days: int = 7):
    """
    Analyze session patterns for behavioral anomaly detection.
    
    Args:
        user_id: Specific user to analyze (optional)
        days: Number of days to analyze
        
    Returns:
        Dictionary with pattern analysis results
    """
    try:
        logger.info(f"Starting session pattern analysis (days={days})")
        
        # Build query for sessions to analyze
        since = timezone.now() - timedelta(days=days)
        query = Q(created_at__gte=since)
        
        if user_id:
            query &= Q(user__id=user_id)
        
        sessions = UserSession.objects.filter(query).select_related('user', 'device_info')
        
        results = {
            'task_id': self.request.id,
            'started_at': timezone.now().isoformat(),
            'analysis_period_days': days,
            'total_sessions': sessions.count(),
            'users_analyzed': 0,
            'patterns_detected': [],
            'recommendations': [],
        }
        
        # Group sessions by user for pattern analysis
        user_sessions = {}
        for session in sessions:
            user_id = str(session.user.id)
            if user_id not in user_sessions:
                user_sessions[user_id] = []
            user_sessions[user_id].append(session)
        
        results['users_analyzed'] = len(user_sessions)
        
        # Analyze patterns for each user
        for user_id, user_session_list in user_sessions.items():
            try:
                patterns = _analyze_user_session_patterns(user_session_list)
                if patterns:
                    results['patterns_detected'].extend(patterns)
                    
            except Exception as e:
                logger.error(
                    f"Error analyzing patterns for user {user_id}: {str(e)}",
                    extra={'task_id': self.request.id, 'user_id': user_id, 'error': str(e)}
                )
        
        # Generate recommendations
        results['recommendations'] = _generate_pattern_recommendations(results['patterns_detected'])
        results['completed_at'] = timezone.now().isoformat()
        
        logger.info(
            f"Session pattern analysis completed: "
            f"{results['users_analyzed']} users analyzed, "
            f"{len(results['patterns_detected'])} patterns detected",
            extra={'task_id': self.request.id}
        )
        
        return results
        
    except Exception as e:
        logger.error(
            f"Error in session pattern analysis task: {str(e)}",
            extra={'task_id': self.request.id, 'error': str(e)}
        )
        raise self.retry(exc=e, countdown=120)


@shared_task(bind=True)
def cleanup_old_security_events(self, days: int = None):
    """
    Clean up old security events beyond retention period.
    
    Args:
        days: Number of days to retain (uses configured default if not provided)
        
    Returns:
        Dictionary with cleanup results
    """
    try:
        logger.info("Starting security events cleanup")
        
        # Use configured retention period if not specified
        retention_days = days or getattr(settings, 'SESSION_FORENSICS_RETENTION_DAYS', 90)
        
        results = {
            'task_id': self.request.id,
            'started_at': timezone.now().isoformat(),
            'retention_days': retention_days,
            'session_events_deleted': 0,
            'security_events_deleted': 0,
        }
        
        # Clean up session security events
        session_events_deleted = session_security_service.cleanup_old_security_events(retention_days)
        results['session_events_deleted'] = session_events_deleted
        
        # Clean up general security events
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        old_security_events = SecurityEvent.objects.filter(created_at__lt=cutoff_date)
        security_events_count = old_security_events.count()
        old_security_events.delete()
        results['security_events_deleted'] = security_events_count
        
        results['completed_at'] = timezone.now().isoformat()
        
        logger.info(
            f"Security events cleanup completed: "
            f"{session_events_deleted} session events, "
            f"{security_events_count} security events deleted",
            extra={'task_id': self.request.id}
        )
        
        return results
        
    except Exception as e:
        logger.error(
            f"Error in security events cleanup task: {str(e)}",
            extra={'task_id': self.request.id, 'error': str(e)}
        )
        raise


@shared_task(bind=True, max_retries=3)
def generate_security_report(self, days: int = 7):
    """
    Generate comprehensive security monitoring report.
    
    Args:
        days: Number of days to include in report
        
    Returns:
        Dictionary with security report data
    """
    try:
        logger.info(f"Generating security report for last {days} days")
        
        since = timezone.now() - timedelta(days=days)
        
        # Collect security statistics
        session_events = SessionSecurityEvent.objects.filter(created_at__gte=since)
        security_events = SecurityEvent.objects.filter(created_at__gte=since)
        sessions = UserSession.objects.filter(created_at__gte=since)
        
        report = {
            'task_id': self.request.id,
            'report_period_days': days,
            'generated_at': timezone.now().isoformat(),
            'period_start': since.isoformat(),
            'period_end': timezone.now().isoformat(),
            
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
                'total_session_events': session_events.count(),
                'total_security_events': security_events.count(),
                'critical_events': session_events.filter(risk_level='critical').count(),
                'high_risk_events': session_events.filter(risk_level='high').count(),
                'events_requiring_review': session_events.filter(requires_manual_review=True).count(),
            },
            
            # Event type breakdown
            'event_types': dict(
                session_events.values_list('event_type')
                .annotate(count=models.Count('id'))
                .order_by('-count')
            ),
            
            # Risk level distribution
            'risk_levels': dict(
                session_events.values_list('risk_level')
                .annotate(count=models.Count('id'))
            ),
            
            # Top threat indicators
            'threat_indicators': _get_top_threat_indicators(session_events),
            
            # Automated actions taken
            'automated_actions': _get_automated_actions_summary(session_events),
            
            # Recommendations
            'recommendations': _generate_security_recommendations(session_events, sessions),
        }
        
        logger.info(
            f"Security report generated: "
            f"{report['session_stats']['total_sessions']} sessions, "
            f"{report['security_event_stats']['total_session_events']} events analyzed",
            extra={'task_id': self.request.id}
        )
        
        return report
        
    except Exception as e:
        logger.error(
            f"Error generating security report: {str(e)}",
            extra={'task_id': self.request.id, 'error': str(e)}
        )
        raise self.retry(exc=e, countdown=300)


@shared_task(bind=True)
def update_threat_intelligence(self):
    """
    Update threat intelligence data from external sources.
    
    Returns:
        Dictionary with update results
    """
    try:
        logger.info("Starting threat intelligence update")
        
        results = {
            'task_id': self.request.id,
            'started_at': timezone.now().isoformat(),
            'sources_updated': 0,
            'indicators_added': 0,
            'indicators_updated': 0,
            'errors': 0,
        }
        
        # This would integrate with external threat intelligence feeds
        # For now, we'll implement a placeholder that could be extended
        
        # Example: Update IP reputation data
        # results.update(_update_ip_reputation_data())
        
        # Example: Update malicious user agent patterns
        # results.update(_update_user_agent_patterns())
        
        # Example: Update behavioral threat patterns
        # results.update(_update_behavioral_patterns())
        
        results['completed_at'] = timezone.now().isoformat()
        
        logger.info(
            f"Threat intelligence update completed: "
            f"{results['indicators_added']} new indicators, "
            f"{results['indicators_updated']} updated",
            extra={'task_id': self.request.id}
        )
        
        return results
        
    except Exception as e:
        logger.error(
            f"Error updating threat intelligence: {str(e)}",
            extra={'task_id': self.request.id, 'error': str(e)}
        )
        raise


# Helper functions

def _analyze_user_session_patterns(sessions: List[UserSession]) -> List[Dict[str, Any]]:
    """Analyze session patterns for a specific user."""
    patterns = []
    
    if len(sessions) < 3:
        return patterns  # Need at least 3 sessions for pattern analysis
    
    # Analyze login time patterns
    login_hours = [session.created_at.hour for session in sessions]
    hour_variance = _calculate_variance(login_hours)
    
    if hour_variance > 50:  # High variance in login times
        patterns.append({
            'type': 'irregular_login_times',
            'user_id': str(sessions[0].user.id),
            'description': 'User shows irregular login time patterns',
            'severity': 'medium',
            'data': {'hour_variance': hour_variance, 'login_hours': login_hours}
        })
    
    # Analyze location patterns
    locations = [(s.latitude, s.longitude) for s in sessions if s.latitude and s.longitude]
    if len(set(locations)) > len(locations) * 0.8:  # Too many different locations
        patterns.append({
            'type': 'excessive_location_diversity',
            'user_id': str(sessions[0].user.id),
            'description': 'User sessions from unusually diverse locations',
            'severity': 'high',
            'data': {'unique_locations': len(set(locations)), 'total_sessions': len(sessions)}
        })
    
    # Analyze device patterns
    devices = [session.device_info.device_fingerprint for session in sessions]
    if len(set(devices)) > 5:  # Too many different devices
        patterns.append({
            'type': 'excessive_device_diversity',
            'user_id': str(sessions[0].user.id),
            'description': 'User sessions from unusually many different devices',
            'severity': 'medium',
            'data': {'unique_devices': len(set(devices)), 'total_sessions': len(sessions)}
        })
    
    return patterns


def _calculate_variance(values: List[float]) -> float:
    """Calculate variance of a list of values."""
    if not values:
        return 0.0
    
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return variance


def _generate_pattern_recommendations(patterns: List[Dict[str, Any]]) -> List[str]:
    """Generate recommendations based on detected patterns."""
    recommendations = []
    
    pattern_types = [pattern['type'] for pattern in patterns]
    
    if 'irregular_login_times' in pattern_types:
        recommendations.append("Consider implementing time-based access controls for users with irregular login patterns")
    
    if 'excessive_location_diversity' in pattern_types:
        recommendations.append("Review users with high location diversity for potential account sharing")
    
    if 'excessive_device_diversity' in pattern_types:
        recommendations.append("Implement device registration and approval workflows")
    
    if len(patterns) > 10:
        recommendations.append("High number of behavioral patterns detected - consider adjusting detection thresholds")
    
    return recommendations


def _get_top_threat_indicators(session_events) -> List[Dict[str, Any]]:
    """Get top threat indicators from session events."""
    # Flatten all anomaly indicators
    all_indicators = []
    for event in session_events:
        all_indicators.extend(event.anomaly_indicators or [])
    
    # Count occurrences
    indicator_counts = {}
    for indicator in all_indicators:
        indicator_counts[indicator] = indicator_counts.get(indicator, 0) + 1
    
    # Return top 10 indicators
    return [
        {'indicator': indicator, 'count': count}
        for indicator, count in sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]


def _get_automated_actions_summary(session_events) -> Dict[str, int]:
    """Get summary of automated actions taken."""
    actions_summary = {}
    
    for event in session_events:
        action = event.action_taken
        if action:
            actions_summary[action] = actions_summary.get(action, 0) + 1
    
    return actions_summary


def _generate_security_recommendations(session_events, sessions) -> List[str]:
    """Generate security recommendations based on analysis."""
    recommendations = []
    
    # Check for high number of critical events
    critical_events = session_events.filter(risk_level='critical').count()
    if critical_events > 10:
        recommendations.append(f"High number of critical security events ({critical_events}) detected - review threat detection thresholds")
    
    # Check for high-risk sessions
    high_risk_sessions = sessions.filter(risk_score__gte=70.0).count()
    total_sessions = sessions.count()
    
    if total_sessions > 0 and (high_risk_sessions / total_sessions) > 0.1:
        recommendations.append("More than 10% of sessions are high-risk - consider tightening security policies")
    
    # Check for unreviewed events
    unreviewed_events = session_events.filter(requires_manual_review=True, reviewed_at__isnull=True).count()
    if unreviewed_events > 5:
        recommendations.append(f"{unreviewed_events} security events require manual review")
    
    return recommendations