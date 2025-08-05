"""
Session security monitoring service.

This service provides comprehensive session security monitoring with
suspicious session detection, anomaly scoring, alerting, and automated
response capabilities.
"""

import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass

from django.db import transaction
from django.db.models import Q, Count, Avg
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

from ..models.session import UserSession, DeviceInfo, SessionActivity
from ..models.security import SecurityEvent, SessionSecurityEvent, ThreatIntelligence
from ..models.user import UserProfile
from ..exceptions import SecurityThreatDetectedError


logger = logging.getLogger(__name__)


@dataclass
class AnomalyScore:
    """Data class for anomaly scoring results."""
    score: float
    confidence: float
    indicators: List[str]
    risk_level: str
    recommendations: List[str]


@dataclass
class ThreatAnalysis:
    """Data class for threat analysis results."""
    threat_detected: bool
    threat_type: str
    risk_score: float
    confidence: float
    indicators: List[str]
    recommended_actions: List[str]


class SessionSecurityMonitoringService:
    """
    Comprehensive session security monitoring service.
    
    Provides real-time session security monitoring, suspicious activity detection,
    anomaly scoring, automated alerting, and threat response capabilities.
    """
    
    def __init__(self):
        """Initialize the session security monitoring service."""
        # Configuration settings
        self.high_risk_threshold = getattr(settings, 'SESSION_HIGH_RISK_THRESHOLD', 70.0)
        self.critical_risk_threshold = getattr(settings, 'SESSION_CRITICAL_RISK_THRESHOLD', 90.0)
        self.anomaly_detection_enabled = getattr(settings, 'SESSION_ANOMALY_DETECTION_ENABLED', True)
        self.auto_terminate_high_risk = getattr(settings, 'AUTO_TERMINATE_HIGH_RISK_SESSIONS', True)
        self.forensics_retention_days = getattr(settings, 'SESSION_FORENSICS_RETENTION_DAYS', 90)
        
        # Anomaly detection thresholds
        self.location_anomaly_threshold = getattr(settings, 'LOCATION_ANOMALY_THRESHOLD', 0.7)
        self.behavioral_anomaly_threshold = getattr(settings, 'BEHAVIORAL_ANOMALY_THRESHOLD', 0.8)
        self.device_anomaly_threshold = getattr(settings, 'DEVICE_ANOMALY_THRESHOLD', 0.6)
        
        # Alert configuration
        self.alert_high_risk_sessions = getattr(settings, 'ALERT_HIGH_RISK_SESSIONS', True)
        self.alert_impossible_travel = getattr(settings, 'ALERT_IMPOSSIBLE_TRAVEL', True)
        self.alert_session_sharing = getattr(settings, 'ALERT_SESSION_SHARING', True)
        
        # Cache keys
        self.cache_prefix = 'session_security'
        self.threat_intel_cache_timeout = 3600  # 1 hour
    
    def monitor_session_security(self, session: UserSession) -> Dict[str, Any]:
        """
        Perform comprehensive security monitoring on a session.
        
        Args:
            session: Session to monitor
            
        Returns:
            Dictionary with monitoring results and actions taken
        """
        monitoring_results = {
            'session_id': session.session_id,
            'user_id': str(session.user.id),
            'timestamp': timezone.now().isoformat(),
            'anomalies_detected': [],
            'threats_detected': [],
            'actions_taken': [],
            'risk_score': session.risk_score,
            'requires_investigation': False,
        }
        
        try:
            # 1. Detect suspicious session patterns
            suspicious_patterns = self._detect_suspicious_patterns(session)
            if suspicious_patterns:
                monitoring_results['anomalies_detected'].extend(suspicious_patterns)
            
            # 2. Perform anomaly scoring
            anomaly_score = self._calculate_session_anomaly_score(session)
            monitoring_results['anomaly_score'] = {
                'score': anomaly_score.score,
                'confidence': anomaly_score.confidence,
                'risk_level': anomaly_score.risk_level,
                'indicators': anomaly_score.indicators,
            }
            
            # 3. Analyze threats using threat intelligence
            threat_analysis = self._analyze_session_threats(session)
            if threat_analysis.threat_detected:
                monitoring_results['threats_detected'].append({
                    'type': threat_analysis.threat_type,
                    'risk_score': threat_analysis.risk_score,
                    'confidence': threat_analysis.confidence,
                    'indicators': threat_analysis.indicators,
                })
            
            # 4. Check for impossible travel
            impossible_travel = self._detect_impossible_travel(session)
            if impossible_travel:
                monitoring_results['anomalies_detected'].append('impossible_travel')
                self._create_security_event(
                    session=session,
                    event_type='impossible_travel',
                    risk_level='high',
                    description=f"Impossible travel detected: {impossible_travel['details']}",
                    anomaly_indicators=['impossible_travel'],
                )
            
            # 5. Detect session sharing
            session_sharing = self._detect_session_sharing(session)
            if session_sharing:
                monitoring_results['anomalies_detected'].append('session_sharing')
                self._create_security_event(
                    session=session,
                    event_type='session_sharing',
                    risk_level='high',
                    description=f"Session sharing detected: {session_sharing['details']}",
                    anomaly_indicators=['concurrent_locations', 'rapid_location_changes'],
                )
            
            # 6. Behavioral anomaly detection
            behavioral_anomalies = self._detect_behavioral_anomalies(session)
            if behavioral_anomalies:
                monitoring_results['anomalies_detected'].extend(behavioral_anomalies)
            
            # 7. Device anomaly detection
            device_anomalies = self._detect_device_anomalies(session)
            if device_anomalies:
                monitoring_results['anomalies_detected'].extend(device_anomalies)
            
            # 8. Determine if automated response is needed
            if self._requires_automated_response(session, anomaly_score, threat_analysis):
                actions = self._execute_automated_response(session, anomaly_score, threat_analysis)
                monitoring_results['actions_taken'].extend(actions)
            
            # 9. Update session risk score if needed
            new_risk_score = max(session.risk_score, anomaly_score.score, threat_analysis.risk_score)
            if new_risk_score > session.risk_score:
                session.risk_score = new_risk_score
                session.save(update_fields=['risk_score'])
                monitoring_results['risk_score'] = new_risk_score
            
            # 10. Determine if manual investigation is required
            monitoring_results['requires_investigation'] = (
                new_risk_score >= self.high_risk_threshold or
                threat_analysis.threat_detected or
                len(monitoring_results['anomalies_detected']) >= 3
            )
            
            # Log monitoring activity
            logger.info(
                f"Session security monitoring completed for session {session.session_id}",
                extra={
                    'session_id': session.session_id,
                    'user_id': str(session.user.id),
                    'anomalies_count': len(monitoring_results['anomalies_detected']),
                    'threats_count': len(monitoring_results['threats_detected']),
                    'risk_score': new_risk_score,
                }
            )
            
            return monitoring_results
            
        except Exception as e:
            logger.error(
                f"Error during session security monitoring: {str(e)}",
                extra={
                    'session_id': session.session_id,
                    'user_id': str(session.user.id),
                    'error': str(e),
                }
            )
            raise
    
    def _detect_suspicious_patterns(self, session: UserSession) -> List[str]:
        """
        Detect suspicious patterns in session behavior.
        
        Args:
            session: Session to analyze
            
        Returns:
            List of detected suspicious patterns
        """
        suspicious_patterns = []
        
        # Check for rapid location changes
        recent_activities = SessionActivity.objects.filter(
            session=session,
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).order_by('-timestamp')[:10]
        
        if recent_activities.count() >= 5:
            # Check for activities from different IPs in short time
            ip_addresses = set()
            for activity in recent_activities:
                if activity.ip_address:
                    ip_addresses.add(activity.ip_address)
            
            if len(ip_addresses) > 2:
                suspicious_patterns.append('rapid_ip_changes')
        
        # Check for unusual activity patterns
        activity_count = SessionActivity.objects.filter(
            session=session,
            timestamp__gte=timezone.now() - timedelta(minutes=10)
        ).count()
        
        if activity_count > 50:  # More than 50 activities in 10 minutes
            suspicious_patterns.append('high_activity_volume')
        
        # Check for suspicious endpoints
        suspicious_endpoints = ['/admin', '/api/internal', '/debug']
        recent_endpoints = SessionActivity.objects.filter(
            session=session,
            timestamp__gte=timezone.now() - timedelta(hours=1),
            endpoint__in=suspicious_endpoints
        )
        
        if recent_endpoints.exists():
            suspicious_patterns.append('suspicious_endpoint_access')
        
        # Check for failed authentication attempts
        failed_attempts = SessionActivity.objects.filter(
            session=session,
            activity_type__in=['login_failure', 'mfa_failure'],
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).count()
        
        if failed_attempts > 5:
            suspicious_patterns.append('multiple_auth_failures')
        
        return suspicious_patterns
    
    def _calculate_session_anomaly_score(self, session: UserSession) -> AnomalyScore:
        """
        Calculate comprehensive anomaly score for a session.
        
        Args:
            session: Session to analyze
            
        Returns:
            AnomalyScore object with detailed scoring
        """
        indicators = []
        total_score = 0.0
        confidence_factors = []
        
        # 1. Location anomaly (25% weight)
        location_score = self._calculate_location_anomaly_score(session)
        if location_score > 0:
            indicators.append(f'location_anomaly_score_{location_score:.1f}')
            total_score += location_score * 0.25
            confidence_factors.append(0.8)  # High confidence in location data
        
        # 2. Device anomaly (20% weight)
        device_score = self._calculate_device_anomaly_score(session)
        if device_score > 0:
            indicators.append(f'device_anomaly_score_{device_score:.1f}')
            total_score += device_score * 0.20
            confidence_factors.append(0.7)  # Medium-high confidence in device data
        
        # 3. Behavioral anomaly (25% weight)
        behavioral_score = self._calculate_behavioral_anomaly_score(session)
        if behavioral_score > 0:
            indicators.append(f'behavioral_anomaly_score_{behavioral_score:.1f}')
            total_score += behavioral_score * 0.25
            confidence_factors.append(0.6)  # Medium confidence in behavioral patterns
        
        # 4. Network anomaly (15% weight)
        network_score = self._calculate_network_anomaly_score(session)
        if network_score > 0:
            indicators.append(f'network_anomaly_score_{network_score:.1f}')
            total_score += network_score * 0.15
            confidence_factors.append(0.5)  # Lower confidence in network data
        
        # 5. Temporal anomaly (15% weight)
        temporal_score = self._calculate_temporal_anomaly_score(session)
        if temporal_score > 0:
            indicators.append(f'temporal_anomaly_score_{temporal_score:.1f}')
            total_score += temporal_score * 0.15
            confidence_factors.append(0.7)  # High confidence in temporal patterns
        
        # Calculate overall confidence
        overall_confidence = sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
        
        # Determine risk level
        if total_score >= self.critical_risk_threshold:
            risk_level = 'critical'
        elif total_score >= self.high_risk_threshold:
            risk_level = 'high'
        elif total_score >= 40.0:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Generate recommendations
        recommendations = self._generate_anomaly_recommendations(total_score, indicators)
        
        return AnomalyScore(
            score=min(total_score, 100.0),
            confidence=overall_confidence,
            indicators=indicators,
            risk_level=risk_level,
            recommendations=recommendations,
        )
    
    def _calculate_location_anomaly_score(self, session: UserSession) -> float:
        """Calculate location-based anomaly score."""
        if not session.latitude or not session.longitude:
            return 0.0
        
        # Get user's historical locations
        historical_sessions = UserSession.objects.filter(
            user=session.user,
            created_at__gte=timezone.now() - timedelta(days=30),
            latitude__isnull=False,
            longitude__isnull=False
        ).exclude(id=session.id)
        
        if not historical_sessions.exists():
            return 30.0  # New location for new user
        
        # Calculate distance from common locations
        from math import radians, sin, cos, sqrt, atan2
        
        min_distance = float('inf')
        for hist_session in historical_sessions:
            # Calculate distance using Haversine formula
            lat1, lon1 = radians(session.latitude), radians(session.longitude)
            lat2, lon2 = radians(hist_session.latitude), radians(hist_session.longitude)
            
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            c = 2 * atan2(sqrt(a), sqrt(1-a))
            distance_km = 6371 * c  # Earth's radius in km
            
            min_distance = min(min_distance, distance_km)
        
        # Score based on distance from nearest known location
        if min_distance > 5000:  # More than 5000km away
            return 80.0
        elif min_distance > 1000:  # More than 1000km away
            return 60.0
        elif min_distance > 500:  # More than 500km away
            return 40.0
        elif min_distance > 100:  # More than 100km away
            return 20.0
        else:
            return 0.0
    
    def _calculate_device_anomaly_score(self, session: UserSession) -> float:
        """Calculate device-based anomaly score."""
        device_score = 0.0
        
        # Check if device is known
        if not session.device_info.is_trusted:
            device_score += 25.0
        
        # Check device characteristics
        user_devices = DeviceInfo.objects.filter(
            sessions__user=session.user,
            sessions__created_at__gte=timezone.now() - timedelta(days=30)
        ).distinct()
        
        if user_devices.count() == 1 and user_devices.first() != session.device_info:
            device_score += 35.0  # Completely new device
        
        # Check for unusual device characteristics
        if session.device_info.device_type == 'unknown':
            device_score += 20.0
        
        # Check user agent anomalies
        common_browsers = ['Chrome', 'Firefox', 'Safari', 'Edge']
        if not any(browser in session.device_info.browser for browser in common_browsers):
            device_score += 15.0
        
        return min(device_score, 100.0)
    
    def _calculate_behavioral_anomaly_score(self, session: UserSession) -> float:
        """Calculate behavioral anomaly score."""
        behavioral_score = 0.0
        
        # Check login time patterns
        current_hour = session.created_at.hour
        historical_hours = UserSession.objects.filter(
            user=session.user,
            created_at__gte=timezone.now() - timedelta(days=30)
        ).exclude(id=session.id).values_list('created_at__hour', flat=True)
        
        if historical_hours:
            hour_frequency = list(historical_hours).count(current_hour) / len(historical_hours)
            if hour_frequency < 0.05:  # Less than 5% of logins at this hour
                behavioral_score += 30.0
        
        # Check session duration patterns
        if session.duration.total_seconds() > 0:
            avg_duration = UserSession.objects.filter(
                user=session.user,
                terminated_at__isnull=False,
                created_at__gte=timezone.now() - timedelta(days=30)
            ).exclude(id=session.id).aggregate(
                avg_duration=Avg('terminated_at') - Avg('created_at')
            )['avg_duration']
            
            if avg_duration and session.duration > avg_duration * 3:
                behavioral_score += 20.0  # Unusually long session
        
        # Check activity patterns
        recent_activity_count = SessionActivity.objects.filter(
            session=session,
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).count()
        
        if recent_activity_count > 100:  # Very high activity
            behavioral_score += 25.0
        elif recent_activity_count == 0:  # No activity (dormant session)
            behavioral_score += 15.0
        
        return min(behavioral_score, 100.0)
    
    def _calculate_network_anomaly_score(self, session: UserSession) -> float:
        """Calculate network-based anomaly score."""
        network_score = 0.0
        
        # Check IP reputation (placeholder - would integrate with threat intel)
        if self._is_suspicious_ip(session.ip_address):
            network_score += 50.0
        
        # Check for VPN/Proxy usage (placeholder)
        if self._is_vpn_or_proxy(session.ip_address):
            network_score += 30.0
        
        # Check ISP patterns
        user_isps = UserSession.objects.filter(
            user=session.user,
            created_at__gte=timezone.now() - timedelta(days=30)
        ).exclude(id=session.id).values_list('isp', flat=True).distinct()
        
        if session.isp and session.isp not in user_isps:
            network_score += 20.0  # New ISP
        
        return min(network_score, 100.0)
    
    def _calculate_temporal_anomaly_score(self, session: UserSession) -> float:
        """Calculate temporal anomaly score."""
        temporal_score = 0.0
        
        # Check for rapid successive logins
        recent_sessions = UserSession.objects.filter(
            user=session.user,
            created_at__gte=session.created_at - timedelta(minutes=5),
            created_at__lt=session.created_at
        ).count()
        
        if recent_sessions > 0:
            temporal_score += 40.0  # Multiple logins in 5 minutes
        
        # Check for unusual login frequency
        today_sessions = UserSession.objects.filter(
            user=session.user,
            created_at__date=session.created_at.date()
        ).count()
        
        if today_sessions > 10:  # More than 10 sessions today
            temporal_score += 25.0
        
        return min(temporal_score, 100.0)
    
    def _analyze_session_threats(self, session: UserSession) -> ThreatAnalysis:
        """
        Analyze session for known threats using threat intelligence.
        
        Args:
            session: Session to analyze
            
        Returns:
            ThreatAnalysis object
        """
        threat_detected = False
        threat_type = ''
        risk_score = 0.0
        confidence = 0.0
        indicators = []
        recommended_actions = []
        
        # Check IP against threat intelligence
        ip_threats = ThreatIntelligence.objects.filter(
            indicator_type='ip_address',
            indicator_value=str(session.ip_address),
            is_active=True
        )
        
        if ip_threats.exists():
            threat_detected = True
            threat_type = 'malicious_ip'
            highest_threat = ip_threats.order_by('-severity_score').first()
            risk_score = highest_threat.severity_score
            confidence = 0.9 if highest_threat.confidence == 'verified' else 0.7
            indicators.append(f'malicious_ip_{highest_threat.threat_type}')
            recommended_actions.append('terminate_session')
            recommended_actions.append('block_ip')
        
        # Check user agent against threat intelligence
        ua_threats = ThreatIntelligence.objects.filter(
            indicator_type='user_agent',
            indicator_value=session.device_info.user_agent,
            is_active=True
        )
        
        if ua_threats.exists():
            threat_detected = True
            if not threat_type:
                threat_type = 'malicious_user_agent'
            highest_ua_threat = ua_threats.order_by('-severity_score').first()
            risk_score = max(risk_score, highest_ua_threat.severity_score)
            indicators.append(f'malicious_user_agent_{highest_ua_threat.threat_type}')
            recommended_actions.append('flag_for_review')
        
        # Check for behavioral patterns matching known threats
        behavioral_threats = self._check_behavioral_threat_patterns(session)
        if behavioral_threats:
            threat_detected = True
            if not threat_type:
                threat_type = 'behavioral_threat'
            risk_score = max(risk_score, behavioral_threats['risk_score'])
            indicators.extend(behavioral_threats['indicators'])
            recommended_actions.extend(behavioral_threats['actions'])
        
        return ThreatAnalysis(
            threat_detected=threat_detected,
            threat_type=threat_type,
            risk_score=risk_score,
            confidence=confidence,
            indicators=indicators,
            recommended_actions=recommended_actions,
        )
    
    def _check_behavioral_threat_patterns(self, session: UserSession) -> Optional[Dict[str, Any]]:
        """Check for behavioral patterns matching known threats."""
        # Check for credential stuffing patterns
        failed_logins = SessionActivity.objects.filter(
            session__ip_address=session.ip_address,
            activity_type='login_failure',
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).count()
        
        if failed_logins > 20:  # High number of failed logins from same IP
            return {
                'risk_score': 85.0,
                'indicators': ['credential_stuffing_pattern'],
                'actions': ['rate_limit_ip', 'alert_security_team'],
            }
        
        # Check for session hijacking patterns
        if self._detect_session_hijacking_patterns(session):
            return {
                'risk_score': 90.0,
                'indicators': ['session_hijacking_pattern'],
                'actions': ['terminate_session', 'alert_security_team'],
            }
        
        return None
    
    def _detect_impossible_travel(self, session: UserSession) -> Optional[Dict[str, Any]]:
        """Detect impossible travel between sessions."""
        if not session.latitude or not session.longitude:
            return None
        
        # Get the most recent session from a different location
        previous_session = UserSession.objects.filter(
            user=session.user,
            created_at__lt=session.created_at,
            latitude__isnull=False,
            longitude__isnull=False
        ).exclude(
            latitude=session.latitude,
            longitude=session.longitude
        ).order_by('-created_at').first()
        
        if not previous_session:
            return None
        
        # Calculate distance and time difference
        from math import radians, sin, cos, sqrt, atan2
        
        lat1, lon1 = radians(previous_session.latitude), radians(previous_session.longitude)
        lat2, lon2 = radians(session.latitude), radians(session.longitude)
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        distance_km = 6371 * c
        
        time_diff_hours = (session.created_at - previous_session.created_at).total_seconds() / 3600
        
        # Maximum reasonable travel speed (including flights): 1000 km/h
        max_speed_kmh = 1000
        max_possible_distance = max_speed_kmh * time_diff_hours
        
        if distance_km > max_possible_distance and time_diff_hours < 24:
            return {
                'detected': True,
                'details': f"Travel of {distance_km:.0f}km in {time_diff_hours:.1f}h "
                          f"(max possible: {max_possible_distance:.0f}km)",
                'distance_km': distance_km,
                'time_hours': time_diff_hours,
                'previous_location': f"{previous_session.city}, {previous_session.country}",
                'current_location': f"{session.city}, {session.country}",
            }
        
        return None
    
    def _detect_session_sharing(self, session: UserSession) -> Optional[Dict[str, Any]]:
        """Detect potential session sharing."""
        # Check for concurrent sessions from different locations
        concurrent_sessions = UserSession.objects.filter(
            user=session.user,
            status='active',
            last_activity__gte=timezone.now() - timedelta(minutes=5)
        ).exclude(id=session.id)
        
        if not concurrent_sessions.exists():
            return None
        
        # Check if sessions are from significantly different locations
        for concurrent_session in concurrent_sessions:
            if (concurrent_session.latitude and concurrent_session.longitude and
                session.latitude and session.longitude):
                
                # Calculate distance
                from math import radians, sin, cos, sqrt, atan2
                
                lat1, lon1 = radians(concurrent_session.latitude), radians(concurrent_session.longitude)
                lat2, lon2 = radians(session.latitude), radians(session.longitude)
                
                dlat = lat2 - lat1
                dlon = lon2 - lon1
                
                a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
                c = 2 * atan2(sqrt(a), sqrt(1-a))
                distance_km = 6371 * c
                
                # If sessions are more than 100km apart and active within 5 minutes
                if distance_km > 100:
                    return {
                        'detected': True,
                        'details': f"Concurrent sessions {distance_km:.0f}km apart",
                        'distance_km': distance_km,
                        'concurrent_session_id': concurrent_session.session_id,
                        'locations': [
                            f"{session.city}, {session.country}",
                            f"{concurrent_session.city}, {concurrent_session.country}"
                        ],
                    }
        
        return None
    
    def _detect_behavioral_anomalies(self, session: UserSession) -> List[str]:
        """Detect behavioral anomalies in session."""
        anomalies = []
        
        # Check for unusual activity patterns
        activity_types = SessionActivity.objects.filter(
            session=session,
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).values_list('activity_type', flat=True)
        
        activity_counts = {}
        for activity_type in activity_types:
            activity_counts[activity_type] = activity_counts.get(activity_type, 0) + 1
        
        # Check for excessive API calls
        if activity_counts.get('api_call', 0) > 100:
            anomalies.append('excessive_api_calls')
        
        # Check for rapid permission checks
        if activity_counts.get('permission_check', 0) > 50:
            anomalies.append('excessive_permission_checks')
        
        # Check for unusual endpoint access patterns
        suspicious_endpoints = SessionActivity.objects.filter(
            session=session,
            endpoint__icontains='admin',
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).count()
        
        if suspicious_endpoints > 10:
            anomalies.append('suspicious_admin_access')
        
        return anomalies
    
    def _detect_device_anomalies(self, session: UserSession) -> List[str]:
        """Detect device-related anomalies."""
        anomalies = []
        
        # Check for device fingerprint anomalies
        user_devices = DeviceInfo.objects.filter(
            sessions__user=session.user,
            sessions__created_at__gte=timezone.now() - timedelta(days=30)
        ).distinct()
        
        if user_devices.count() > 10:  # Too many different devices
            anomalies.append('excessive_device_diversity')
        
        # Check for unusual device characteristics
        if session.device_info.device_type == 'unknown':
            anomalies.append('unknown_device_type')
        
        # Check for automated/bot-like user agents
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper']
        if any(indicator in session.device_info.user_agent.lower() for indicator in bot_indicators):
            anomalies.append('bot_like_user_agent')
        
        return anomalies
    
    def _detect_session_hijacking_patterns(self, session: UserSession) -> bool:
        """Detect patterns indicative of session hijacking."""
        # Check for sudden changes in session characteristics
        recent_activities = SessionActivity.objects.filter(
            session=session,
            timestamp__gte=timezone.now() - timedelta(minutes=30)
        ).order_by('timestamp')
        
        if recent_activities.count() < 2:
            return False
        
        # Check for IP address changes within the session
        ip_addresses = set()
        user_agents = set()
        
        for activity in recent_activities:
            if activity.ip_address:
                ip_addresses.add(activity.ip_address)
            if activity.user_agent:
                user_agents.add(activity.user_agent)
        
        # Multiple IPs or user agents in short time could indicate hijacking
        return len(ip_addresses) > 2 or len(user_agents) > 1
    
    def _requires_automated_response(self, session: UserSession, 
                                   anomaly_score: AnomalyScore, 
                                   threat_analysis: ThreatAnalysis) -> bool:
        """Determine if automated response is required."""
        return (
            anomaly_score.score >= self.critical_risk_threshold or
            threat_analysis.threat_detected or
            session.risk_score >= self.critical_risk_threshold
        )
    
    def _execute_automated_response(self, session: UserSession, 
                                  anomaly_score: AnomalyScore, 
                                  threat_analysis: ThreatAnalysis) -> List[str]:
        """Execute automated response actions."""
        actions_taken = []
        
        try:
            # Determine response actions based on threat level
            if threat_analysis.threat_detected and 'terminate_session' in threat_analysis.recommended_actions:
                # Terminate high-risk session
                session.terminate(reason='automated_security_response_high_risk')
                actions_taken.append('session_terminated')
                
                # Create security event
                self._create_security_event(
                    session=session,
                    event_type='session_terminated',
                    risk_level='critical',
                    description=f"Session automatically terminated due to threat detection: {threat_analysis.threat_type}",
                    anomaly_indicators=threat_analysis.indicators,
                    action_taken='terminate_session',
                )
            
            elif anomaly_score.score >= self.critical_risk_threshold:
                # Mark session as suspicious and require re-authentication
                session.status = 'suspicious'
                session.save(update_fields=['status'])
                actions_taken.append('session_marked_suspicious')
                
                # Create security event
                self._create_security_event(
                    session=session,
                    event_type='session_anomaly',
                    risk_level='high',
                    description=f"Session marked as suspicious due to high anomaly score: {anomaly_score.score:.1f}",
                    anomaly_indicators=anomaly_score.indicators,
                    action_taken='mark_suspicious',
                )
            
            # Additional response actions
            if 'block_ip' in threat_analysis.recommended_actions:
                # This would integrate with firewall/WAF to block the IP
                actions_taken.append('ip_blocked')
                logger.warning(f"IP {session.ip_address} should be blocked (threat detected)")
            
            if 'alert_security_team' in threat_analysis.recommended_actions:
                # This would send alerts to security team
                actions_taken.append('security_team_alerted')
                logger.critical(
                    f"Security team alert: High-risk session detected",
                    extra={
                        'session_id': session.session_id,
                        'user_id': str(session.user.id),
                        'threat_type': threat_analysis.threat_type,
                        'risk_score': threat_analysis.risk_score,
                    }
                )
            
            return actions_taken
            
        except Exception as e:
            logger.error(
                f"Error executing automated response: {str(e)}",
                extra={
                    'session_id': session.session_id,
                    'error': str(e),
                }
            )
            return actions_taken
    
    def _create_security_event(self, session: UserSession, event_type: str, 
                             risk_level: str, description: str,
                             anomaly_indicators: List[str], 
                             action_taken: str = '') -> SessionSecurityEvent:
        """Create a session security event record."""
        try:
            return SessionSecurityEvent.objects.create(
                session=session,
                event_type=event_type,
                risk_level=risk_level,
                description=description,
                risk_score=session.risk_score,
                detection_algorithm='session_security_monitoring',
                confidence_level=0.8,
                current_session_data={
                    'ip_address': str(session.ip_address),
                    'location': session.location_string,
                    'device_fingerprint': session.device_info.device_fingerprint,
                    'user_agent': session.device_info.user_agent,
                    'risk_score': session.risk_score,
                },
                anomaly_indicators=anomaly_indicators,
                action_taken=action_taken,
                action_details={'automated_response': True, 'timestamp': timezone.now().isoformat()},
                requires_manual_review=risk_level in ['high', 'critical'],
            )
        except Exception as e:
            logger.error(f"Failed to create security event: {str(e)}")
            raise
    
    def _generate_anomaly_recommendations(self, score: float, indicators: List[str]) -> List[str]:
        """Generate recommendations based on anomaly score and indicators."""
        recommendations = []
        
        if score >= self.critical_risk_threshold:
            recommendations.extend([
                'Terminate session immediately',
                'Require multi-factor authentication',
                'Alert security team',
                'Block IP address if malicious',
            ])
        elif score >= self.high_risk_threshold:
            recommendations.extend([
                'Mark session as suspicious',
                'Require additional authentication',
                'Monitor closely',
                'Investigate manually',
            ])
        elif score >= 40.0:
            recommendations.extend([
                'Increase monitoring frequency',
                'Log additional details',
                'Consider user notification',
            ])
        
        # Specific recommendations based on indicators
        if any('location' in indicator for indicator in indicators):
            recommendations.append('Verify user location through secondary channel')
        
        if any('device' in indicator for indicator in indicators):
            recommendations.append('Request device verification')
        
        if any('behavioral' in indicator for indicator in indicators):
            recommendations.append('Analyze user behavior patterns')
        
        return recommendations
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious (placeholder for threat intel integration)."""
        # This would integrate with threat intelligence feeds
        # For now, return False as placeholder
        return False
    
    def _is_vpn_or_proxy(self, ip_address: str) -> bool:
        """Check if IP address is from VPN or proxy (placeholder)."""
        # This would integrate with IP intelligence services
        # For now, return False as placeholder
        return False
    
    def get_session_forensics(self, session: UserSession) -> Dict[str, Any]:
        """
        Get comprehensive forensic data for a session.
        
        Args:
            session: Session to analyze
            
        Returns:
            Dictionary with forensic data
        """
        try:
            # Get all security events for this session
            security_events = SessionSecurityEvent.objects.filter(
                session=session
            ).order_by('-created_at')
            
            # Get all activities for this session
            activities = SessionActivity.objects.filter(
                session=session
            ).order_by('-timestamp')
            
            # Calculate session statistics
            activity_stats = {
                'total_activities': activities.count(),
                'unique_endpoints': activities.values('endpoint').distinct().count(),
                'unique_ips': activities.values('ip_address').distinct().count(),
                'activity_types': dict(
                    activities.values('activity_type')
                    .annotate(count=Count('id'))
                    .values_list('activity_type', 'count')
                ),
            }
            
            # Get related sessions (same user, similar timeframe)
            related_sessions = UserSession.objects.filter(
                user=session.user,
                created_at__gte=session.created_at - timedelta(hours=2),
                created_at__lte=session.created_at + timedelta(hours=2)
            ).exclude(id=session.id)
            
            forensic_data = {
                'session_info': {
                    'session_id': session.session_id,
                    'user_id': str(session.user.id),
                    'user_email': session.user.email,
                    'created_at': session.created_at.isoformat(),
                    'last_activity': session.last_activity.isoformat(),
                    'status': session.status,
                    'risk_score': session.risk_score,
                    'location': session.location_string,
                    'ip_address': str(session.ip_address),
                    'device_info': {
                        'fingerprint': session.device_info.device_fingerprint,
                        'type': session.device_info.device_type,
                        'browser': session.device_info.browser,
                        'os': session.device_info.operating_system,
                        'is_trusted': session.device_info.is_trusted,
                    },
                },
                'security_events': [
                    {
                        'id': str(event.id),
                        'event_type': event.event_type,
                        'risk_level': event.risk_level,
                        'description': event.description,
                        'risk_score': event.risk_score,
                        'created_at': event.created_at.isoformat(),
                        'anomaly_indicators': event.anomaly_indicators,
                        'action_taken': event.action_taken,
                    }
                    for event in security_events
                ],
                'activity_summary': activity_stats,
                'recent_activities': [
                    {
                        'timestamp': activity.timestamp.isoformat(),
                        'activity_type': activity.activity_type,
                        'endpoint': activity.endpoint,
                        'method': activity.method,
                        'status_code': activity.status_code,
                        'ip_address': str(activity.ip_address) if activity.ip_address else None,
                    }
                    for activity in activities[:50]  # Last 50 activities
                ],
                'related_sessions': [
                    {
                        'session_id': rel_session.session_id,
                        'created_at': rel_session.created_at.isoformat(),
                        'status': rel_session.status,
                        'risk_score': rel_session.risk_score,
                        'location': rel_session.location_string,
                        'ip_address': str(rel_session.ip_address),
                    }
                    for rel_session in related_sessions
                ],
                'analysis_timestamp': timezone.now().isoformat(),
            }
            
            return forensic_data
            
        except Exception as e:
            logger.error(
                f"Error generating session forensics: {str(e)}",
                extra={
                    'session_id': session.session_id,
                    'error': str(e),
                }
            )
            raise
    
    def cleanup_old_security_events(self, days: int = None) -> int:
        """
        Clean up old security events beyond retention period.
        
        Args:
            days: Number of days to retain (defaults to configured retention)
            
        Returns:
            Number of events cleaned up
        """
        retention_days = days or self.forensics_retention_days
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        try:
            # Clean up session security events
            old_events = SessionSecurityEvent.objects.filter(
                created_at__lt=cutoff_date
            )
            count = old_events.count()
            old_events.delete()
            
            logger.info(f"Cleaned up {count} old session security events")
            return count
            
        except Exception as e:
            logger.error(f"Error cleaning up old security events: {str(e)}")
            return 0


# Global service instance
session_security_service = SessionSecurityMonitoringService()