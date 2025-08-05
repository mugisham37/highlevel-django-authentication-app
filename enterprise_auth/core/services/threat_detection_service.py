"""
Comprehensive threat detection service for enterprise authentication system.

This service provides real-time threat analysis, behavioral pattern detection,
IP reputation checking, and automated threat response capabilities.
"""

import asyncio
import hashlib
import json
import logging
import math
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import Q, Count, Avg, Max
from django.utils import timezone
from django.contrib.gis.geoip2 import GeoIP2
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import Distance

import requests
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..models import (
    UserProfile, UserSession, SecurityEvent, ThreatIntelligence,
    SessionSecurityEvent
)
from ..exceptions import (
    SecurityError, ThreatDetectedError, SuspiciousActivityError,
    RateLimitExceededError
)
from .audit_service import audit_service


logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of security threats."""
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ACCOUNT_TAKEOVER = "account_takeover"
    SUSPICIOUS_LOGIN = "suspicious_login"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    DEVICE_ANOMALY = "device_anomaly"
    LOCATION_ANOMALY = "location_anomaly"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    SESSION_HIJACK = "session_hijack"
    API_ABUSE = "api_abuse"
    MALICIOUS_IP = "malicious_ip"
    BOT_ACTIVITY = "bot_activity"
    RATE_LIMIT_ABUSE = "rate_limit_abuse"


@dataclass
class ThreatIndicator:
    """Individual threat indicator."""
    type: str
    value: str
    weight: float
    confidence: float
    description: str
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ThreatAnalysis:
    """Comprehensive threat analysis result."""
    risk_score: float
    threat_level: ThreatLevel
    threat_types: List[ThreatType]
    indicators: List[ThreatIndicator]
    confidence: float
    recommended_actions: List[str]
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'risk_score': self.risk_score,
            'threat_level': self.threat_level.value,
            'threat_types': [t.value for t in self.threat_types],
            'indicators': [asdict(i) for i in self.indicators],
            'confidence': self.confidence,
            'recommended_actions': self.recommended_actions,
            'metadata': self.metadata
        }


@dataclass
class LoginAttemptContext:
    """Context data for login attempt analysis."""
    user: Optional[UserProfile]
    ip_address: str
    user_agent: str
    timestamp: datetime
    success: bool
    session_id: Optional[str] = None
    device_fingerprint: Optional[str] = None
    location_data: Optional[Dict[str, Any]] = None
    request_headers: Optional[Dict[str, str]] = None
    correlation_id: Optional[str] = None


class ThreatDetectionService:
    """
    Comprehensive threat detection service with real-time analysis capabilities.
    
    Provides behavioral analysis, IP reputation checking, geographic analysis,
    and machine learning-based anomaly detection.
    """

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.geoip = self._initialize_geoip()
        self.ml_models = self._initialize_ml_models()
        
        # Threat detection thresholds
        self.risk_thresholds = {
            ThreatLevel.LOW: 25.0,
            ThreatLevel.MEDIUM: 50.0,
            ThreatLevel.HIGH: 75.0,
            ThreatLevel.CRITICAL: 90.0
        }
        
        # Cache keys
        self.cache_prefix = "threat_detection"
        self.ip_reputation_cache_ttl = 3600  # 1 hour
        self.behavioral_cache_ttl = 1800  # 30 minutes
        
    def _initialize_geoip(self) -> Optional[GeoIP2]:
        """Initialize GeoIP2 for geographic analysis."""
        try:
            return GeoIP2()
        except Exception as e:
            self.logger.warning(f"Failed to initialize GeoIP2: {e}")
            return None
    
    def _initialize_ml_models(self) -> Dict[str, Any]:
        """Initialize machine learning models for anomaly detection."""
        models = {}
        
        try:
            # Isolation Forest for behavioral anomaly detection
            models['behavioral_anomaly'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Standard scaler for feature normalization
            models['scaler'] = StandardScaler()
            
            self.logger.info("Machine learning models initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}")
        
        return models
    
    async def analyze_login_attempt(
        self,
        context: LoginAttemptContext
    ) -> ThreatAnalysis:
        """
        Perform comprehensive threat analysis on a login attempt.
        
        Args:
            context: Login attempt context data
            
        Returns:
            ThreatAnalysis: Comprehensive threat analysis result
        """
        self.logger.info(
            f"Analyzing login attempt for IP {context.ip_address}, "
            f"User: {context.user.email if context.user else 'Unknown'}, "
            f"Success: {context.success}"
        )
        
        indicators = []
        threat_types = []
        
        # Parallel analysis tasks
        analysis_tasks = [
            self._analyze_ip_reputation(context),
            self._analyze_geographic_anomalies(context),
            self._analyze_device_fingerprint(context),
            self._analyze_behavioral_patterns(context),
            self._analyze_velocity_patterns(context),
            self._analyze_threat_intelligence(context),
        ]
        
        # Execute analysis tasks concurrently
        analysis_results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        # Process results
        for result in analysis_results:
            if isinstance(result, Exception):
                self.logger.error(f"Analysis task failed: {result}")
                continue
            
            if result:
                result_indicators, result_threats = result
                indicators.extend(result_indicators)
                threat_types.extend(result_threats)
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(indicators)
        
        # Determine threat level
        threat_level = self._determine_threat_level(risk_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(indicators)
        
        # Generate recommended actions
        recommended_actions = self._generate_recommended_actions(
            threat_level, threat_types, context
        )
        
        # Create threat analysis
        analysis = ThreatAnalysis(
            risk_score=risk_score,
            threat_level=threat_level,
            threat_types=list(set(threat_types)),
            indicators=indicators,
            confidence=confidence,
            recommended_actions=recommended_actions,
            metadata={
                'analysis_timestamp': timezone.now().isoformat(),
                'context_id': context.correlation_id,
                'user_id': str(context.user.id) if context.user else None,
                'ip_address': context.ip_address,
                'success': context.success
            }
        )
        
        # Log security event
        await self._log_security_event(context, analysis)
        
        self.logger.info(
            f"Threat analysis completed: Risk Score: {risk_score:.2f}, "
            f"Threat Level: {threat_level.value}, "
            f"Indicators: {len(indicators)}"
        )
        
        return analysis
    
    async def _analyze_ip_reputation(
        self,
        context: LoginAttemptContext
    ) -> Tuple[List[ThreatIndicator], List[ThreatType]]:
        """Analyze IP address reputation."""
        indicators = []
        threat_types = []
        
        ip_address = context.ip_address
        cache_key = f"{self.cache_prefix}:ip_reputation:{ip_address}"
        
        # Check cache first
        cached_result = cache.get(cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Check internal threat intelligence
            threat_intel = await self._check_internal_threat_intelligence(
                'ip_address', ip_address
            )
            
            if threat_intel:
                indicators.append(ThreatIndicator(
                    type="malicious_ip",
                    value=ip_address,
                    weight=threat_intel.severity_score / 100.0,
                    confidence=self._confidence_to_float(threat_intel.confidence),
                    description=f"IP found in threat intelligence: {threat_intel.description}",
                    metadata={'source': threat_intel.source}
                ))
                threat_types.append(ThreatType.MALICIOUS_IP)
            
            # Check external reputation services
            external_reputation = await self._check_external_ip_reputation(ip_address)
            if external_reputation['is_malicious']:
                indicators.append(ThreatIndicator(
                    type="external_reputation",
                    value=ip_address,
                    weight=external_reputation['risk_score'] / 100.0,
                    confidence=external_reputation['confidence'],
                    description=f"External reputation check: {external_reputation['reason']}",
                    metadata=external_reputation['metadata']
                ))
                threat_types.append(ThreatType.MALICIOUS_IP)
            
            # Check for VPN/Proxy/Tor
            proxy_check = await self._check_proxy_vpn_tor(ip_address)
            if proxy_check['is_proxy']:
                indicators.append(ThreatIndicator(
                    type="proxy_vpn_tor",
                    value=ip_address,
                    weight=0.3,  # Moderate risk
                    confidence=proxy_check['confidence'],
                    description=f"IP is using {proxy_check['type']}",
                    metadata=proxy_check
                ))
            
            # Analyze IP behavior patterns
            behavior_analysis = await self._analyze_ip_behavior(ip_address, context)
            if behavior_analysis['is_suspicious']:
                indicators.extend(behavior_analysis['indicators'])
                threat_types.extend(behavior_analysis['threat_types'])
            
            result = (indicators, threat_types)
            
            # Cache result
            cache.set(cache_key, result, self.ip_reputation_cache_ttl)
            
        except Exception as e:
            self.logger.error(f"IP reputation analysis failed for {ip_address}: {e}")
        
        return indicators, threat_types
    
    async def _analyze_geographic_anomalies(
        self,
        context: LoginAttemptContext
    ) -> Tuple[List[ThreatIndicator], List[ThreatType]]:
        """Analyze geographic anomalies and impossible travel."""
        indicators = []
        threat_types = []
        
        if not self.geoip or not context.user:
            return indicators, threat_types
        
        try:
            # Get current location
            current_location = self._get_location_from_ip(context.ip_address)
            if not current_location:
                return indicators, threat_types
            
            # Get user's recent sessions for comparison
            recent_sessions = UserSession.objects.filter(
                user=context.user,
                created_at__gte=timezone.now() - timedelta(hours=24)
            ).exclude(
                ip_address=context.ip_address
            ).order_by('-created_at')[:5]
            
            for session in recent_sessions:
                if not session.ip_address:
                    continue
                
                previous_location = self._get_location_from_ip(session.ip_address)
                if not previous_location:
                    continue
                
                # Calculate distance and time difference
                distance_km = self._calculate_distance(
                    current_location, previous_location
                )
                time_diff_hours = (
                    context.timestamp - session.created_at
                ).total_seconds() / 3600
                
                # Check for impossible travel
                if time_diff_hours > 0:
                    max_speed_kmh = distance_km / time_diff_hours
                    
                    # Impossible travel threshold (commercial flight speed)
                    if max_speed_kmh > 900:  # km/h
                        indicators.append(ThreatIndicator(
                            type="impossible_travel",
                            value=f"{distance_km:.0f}km in {time_diff_hours:.1f}h",
                            weight=0.8,
                            confidence=0.9,
                            description=(
                                f"Impossible travel detected: {distance_km:.0f}km "
                                f"in {time_diff_hours:.1f} hours "
                                f"(speed: {max_speed_kmh:.0f} km/h)"
                            ),
                            metadata={
                                'distance_km': distance_km,
                                'time_hours': time_diff_hours,
                                'speed_kmh': max_speed_kmh,
                                'from_location': previous_location,
                                'to_location': current_location
                            }
                        ))
                        threat_types.append(ThreatType.IMPOSSIBLE_TRAVEL)
                        break  # One impossible travel detection is enough
                
                # Check for unusual location
                if distance_km > 1000:  # More than 1000km from usual location
                    indicators.append(ThreatIndicator(
                        type="location_anomaly",
                        value=f"{current_location['country']}, {current_location['city']}",
                        weight=0.4,
                        confidence=0.7,
                        description=(
                            f"Login from unusual location: "
                            f"{current_location['country']}, {current_location['city']} "
                            f"({distance_km:.0f}km from usual location)"
                        ),
                        metadata={
                            'distance_km': distance_km,
                            'current_location': current_location,
                            'usual_location': previous_location
                        }
                    ))
                    threat_types.append(ThreatType.LOCATION_ANOMALY)
                    break
            
        except Exception as e:
            self.logger.error(f"Geographic analysis failed: {e}")
        
        return indicators, threat_types
    
    async def _analyze_device_fingerprint(
        self,
        context: LoginAttemptContext
    ) -> Tuple[List[ThreatIndicator], List[ThreatType]]:
        """Analyze device fingerprint anomalies."""
        indicators = []
        threat_types = []
        
        if not context.user or not context.device_fingerprint:
            return indicators, threat_types
        
        try:
            # Get user's known devices
            known_devices = UserSession.objects.filter(
                user=context.user,
                device_fingerprint__isnull=False
            ).values_list('device_fingerprint', flat=True).distinct()
            
            # Check if this is a new device
            if context.device_fingerprint not in known_devices:
                indicators.append(ThreatIndicator(
                    type="new_device",
                    value=context.device_fingerprint[:16] + "...",
                    weight=0.3,
                    confidence=0.8,
                    description="Login from new/unknown device",
                    metadata={'device_fingerprint': context.device_fingerprint}
                ))
                threat_types.append(ThreatType.DEVICE_ANOMALY)
            
            # Analyze user agent patterns
            user_agent_analysis = self._analyze_user_agent(context.user_agent)
            if user_agent_analysis['is_suspicious']:
                indicators.append(ThreatIndicator(
                    type="suspicious_user_agent",
                    value=context.user_agent[:50] + "...",
                    weight=user_agent_analysis['risk_score'],
                    confidence=user_agent_analysis['confidence'],
                    description=user_agent_analysis['reason'],
                    metadata={'user_agent': context.user_agent}
                ))
                threat_types.append(ThreatType.DEVICE_ANOMALY)
            
        except Exception as e:
            self.logger.error(f"Device fingerprint analysis failed: {e}")
        
        return indicators, threat_types
    
    async def _analyze_behavioral_patterns(
        self,
        context: LoginAttemptContext
    ) -> Tuple[List[ThreatIndicator], List[ThreatType]]:
        """Analyze behavioral patterns using machine learning."""
        indicators = []
        threat_types = []
        
        if not context.user:
            return indicators, threat_types
        
        try:
            # Extract behavioral features
            features = await self._extract_behavioral_features(context)
            if not features:
                return indicators, threat_types
            
            # Use ML model for anomaly detection
            if 'behavioral_anomaly' in self.ml_models:
                anomaly_score = self._detect_behavioral_anomaly(features)
                
                if anomaly_score < -0.5:  # Anomaly threshold
                    indicators.append(ThreatIndicator(
                        type="behavioral_anomaly",
                        value=f"Anomaly score: {anomaly_score:.3f}",
                        weight=abs(anomaly_score),
                        confidence=0.7,
                        description="Behavioral pattern anomaly detected",
                        metadata={
                            'anomaly_score': anomaly_score,
                            'features': features
                        }
                    ))
                    threat_types.append(ThreatType.BEHAVIORAL_ANOMALY)
            
            # Analyze login timing patterns
            timing_analysis = await self._analyze_login_timing(context)
            if timing_analysis['is_anomalous']:
                indicators.append(ThreatIndicator(
                    type="timing_anomaly",
                    value=timing_analysis['description'],
                    weight=timing_analysis['risk_score'],
                    confidence=timing_analysis['confidence'],
                    description="Unusual login timing pattern",
                    metadata=timing_analysis
                ))
                threat_types.append(ThreatType.BEHAVIORAL_ANOMALY)
            
        except Exception as e:
            self.logger.error(f"Behavioral pattern analysis failed: {e}")
        
        return indicators, threat_types
    
    async def _analyze_velocity_patterns(
        self,
        context: LoginAttemptContext
    ) -> Tuple[List[ThreatIndicator], List[ThreatType]]:
        """Analyze velocity patterns for brute force and credential stuffing."""
        indicators = []
        threat_types = []
        
        try:
            # Analyze IP-based velocity
            ip_velocity = await self._analyze_ip_velocity(context.ip_address)
            if ip_velocity['is_suspicious']:
                indicators.append(ThreatIndicator(
                    type="high_velocity_ip",
                    value=f"{ip_velocity['attempts']} attempts in {ip_velocity['window']}s",
                    weight=ip_velocity['risk_score'],
                    confidence=0.9,
                    description=f"High velocity login attempts from IP: {ip_velocity['attempts']} attempts",
                    metadata=ip_velocity
                ))
                
                if ip_velocity['pattern'] == 'brute_force':
                    threat_types.append(ThreatType.BRUTE_FORCE)
                elif ip_velocity['pattern'] == 'credential_stuffing':
                    threat_types.append(ThreatType.CREDENTIAL_STUFFING)
            
            # Analyze user-based velocity (if user exists)
            if context.user:
                user_velocity = await self._analyze_user_velocity(context.user)
                if user_velocity['is_suspicious']:
                    indicators.append(ThreatIndicator(
                        type="high_velocity_user",
                        value=f"{user_velocity['attempts']} attempts in {user_velocity['window']}s",
                        weight=user_velocity['risk_score'],
                        confidence=0.8,
                        description=f"High velocity attempts for user: {user_velocity['attempts']} attempts",
                        metadata=user_velocity
                    ))
                    threat_types.append(ThreatType.ACCOUNT_TAKEOVER)
            
        except Exception as e:
            self.logger.error(f"Velocity pattern analysis failed: {e}")
        
        return indicators, threat_types
    
    async def _analyze_threat_intelligence(
        self,
        context: LoginAttemptContext
    ) -> Tuple[List[ThreatIndicator], List[ThreatType]]:
        """Analyze against threat intelligence database."""
        indicators = []
        threat_types = []
        
        try:
            # Check user agent against threat intelligence
            if context.user_agent:
                ua_threat = await self._check_internal_threat_intelligence(
                    'user_agent', context.user_agent
                )
                if ua_threat:
                    indicators.append(ThreatIndicator(
                        type="malicious_user_agent",
                        value=context.user_agent[:50] + "...",
                        weight=ua_threat.severity_score / 100.0,
                        confidence=self._confidence_to_float(ua_threat.confidence),
                        description=f"User agent in threat intelligence: {ua_threat.description}",
                        metadata={'source': ua_threat.source}
                    ))
                    threat_types.append(ThreatType.BOT_ACTIVITY)
            
            # Check for known attack patterns
            pattern_analysis = self._analyze_attack_patterns(context)
            if pattern_analysis['matches']:
                for match in pattern_analysis['matches']:
                    indicators.append(ThreatIndicator(
                        type="attack_pattern",
                        value=match['pattern'],
                        weight=match['risk_score'],
                        confidence=match['confidence'],
                        description=f"Known attack pattern detected: {match['description']}",
                        metadata=match
                    ))
                    threat_types.append(ThreatType.API_ABUSE)
            
        except Exception as e:
            self.logger.error(f"Threat intelligence analysis failed: {e}")
        
        return indicators, threat_types
    
    def _calculate_risk_score(self, indicators: List[ThreatIndicator]) -> float:
        """Calculate overall risk score from indicators."""
        if not indicators:
            return 0.0
        
        # Weighted sum with confidence adjustment
        total_score = 0.0
        total_weight = 0.0
        
        for indicator in indicators:
            adjusted_weight = indicator.weight * indicator.confidence
            total_score += adjusted_weight * 100  # Scale to 0-100
            total_weight += indicator.confidence
        
        if total_weight == 0:
            return 0.0
        
        # Normalize and apply diminishing returns
        base_score = total_score / total_weight
        
        # Apply logarithmic scaling to prevent extreme scores
        risk_score = min(100.0, base_score * (1 - math.exp(-len(indicators) / 5)))
        
        return round(risk_score, 2)
    
    def _determine_threat_level(self, risk_score: float) -> ThreatLevel:
        """Determine threat level based on risk score."""
        if risk_score >= self.risk_thresholds[ThreatLevel.CRITICAL]:
            return ThreatLevel.CRITICAL
        elif risk_score >= self.risk_thresholds[ThreatLevel.HIGH]:
            return ThreatLevel.HIGH
        elif risk_score >= self.risk_thresholds[ThreatLevel.MEDIUM]:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _calculate_confidence(self, indicators: List[ThreatIndicator]) -> float:
        """Calculate overall confidence in the threat analysis."""
        if not indicators:
            return 0.0
        
        # Average confidence weighted by indicator importance
        total_confidence = sum(i.confidence * i.weight for i in indicators)
        total_weight = sum(i.weight for i in indicators)
        
        if total_weight == 0:
            return 0.0
        
        return round(total_confidence / total_weight, 3)
    
    def _generate_recommended_actions(
        self,
        threat_level: ThreatLevel,
        threat_types: List[ThreatType],
        context: LoginAttemptContext
    ) -> List[str]:
        """Generate recommended security actions."""
        actions = []
        
        if threat_level == ThreatLevel.CRITICAL:
            actions.extend([
                "Block IP address immediately",
                "Terminate all user sessions",
                "Require immediate password reset",
                "Enable mandatory MFA",
                "Alert security team",
                "Initiate incident response"
            ])
        elif threat_level == ThreatLevel.HIGH:
            actions.extend([
                "Increase monitoring for this IP/user",
                "Require MFA for next login",
                "Limit session duration",
                "Alert security team"
            ])
        elif threat_level == ThreatLevel.MEDIUM:
            actions.extend([
                "Log security event",
                "Increase rate limiting",
                "Monitor for additional suspicious activity"
            ])
        
        # Threat-specific actions
        if ThreatType.BRUTE_FORCE in threat_types:
            actions.append("Implement progressive delays")
        
        if ThreatType.IMPOSSIBLE_TRAVEL in threat_types:
            actions.append("Require location verification")
        
        if ThreatType.DEVICE_ANOMALY in threat_types:
            actions.append("Require device verification")
        
        return list(set(actions))  # Remove duplicates
    
    async def _log_security_event(
        self,
        context: LoginAttemptContext,
        analysis: ThreatAnalysis
    ) -> None:
        """Log security event based on threat analysis."""
        try:
            # Determine event type
            event_type = 'login_success' if context.success else 'login_failure'
            if analysis.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                event_type = 'suspicious_login'
            
            # Create security event
            security_event = SecurityEvent.objects.create(
                event_type=event_type,
                severity=analysis.threat_level.value,
                user=context.user,
                ip_address=context.ip_address,
                user_agent=context.user_agent,
                request_id=context.correlation_id,
                title=f"Login attempt - {analysis.threat_level.value} risk",
                description=f"Risk score: {analysis.risk_score}, Indicators: {len(analysis.indicators)}",
                risk_score=analysis.risk_score,
                threat_indicators=[i.type for i in analysis.indicators],
                confidence_score=analysis.confidence,
                event_data=analysis.to_dict(),
                detection_method="ThreatDetectionService",
                response_taken=False
            )
            
            self.logger.info(f"Security event logged: {security_event.event_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to log security event: {e}")
    
    # Helper methods for specific analysis tasks
    
    async def _check_internal_threat_intelligence(
        self,
        indicator_type: str,
        value: str
    ) -> Optional[ThreatIntelligence]:
        """Check internal threat intelligence database."""
        try:
            return ThreatIntelligence.objects.filter(
                indicator_type=indicator_type,
                indicator_value=value,
                is_active=True
            ).first()
        except Exception as e:
            self.logger.error(f"Threat intelligence check failed: {e}")
            return None
    
    async def _check_external_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check external IP reputation services."""
        # Placeholder for external reputation check
        # In production, integrate with services like VirusTotal, AbuseIPDB, etc.
        return {
            'is_malicious': False,
            'risk_score': 0.0,
            'confidence': 0.0,
            'reason': '',
            'metadata': {}
        }
    
    async def _check_proxy_vpn_tor(self, ip_address: str) -> Dict[str, Any]:
        """Check if IP is using proxy/VPN/Tor."""
        # Placeholder for proxy/VPN/Tor detection
        # In production, integrate with services like IPQualityScore, MaxMind, etc.
        return {
            'is_proxy': False,
            'type': '',
            'confidence': 0.0
        }
    
    async def _analyze_ip_behavior(
        self,
        ip_address: str,
        context: LoginAttemptContext
    ) -> Dict[str, Any]:
        """Analyze IP behavior patterns."""
        try:
            # Get recent login attempts from this IP
            recent_attempts = SecurityEvent.objects.filter(
                ip_address=ip_address,
                event_type__in=['login_attempt', 'login_success', 'login_failure'],
                created_at__gte=timezone.now() - timedelta(hours=24)
            ).count()
            
            # Get unique users targeted from this IP
            unique_users = SecurityEvent.objects.filter(
                ip_address=ip_address,
                user__isnull=False,
                created_at__gte=timezone.now() - timedelta(hours=24)
            ).values('user').distinct().count()
            
            indicators = []
            threat_types = []
            
            # High volume of attempts
            if recent_attempts > 100:
                indicators.append(ThreatIndicator(
                    type="high_volume_ip",
                    value=f"{recent_attempts} attempts",
                    weight=0.6,
                    confidence=0.9,
                    description=f"High volume of login attempts: {recent_attempts} in 24h"
                ))
                threat_types.append(ThreatType.BRUTE_FORCE)
            
            # Multiple users targeted
            if unique_users > 10:
                indicators.append(ThreatIndicator(
                    type="multiple_users_targeted",
                    value=f"{unique_users} users",
                    weight=0.7,
                    confidence=0.8,
                    description=f"Multiple users targeted: {unique_users} different users"
                ))
                threat_types.append(ThreatType.CREDENTIAL_STUFFING)
            
            return {
                'is_suspicious': len(indicators) > 0,
                'indicators': indicators,
                'threat_types': threat_types
            }
            
        except Exception as e:
            self.logger.error(f"IP behavior analysis failed: {e}")
            return {'is_suspicious': False, 'indicators': [], 'threat_types': []}
    
    def _get_location_from_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geographic location from IP address."""
        if not self.geoip:
            return None
        
        try:
            city_data = self.geoip.city(ip_address)
            return {
                'country': city_data.country.name,
                'country_code': city_data.country.iso_code,
                'city': city_data.city.name,
                'latitude': float(city_data.location.latitude) if city_data.location.latitude else None,
                'longitude': float(city_data.location.longitude) if city_data.location.longitude else None,
            }
        except Exception as e:
            self.logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
            return None
    
    def _calculate_distance(
        self,
        location1: Dict[str, Any],
        location2: Dict[str, Any]
    ) -> float:
        """Calculate distance between two locations in kilometers."""
        if not all([
            location1.get('latitude'), location1.get('longitude'),
            location2.get('latitude'), location2.get('longitude')
        ]):
            return 0.0
        
        try:
            point1 = Point(location1['longitude'], location1['latitude'])
            point2 = Point(location2['longitude'], location2['latitude'])
            
            distance = point1.distance(point2) * 111.32  # Convert to km
            return distance
        except Exception as e:
            self.logger.error(f"Distance calculation failed: {e}")
            return 0.0
    
    def _analyze_user_agent(self, user_agent: str) -> Dict[str, Any]:
        """Analyze user agent for suspicious patterns."""
        suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python', 'java', 'go-http', 'okhttp', 'apache-httpclient'
        ]
        
        user_agent_lower = user_agent.lower()
        
        for pattern in suspicious_patterns:
            if pattern in user_agent_lower:
                return {
                    'is_suspicious': True,
                    'risk_score': 0.6,
                    'confidence': 0.8,
                    'reason': f"Suspicious user agent pattern: {pattern}"
                }
        
        # Check for empty or very short user agents
        if len(user_agent.strip()) < 10:
            return {
                'is_suspicious': True,
                'risk_score': 0.4,
                'confidence': 0.7,
                'reason': "Unusually short user agent"
            }
        
        return {
            'is_suspicious': False,
            'risk_score': 0.0,
            'confidence': 0.0,
            'reason': ''
        }
    
    async def _extract_behavioral_features(
        self,
        context: LoginAttemptContext
    ) -> Optional[List[float]]:
        """Extract behavioral features for ML analysis."""
        if not context.user:
            return None
        
        try:
            # Get user's historical login data
            user_sessions = UserSession.objects.filter(
                user=context.user,
                created_at__gte=timezone.now() - timedelta(days=30)
            ).order_by('-created_at')[:100]
            
            if len(user_sessions) < 5:  # Need minimum data for analysis
                return None
            
            # Extract features
            features = []
            
            # Time-based features
            login_hours = [s.created_at.hour for s in user_sessions]
            features.extend([
                np.mean(login_hours),
                np.std(login_hours),
                context.timestamp.hour
            ])
            
            # Day of week features
            login_weekdays = [s.created_at.weekday() for s in user_sessions]
            features.extend([
                np.mean(login_weekdays),
                np.std(login_weekdays),
                context.timestamp.weekday()
            ])
            
            # Session duration features (if available)
            durations = []
            for session in user_sessions:
                if session.last_activity and session.created_at:
                    duration = (session.last_activity - session.created_at).total_seconds()
                    durations.append(duration)
            
            if durations:
                features.extend([
                    np.mean(durations),
                    np.std(durations)
                ])
            else:
                features.extend([0.0, 0.0])
            
            # IP diversity
            unique_ips = len(set(s.ip_address for s in user_sessions if s.ip_address))
            features.append(unique_ips)
            
            # Device diversity
            unique_devices = len(set(
                s.device_fingerprint for s in user_sessions 
                if s.device_fingerprint
            ))
            features.append(unique_devices)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")
            return None
    
    def _detect_behavioral_anomaly(self, features: List[float]) -> float:
        """Detect behavioral anomaly using ML model."""
        try:
            if 'behavioral_anomaly' not in self.ml_models:
                return 0.0
            
            model = self.ml_models['behavioral_anomaly']
            scaler = self.ml_models.get('scaler')
            
            # Reshape features for prediction
            features_array = np.array(features).reshape(1, -1)
            
            # Scale features if scaler is available
            if scaler:
                features_array = scaler.transform(features_array)
            
            # Get anomaly score
            anomaly_score = model.decision_function(features_array)[0]
            
            return anomaly_score
            
        except Exception as e:
            self.logger.error(f"Behavioral anomaly detection failed: {e}")
            return 0.0
    
    async def _analyze_login_timing(
        self,
        context: LoginAttemptContext
    ) -> Dict[str, Any]:
        """Analyze login timing patterns."""
        if not context.user:
            return {'is_anomalous': False}
        
        try:
            # Get user's typical login hours
            recent_logins = SecurityEvent.objects.filter(
                user=context.user,
                event_type='login_success',
                created_at__gte=timezone.now() - timedelta(days=30)
            ).values_list('created_at', flat=True)
            
            if len(recent_logins) < 5:
                return {'is_anomalous': False}
            
            # Calculate typical login hours
            login_hours = [login.hour for login in recent_logins]
            mean_hour = np.mean(login_hours)
            std_hour = np.std(login_hours)
            
            current_hour = context.timestamp.hour
            
            # Check if current hour is anomalous (more than 2 standard deviations)
            if std_hour > 0:
                z_score = abs(current_hour - mean_hour) / std_hour
                if z_score > 2:
                    return {
                        'is_anomalous': True,
                        'risk_score': min(0.6, z_score / 4),  # Cap at 0.6
                        'confidence': 0.7,
                        'description': f"Unusual login time: {current_hour}:00 (typical: {mean_hour:.1f}±{std_hour:.1f})",
                        'z_score': z_score,
                        'typical_hour': mean_hour,
                        'current_hour': current_hour
                    }
            
            return {'is_anomalous': False}
            
        except Exception as e:
            self.logger.error(f"Login timing analysis failed: {e}")
            return {'is_anomalous': False}
    
    async def _analyze_ip_velocity(self, ip_address: str) -> Dict[str, Any]:
        """Analyze IP-based velocity patterns."""
        try:
            # Check different time windows
            windows = [
                (60, 10),    # 10 attempts in 1 minute
                (300, 30),   # 30 attempts in 5 minutes
                (3600, 100), # 100 attempts in 1 hour
            ]
            
            for window_seconds, threshold in windows:
                since = timezone.now() - timedelta(seconds=window_seconds)
                
                attempts = SecurityEvent.objects.filter(
                    ip_address=ip_address,
                    event_type__in=['login_attempt', 'login_failure'],
                    created_at__gte=since
                ).count()
                
                if attempts >= threshold:
                    # Determine pattern type
                    unique_users = SecurityEvent.objects.filter(
                        ip_address=ip_address,
                        user__isnull=False,
                        created_at__gte=since
                    ).values('user').distinct().count()
                    
                    pattern = 'credential_stuffing' if unique_users > 5 else 'brute_force'
                    risk_score = min(0.9, attempts / threshold)
                    
                    return {
                        'is_suspicious': True,
                        'attempts': attempts,
                        'window': window_seconds,
                        'threshold': threshold,
                        'pattern': pattern,
                        'risk_score': risk_score,
                        'unique_users': unique_users
                    }
            
            return {'is_suspicious': False}
            
        except Exception as e:
            self.logger.error(f"IP velocity analysis failed: {e}")
            return {'is_suspicious': False}
    
    async def _analyze_user_velocity(self, user: UserProfile) -> Dict[str, Any]:
        """Analyze user-based velocity patterns."""
        try:
            # Check for rapid login attempts for this user
            since = timezone.now() - timedelta(minutes=5)
            
            attempts = SecurityEvent.objects.filter(
                user=user,
                event_type__in=['login_attempt', 'login_failure'],
                created_at__gte=since
            ).count()
            
            if attempts >= 10:  # 10 attempts in 5 minutes
                return {
                    'is_suspicious': True,
                    'attempts': attempts,
                    'window': 300,
                    'risk_score': min(0.8, attempts / 20)
                }
            
            return {'is_suspicious': False}
            
        except Exception as e:
            self.logger.error(f"User velocity analysis failed: {e}")
            return {'is_suspicious': False}
    
    def _analyze_attack_patterns(self, context: LoginAttemptContext) -> Dict[str, Any]:
        """Analyze for known attack patterns."""
        matches = []
        
        # Check for common attack patterns in user agent
        attack_patterns = [
            ('sqlmap', 0.9, 'SQL injection tool detected'),
            ('nikto', 0.8, 'Web vulnerability scanner detected'),
            ('nmap', 0.7, 'Network scanner detected'),
            ('masscan', 0.8, 'Port scanner detected'),
        ]
        
        user_agent_lower = context.user_agent.lower()
        
        for pattern, risk_score, description in attack_patterns:
            if pattern in user_agent_lower:
                matches.append({
                    'pattern': pattern,
                    'risk_score': risk_score,
                    'confidence': 0.9,
                    'description': description
                })
        
        return {'matches': matches}
    
    def _confidence_to_float(self, confidence_str: str) -> float:
        """Convert confidence string to float."""
        confidence_map = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'verified': 1.0
        }
        return confidence_map.get(confidence_str, 0.5)


# Global service instance
threat_detection_service = ThreatDetectionService()