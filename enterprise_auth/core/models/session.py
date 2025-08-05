"""
Session management models for enterprise authentication system.

This module provides comprehensive session tracking with device fingerprinting,
geographic location enrichment, and risk scoring capabilities.
"""

import uuid
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

from .base import BaseModel, TimestampedModel
from .user import UserProfile


class DeviceInfo(BaseModel):
    """
    Device information model for tracking user devices.
    
    Stores normalized device information extracted from user agents
    and other device characteristics for session binding.
    """
    
    DEVICE_TYPE_CHOICES = [
        ('desktop', 'Desktop'),
        ('mobile', 'Mobile'),
        ('tablet', 'Tablet'),
        ('tv', 'Smart TV'),
        ('watch', 'Smart Watch'),
        ('unknown', 'Unknown'),
    ]
    
    device_fingerprint = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Unique device fingerprint hash"
    )
    
    device_type = models.CharField(
        max_length=20,
        choices=DEVICE_TYPE_CHOICES,
        default='unknown',
        help_text="Type of device"
    )
    
    browser = models.CharField(
        max_length=100,
        blank=True,
        help_text="Browser name and version"
    )
    
    operating_system = models.CharField(
        max_length=100,
        blank=True,
        help_text="Operating system name and version"
    )
    
    screen_resolution = models.CharField(
        max_length=20,
        blank=True,
        help_text="Screen resolution (e.g., 1920x1080)"
    )
    
    timezone_offset = models.IntegerField(
        null=True,
        blank=True,
        help_text="Timezone offset in minutes"
    )
    
    language = models.CharField(
        max_length=10,
        blank=True,
        help_text="Browser language preference"
    )
    
    user_agent = models.TextField(
        help_text="Full user agent string"
    )
    
    device_characteristics = models.JSONField(
        default=dict,
        help_text="Additional device characteristics for fingerprinting"
    )
    
    is_trusted = models.BooleanField(
        default=False,
        help_text="Whether this device is marked as trusted"
    )
    
    first_seen = models.DateTimeField(
        auto_now_add=True,
        help_text="When this device was first seen"
    )
    
    last_seen = models.DateTimeField(
        auto_now=True,
        help_text="When this device was last seen"
    )
    
    class Meta:
        db_table = 'auth_device_info'
        verbose_name = 'Device Info'
        verbose_name_plural = 'Device Info'
        indexes = [
            models.Index(fields=['device_fingerprint']),
            models.Index(fields=['device_type', 'is_trusted']),
            models.Index(fields=['last_seen']),
        ]
    
    def __str__(self):
        return f"{self.device_type} - {self.browser} on {self.operating_system}"


class UserSession(TimestampedModel):
    """
    Advanced user session model with comprehensive tracking.
    
    Tracks user sessions with device binding, geographic location,
    risk scoring, and security monitoring capabilities.
    """
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('terminated', 'Terminated'),
        ('suspicious', 'Suspicious'),
        ('locked', 'Locked'),
    ]
    
    LOGIN_METHOD_CHOICES = [
        ('password', 'Password'),
        ('oauth_google', 'Google OAuth'),
        ('oauth_github', 'GitHub OAuth'),
        ('oauth_microsoft', 'Microsoft OAuth'),
        ('oauth_apple', 'Apple OAuth'),
        ('oauth_linkedin', 'LinkedIn OAuth'),
        ('mfa_totp', 'TOTP MFA'),
        ('mfa_sms', 'SMS MFA'),
        ('mfa_email', 'Email MFA'),
        ('api_key', 'API Key'),
        ('refresh_token', 'Refresh Token'),
    ]
    
    # Core session identification
    session_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Unique session identifier"
    )
    
    user = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='sessions',
        help_text="User associated with this session"
    )
    
    device_info = models.ForeignKey(
        DeviceInfo,
        on_delete=models.CASCADE,
        related_name='sessions',
        help_text="Device information for this session"
    )
    
    # Network and location information
    ip_address = models.GenericIPAddressField(
        help_text="IP address of the session"
    )
    
    country = models.CharField(
        max_length=100,
        blank=True,
        help_text="Country derived from IP geolocation"
    )
    
    region = models.CharField(
        max_length=100,
        blank=True,
        help_text="Region/state derived from IP geolocation"
    )
    
    city = models.CharField(
        max_length=100,
        blank=True,
        help_text="City derived from IP geolocation"
    )
    
    latitude = models.FloatField(
        null=True,
        blank=True,
        validators=[MinValueValidator(-90), MaxValueValidator(90)],
        help_text="Latitude coordinate"
    )
    
    longitude = models.FloatField(
        null=True,
        blank=True,
        validators=[MinValueValidator(-180), MaxValueValidator(180)],
        help_text="Longitude coordinate"
    )
    
    isp = models.CharField(
        max_length=255,
        blank=True,
        help_text="Internet Service Provider"
    )
    
    # Session metadata
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active',
        db_index=True,
        help_text="Current session status"
    )
    
    login_method = models.CharField(
        max_length=20,
        choices=LOGIN_METHOD_CHOICES,
        help_text="Method used for authentication"
    )
    
    # Risk and security scoring
    risk_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0), MaxValueValidator(100.0)],
        help_text="Calculated risk score (0-100)"
    )
    
    risk_factors = models.JSONField(
        default=dict,
        help_text="Detailed risk factors and their scores"
    )
    
    is_trusted_device = models.BooleanField(
        default=False,
        help_text="Whether this session is from a trusted device"
    )
    
    # Session lifecycle
    last_activity = models.DateTimeField(
        auto_now=True,
        help_text="Last activity timestamp"
    )
    
    expires_at = models.DateTimeField(
        help_text="Session expiration timestamp"
    )
    
    terminated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the session was terminated"
    )
    
    terminated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='terminated_sessions',
        help_text="User who terminated this session"
    )
    
    termination_reason = models.CharField(
        max_length=100,
        blank=True,
        help_text="Reason for session termination"
    )
    
    # Additional session data
    session_data = models.JSONField(
        default=dict,
        help_text="Additional session-specific data"
    )
    
    class Meta:
        db_table = 'auth_user_session'
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['session_id']),
            models.Index(fields=['ip_address', 'created_at']),
            models.Index(fields=['device_info', 'status']),
            models.Index(fields=['risk_score']),
            models.Index(fields=['last_activity']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['country', 'city']),
        ]
        ordering = ['-last_activity']
    
    def __str__(self):
        return f"Session {self.session_id[:8]}... for {self.user.email}"
    
    @property
    def is_active(self) -> bool:
        """Check if session is currently active."""
        return (
            self.status == 'active' and
            self.expires_at > timezone.now() and
            self.terminated_at is None
        )
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return self.expires_at <= timezone.now()
    
    @property
    def duration(self) -> timedelta:
        """Get session duration."""
        end_time = self.terminated_at or timezone.now()
        return end_time - self.created_at
    
    @property
    def location_string(self) -> str:
        """Get formatted location string."""
        parts = [part for part in [self.city, self.region, self.country] if part]
        return ', '.join(parts) if parts else 'Unknown Location'
    
    def calculate_risk_score(self) -> float:
        """
        Calculate session risk score based on multiple factors.
        
        Returns:
            float: Risk score between 0.0 and 100.0
        """
        risk_factors = {}
        total_score = 0.0
        
        # Geographic risk (30% weight)
        geo_risk = self._calculate_geographic_risk()
        risk_factors['geographic'] = geo_risk
        total_score += geo_risk * 0.3
        
        # Device risk (25% weight)
        device_risk = self._calculate_device_risk()
        risk_factors['device'] = device_risk
        total_score += device_risk * 0.25
        
        # Behavioral risk (25% weight)
        behavioral_risk = self._calculate_behavioral_risk()
        risk_factors['behavioral'] = behavioral_risk
        total_score += behavioral_risk * 0.25
        
        # Network risk (20% weight)
        network_risk = self._calculate_network_risk()
        risk_factors['network'] = network_risk
        total_score += network_risk * 0.2
        
        # Store risk factors for analysis
        self.risk_factors = risk_factors
        
        return min(total_score, 100.0)
    
    def _calculate_geographic_risk(self) -> float:
        """Calculate risk based on geographic factors."""
        risk = 0.0
        
        # Check for unusual location
        user_sessions = UserSession.objects.filter(
            user=self.user,
            status='active',
            created_at__gte=timezone.now() - timedelta(days=30)
        ).exclude(id=self.id)
        
        if user_sessions.exists():
            # Check if this location is significantly different
            common_countries = set(
                user_sessions.values_list('country', flat=True)
            )
            
            if self.country and self.country not in common_countries:
                risk += 40.0  # New country
            
            # Check for impossible travel
            latest_session = user_sessions.order_by('-created_at').first()
            if latest_session and self._is_impossible_travel(latest_session):
                risk += 60.0  # Impossible travel detected
        
        return min(risk, 100.0)
    
    def _calculate_device_risk(self) -> float:
        """Calculate risk based on device factors."""
        risk = 0.0
        
        # New device risk
        if not self.device_info.is_trusted:
            device_sessions = UserSession.objects.filter(
                user=self.user,
                device_info=self.device_info,
                status='active'
            ).exclude(id=self.id)
            
            if not device_sessions.exists():
                risk += 30.0  # New device
        
        # Unusual device characteristics
        if self.device_info.device_type == 'unknown':
            risk += 20.0
        
        return min(risk, 100.0)
    
    def _calculate_behavioral_risk(self) -> float:
        """Calculate risk based on behavioral patterns."""
        risk = 0.0
        
        # Unusual login time
        current_hour = self.created_at.hour
        user_sessions = UserSession.objects.filter(
            user=self.user,
            created_at__gte=timezone.now() - timedelta(days=30)
        ).exclude(id=self.id)
        
        if user_sessions.exists():
            common_hours = [
                session.created_at.hour 
                for session in user_sessions
            ]
            
            # Check if current hour is unusual
            hour_frequency = common_hours.count(current_hour) / len(common_hours)
            if hour_frequency < 0.1:  # Less than 10% of logins at this hour
                risk += 25.0
        
        # Multiple concurrent sessions
        concurrent_sessions = UserSession.objects.filter(
            user=self.user,
            status='active',
            created_at__gte=timezone.now() - timedelta(hours=1)
        ).exclude(id=self.id).count()
        
        if concurrent_sessions > 3:
            risk += 30.0
        
        return min(risk, 100.0)
    
    def _calculate_network_risk(self) -> float:
        """Calculate risk based on network factors."""
        risk = 0.0
        
        # Check for known malicious IPs (placeholder - would integrate with threat intel)
        # This would typically check against threat intelligence feeds
        
        # Check for VPN/Proxy usage (placeholder)
        # This would typically use IP intelligence services
        
        # Check for unusual ISP
        user_sessions = UserSession.objects.filter(
            user=self.user,
            created_at__gte=timezone.now() - timedelta(days=30)
        ).exclude(id=self.id)
        
        if user_sessions.exists() and self.isp:
            common_isps = set(
                user_sessions.values_list('isp', flat=True)
            )
            
            if self.isp not in common_isps:
                risk += 20.0  # New ISP
        
        return min(risk, 100.0)
    
    def _is_impossible_travel(self, previous_session: 'UserSession') -> bool:
        """
        Check if travel between two sessions is impossible.
        
        Args:
            previous_session: Previous session to compare against
            
        Returns:
            bool: True if travel is impossible
        """
        if not all([
            self.latitude, self.longitude,
            previous_session.latitude, previous_session.longitude
        ]):
            return False
        
        # Calculate distance between locations (simplified)
        from math import radians, sin, cos, sqrt, atan2
        
        lat1, lon1 = radians(previous_session.latitude), radians(previous_session.longitude)
        lat2, lon2 = radians(self.latitude), radians(self.longitude)
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        distance_km = 6371 * c  # Earth's radius in km
        
        # Calculate time difference
        time_diff = (self.created_at - previous_session.created_at).total_seconds() / 3600  # hours
        
        # Maximum reasonable travel speed (including flights): 1000 km/h
        max_speed_kmh = 1000
        max_possible_distance = max_speed_kmh * time_diff
        
        return distance_km > max_possible_distance
    
    def terminate(self, terminated_by: Optional[UserProfile] = None, reason: str = '') -> None:
        """
        Terminate the session.
        
        Args:
            terminated_by: User who terminated the session
            reason: Reason for termination
        """
        self.status = 'terminated'
        self.terminated_at = timezone.now()
        self.terminated_by = terminated_by
        self.termination_reason = reason
        self.save(update_fields=[
            'status', 'terminated_at', 'terminated_by', 'termination_reason'
        ])
    
    def extend_expiration(self, hours: int = 24) -> None:
        """
        Extend session expiration.
        
        Args:
            hours: Number of hours to extend
        """
        self.expires_at = timezone.now() + timedelta(hours=hours)
        self.save(update_fields=['expires_at'])
    
    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])


class SessionActivity(BaseModel):
    """
    Track specific activities within a session.
    
    Records detailed activity logs for session forensics and analysis.
    """
    
    ACTIVITY_TYPE_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('api_call', 'API Call'),
        ('page_view', 'Page View'),
        ('password_change', 'Password Change'),
        ('profile_update', 'Profile Update'),
        ('mfa_setup', 'MFA Setup'),
        ('mfa_verify', 'MFA Verification'),
        ('oauth_link', 'OAuth Account Link'),
        ('oauth_unlink', 'OAuth Account Unlink'),
        ('permission_check', 'Permission Check'),
        ('suspicious_activity', 'Suspicious Activity'),
    ]
    
    session = models.ForeignKey(
        UserSession,
        on_delete=models.CASCADE,
        related_name='activities',
        help_text="Session this activity belongs to"
    )
    
    activity_type = models.CharField(
        max_length=30,
        choices=ACTIVITY_TYPE_CHOICES,
        help_text="Type of activity"
    )
    
    endpoint = models.CharField(
        max_length=255,
        blank=True,
        help_text="API endpoint or page accessed"
    )
    
    method = models.CharField(
        max_length=10,
        blank=True,
        help_text="HTTP method used"
    )
    
    status_code = models.IntegerField(
        null=True,
        blank=True,
        help_text="HTTP status code"
    )
    
    response_time_ms = models.IntegerField(
        null=True,
        blank=True,
        help_text="Response time in milliseconds"
    )
    
    user_agent = models.TextField(
        blank=True,
        help_text="User agent for this specific activity"
    )
    
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address for this specific activity"
    )
    
    activity_data = models.JSONField(
        default=dict,
        help_text="Additional activity-specific data"
    )
    
    risk_indicators = models.JSONField(
        default=list,
        help_text="Risk indicators detected during this activity"
    )
    
    timestamp = models.DateTimeField(
        auto_now_add=True,
        help_text="When this activity occurred"
    )
    
    class Meta:
        db_table = 'auth_session_activity'
        verbose_name = 'Session Activity'
        verbose_name_plural = 'Session Activities'
        indexes = [
            models.Index(fields=['session', 'timestamp']),
            models.Index(fields=['activity_type', 'timestamp']),
            models.Index(fields=['endpoint']),
            models.Index(fields=['status_code']),
        ]
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.activity_type} - {self.session.session_id[:8]}..."