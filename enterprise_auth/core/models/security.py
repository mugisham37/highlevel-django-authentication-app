"""
Security event models for enterprise authentication system.

This module provides comprehensive security event tracking, threat detection,
and session security monitoring capabilities.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

from .base import BaseModel, TimestampedModel
from .user import UserProfile
from .session import UserSession


class SecurityEvent(TimestampedModel):
    """
    Comprehensive security event model for tracking threats and anomalies.
    
    Records security-related events with detailed context for analysis,
    alerting, and forensic investigation.
    """
    
    EVENT_TYPE_CHOICES = [
        # Authentication events
        ('login_attempt', 'Login Attempt'),
        ('login_success', 'Login Success'),
        ('login_failure', 'Login Failed'),
        ('logout', 'Logout'),
        ('password_change', 'Password Change'),
        ('password_reset', 'Password Reset'),
        
        # Session events
        ('session_created', 'Session Created'),
        ('session_terminated', 'Session Terminated'),
        ('session_expired', 'Session Expired'),
        ('session_hijack_attempt', 'Session Hijack Attempt'),
        ('concurrent_session_limit', 'Concurrent Session Limit'),
        ('session_sharing_detected', 'Session Sharing Detected'),
        
        # MFA events
        ('mfa_setup', 'MFA Setup'),
        ('mfa_verification', 'MFA Verification'),
        ('mfa_failure', 'MFA Failure'),
        ('mfa_bypass_attempt', 'MFA Bypass Attempt'),
        
        # Suspicious activities
        ('suspicious_login', 'Suspicious Login'),
        ('impossible_travel', 'Impossible Travel'),
        ('device_anomaly', 'Device Anomaly'),
        ('location_anomaly', 'Location Anomaly'),
        ('behavioral_anomaly', 'Behavioral Anomaly'),
        ('brute_force_attack', 'Brute Force Attack'),
        ('credential_stuffing', 'Credential Stuffing'),
        
        # Rate limiting events
        ('rate_limit_exceeded', 'Rate Limit Exceeded'),
        ('rate_limit_warning', 'Rate Limit Warning'),
        
        # Account security events
        ('account_locked', 'Account Locked'),
        ('account_unlocked', 'Account Unlocked'),
        ('account_disabled', 'Account Disabled'),
        ('account_enabled', 'Account Enabled'),
        
        # API security events
        ('api_abuse', 'API Abuse'),
        ('invalid_token', 'Invalid Token'),
        ('token_theft_attempt', 'Token Theft Attempt'),
        
        # System security events
        ('security_scan_detected', 'Security Scan Detected'),
        ('malicious_payload', 'Malicious Payload'),
        ('injection_attempt', 'Injection Attempt'),
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False Positive'),
        ('resolved', 'Resolved'),
        ('ignored', 'Ignored'),
    ]
    
    # Core event identification
    event_id = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        db_index=True,
        help_text="Unique event identifier"
    )
    
    event_type = models.CharField(
        max_length=50,
        choices=EVENT_TYPE_CHOICES,
        db_index=True,
        help_text="Type of security event"
    )
    
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default='low',
        db_index=True,
        help_text="Event severity level"
    )
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='new',
        db_index=True,
        help_text="Investigation status"
    )
    
    # Associated entities
    user = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_events',
        help_text="User associated with this event"
    )
    
    session = models.ForeignKey(
        UserSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_events',
        help_text="Session associated with this event"
    )
    
    # Request context
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address where event originated"
    )
    
    user_agent = models.TextField(
        blank=True,
        help_text="User agent string"
    )
    
    request_id = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
        help_text="Request correlation ID"
    )
    
    # Event details
    title = models.CharField(
        max_length=255,
        help_text="Brief event title"
    )
    
    description = models.TextField(
        help_text="Detailed event description"
    )
    
    # Risk and threat analysis
    risk_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0), MaxValueValidator(100.0)],
        help_text="Calculated risk score (0-100)"
    )
    
    threat_indicators = models.JSONField(
        default=list,
        help_text="List of threat indicators detected"
    )
    
    confidence_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
        help_text="Confidence in threat detection (0.0-1.0)"
    )
    
    # Event metadata
    event_data = models.JSONField(
        default=dict,
        help_text="Additional event-specific data"
    )
    
    detection_method = models.CharField(
        max_length=100,
        blank=True,
        help_text="Method used to detect this event"
    )
    
    # Response and mitigation
    response_taken = models.BooleanField(
        default=False,
        help_text="Whether automated response was taken"
    )
    
    response_details = models.JSONField(
        default=dict,
        help_text="Details of response actions taken"
    )
    
    mitigation_applied = models.BooleanField(
        default=False,
        help_text="Whether mitigation measures were applied"
    )
    
    # Investigation tracking
    investigated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='investigated_security_events',
        help_text="User who investigated this event"
    )
    
    investigated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When investigation was completed"
    )
    
    investigation_notes = models.TextField(
        blank=True,
        help_text="Investigation notes and findings"
    )
    
    # Correlation and grouping
    correlation_id = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
        help_text="ID for correlating related events"
    )
    
    parent_event = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='child_events',
        help_text="Parent event if this is a follow-up"
    )
    
    class Meta:
        db_table = 'security_event'
        verbose_name = 'Security Event'
        verbose_name_plural = 'Security Events'
        indexes = [
            models.Index(fields=['event_type', 'severity']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['session', 'created_at']),
            models.Index(fields=['ip_address', 'created_at']),
            models.Index(fields=['risk_score']),
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['correlation_id']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.event_type} - {self.severity} - {self.created_at}"
    
    @property
    def is_high_risk(self) -> bool:
        """Check if this is a high-risk event."""
        return self.risk_score >= 70.0 or self.severity in ['high', 'critical']
    
    @property
    def requires_investigation(self) -> bool:
        """Check if this event requires investigation."""
        return (
            self.is_high_risk and 
            self.status in ['new', 'investigating'] and
            not self.investigated_at
        )
    
    def mark_investigated(self, investigated_by: UserProfile, notes: str = '') -> None:
        """
        Mark event as investigated.
        
        Args:
            investigated_by: User who investigated the event
            notes: Investigation notes
        """
        self.investigated_by = investigated_by
        self.investigated_at = timezone.now()
        self.investigation_notes = notes
        self.status = 'investigated' if self.status == 'investigating' else self.status
        self.save(update_fields=[
            'investigated_by', 'investigated_at', 'investigation_notes', 'status'
        ])
    
    def add_response_action(self, action: str, details: Dict[str, Any]) -> None:
        """
        Add a response action to this event.
        
        Args:
            action: Action taken
            details: Action details
        """
        if not self.response_details:
            self.response_details = {}
        
        if 'actions' not in self.response_details:
            self.response_details['actions'] = []
        
        self.response_details['actions'].append({
            'action': action,
            'details': details,
            'timestamp': timezone.now().isoformat(),
        })
        
        self.response_taken = True
        self.save(update_fields=['response_details', 'response_taken'])


class SessionSecurityEvent(TimestampedModel):
    """
    Specialized security event model for session-specific security monitoring.
    
    Tracks session-related security events with detailed session context
    for forensic analysis and threat detection.
    """
    
    EVENT_TYPE_CHOICES = [
        ('session_anomaly', 'Session Anomaly'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('location_change', 'Location Change'),
        ('device_change', 'Device Change'),
        ('concurrent_session', 'Concurrent Session'),
        ('session_sharing', 'Session Sharing'),
        ('impossible_travel', 'Impossible Travel'),
        ('risk_threshold_exceeded', 'Risk Threshold Exceeded'),
        ('behavioral_anomaly', 'Behavioral Anomaly'),
        ('session_hijack', 'Session Hijack'),
        ('session_replay', 'Session Replay'),
    ]
    
    RISK_LEVEL_CHOICES = [
        ('low', 'Low Risk'),
        ('medium', 'Medium Risk'),
        ('high', 'High Risk'),
        ('critical', 'Critical Risk'),
    ]
    
    # Core event identification
    session = models.ForeignKey(
        UserSession,
        on_delete=models.CASCADE,
        related_name='session_security_events',
        help_text="Session this security event relates to"
    )
    
    event_type = models.CharField(
        max_length=30,
        choices=EVENT_TYPE_CHOICES,
        db_index=True,
        help_text="Type of session security event"
    )
    
    risk_level = models.CharField(
        max_length=20,
        choices=RISK_LEVEL_CHOICES,
        default='low',
        db_index=True,
        help_text="Risk level of this event"
    )
    
    # Event details
    description = models.TextField(
        help_text="Detailed description of the security event"
    )
    
    risk_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0), MaxValueValidator(100.0)],
        help_text="Risk score for this specific event"
    )
    
    # Detection details
    detection_algorithm = models.CharField(
        max_length=100,
        blank=True,
        help_text="Algorithm or method used for detection"
    )
    
    confidence_level = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
        help_text="Confidence level in detection (0.0-1.0)"
    )
    
    # Context data
    previous_session_data = models.JSONField(
        default=dict,
        help_text="Previous session data for comparison"
    )
    
    current_session_data = models.JSONField(
        default=dict,
        help_text="Current session data that triggered the event"
    )
    
    anomaly_indicators = models.JSONField(
        default=list,
        help_text="Specific indicators that triggered the anomaly detection"
    )
    
    # Response tracking
    action_taken = models.CharField(
        max_length=100,
        blank=True,
        help_text="Automated action taken in response"
    )
    
    action_details = models.JSONField(
        default=dict,
        help_text="Details of the action taken"
    )
    
    requires_manual_review = models.BooleanField(
        default=False,
        help_text="Whether this event requires manual review"
    )
    
    reviewed_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_session_events',
        help_text="User who reviewed this event"
    )
    
    reviewed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this event was reviewed"
    )
    
    review_notes = models.TextField(
        blank=True,
        help_text="Notes from manual review"
    )
    
    class Meta:
        db_table = 'session_security_event'
        verbose_name = 'Session Security Event'
        verbose_name_plural = 'Session Security Events'
        indexes = [
            models.Index(fields=['session', 'event_type']),
            models.Index(fields=['risk_level', 'created_at']),
            models.Index(fields=['requires_manual_review']),
            models.Index(fields=['reviewed_at']),
            models.Index(fields=['risk_score']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.event_type} - {self.risk_level} - Session {self.session.session_id[:8]}..."
    
    @property
    def is_critical(self) -> bool:
        """Check if this is a critical security event."""
        return self.risk_level == 'critical' or self.risk_score >= 90.0
    
    def mark_reviewed(self, reviewed_by: UserProfile, notes: str = '') -> None:
        """
        Mark event as reviewed.
        
        Args:
            reviewed_by: User who reviewed the event
            notes: Review notes
        """
        self.reviewed_by = reviewed_by
        self.reviewed_at = timezone.now()
        self.review_notes = notes
        self.requires_manual_review = False
        self.save(update_fields=[
            'reviewed_by', 'reviewed_at', 'review_notes', 'requires_manual_review'
        ])


class ThreatIntelligence(TimestampedModel):
    """
    Threat intelligence data for enhancing security event detection.
    
    Stores threat indicators, malicious IPs, and other intelligence
    data for improving security monitoring accuracy.
    """
    
    INDICATOR_TYPE_CHOICES = [
        ('ip_address', 'IP Address'),
        ('user_agent', 'User Agent'),
        ('domain', 'Domain'),
        ('hash', 'Hash'),
        ('pattern', 'Pattern'),
        ('behavior', 'Behavior'),
    ]
    
    SOURCE_CHOICES = [
        ('internal', 'Internal Analysis'),
        ('external_feed', 'External Threat Feed'),
        ('manual_entry', 'Manual Entry'),
        ('ml_detection', 'Machine Learning Detection'),
        ('community', 'Community Intelligence'),
    ]
    
    CONFIDENCE_CHOICES = [
        ('low', 'Low Confidence'),
        ('medium', 'Medium Confidence'),
        ('high', 'High Confidence'),
        ('verified', 'Verified'),
    ]
    
    # Threat indicator details
    indicator_type = models.CharField(
        max_length=20,
        choices=INDICATOR_TYPE_CHOICES,
        db_index=True,
        help_text="Type of threat indicator"
    )
    
    indicator_value = models.TextField(
        db_index=True,
        help_text="Value of the threat indicator"
    )
    
    threat_type = models.CharField(
        max_length=100,
        help_text="Type of threat this indicator represents"
    )
    
    # Source and confidence
    source = models.CharField(
        max_length=20,
        choices=SOURCE_CHOICES,
        help_text="Source of this threat intelligence"
    )
    
    confidence = models.CharField(
        max_length=20,
        choices=CONFIDENCE_CHOICES,
        default='medium',
        help_text="Confidence level in this indicator"
    )
    
    # Threat details
    description = models.TextField(
        help_text="Description of the threat"
    )
    
    severity_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0), MaxValueValidator(100.0)],
        help_text="Severity score of this threat (0-100)"
    )
    
    # Metadata
    tags = models.JSONField(
        default=list,
        help_text="Tags for categorizing this threat intelligence"
    )
    
    metadata = models.JSONField(
        default=dict,
        help_text="Additional metadata about this threat"
    )
    
    # Lifecycle
    first_seen = models.DateTimeField(
        auto_now_add=True,
        help_text="When this indicator was first seen"
    )
    
    last_seen = models.DateTimeField(
        auto_now=True,
        help_text="When this indicator was last seen"
    )
    
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this indicator expires"
    )
    
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this indicator is currently active"
    )
    
    # Attribution
    added_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='added_threat_intelligence',
        help_text="User who added this threat intelligence"
    )
    
    class Meta:
        db_table = 'threat_intelligence'
        verbose_name = 'Threat Intelligence'
        verbose_name_plural = 'Threat Intelligence'
        indexes = [
            models.Index(fields=['indicator_type', 'indicator_value']),
            models.Index(fields=['threat_type']),
            models.Index(fields=['source', 'confidence']),
            models.Index(fields=['is_active', 'expires_at']),
            models.Index(fields=['severity_score']),
        ]
        unique_together = [['indicator_type', 'indicator_value']]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.indicator_type}: {self.indicator_value[:50]}..."
    
    @property
    def is_expired(self) -> bool:
        """Check if this threat intelligence has expired."""
        return self.expires_at and self.expires_at <= timezone.now()
    
    @property
    def is_high_confidence(self) -> bool:
        """Check if this is high confidence threat intelligence."""
        return self.confidence in ['high', 'verified']
    
    def update_last_seen(self) -> None:
        """Update the last seen timestamp."""
        self.last_seen = timezone.now()
        self.save(update_fields=['last_seen'])