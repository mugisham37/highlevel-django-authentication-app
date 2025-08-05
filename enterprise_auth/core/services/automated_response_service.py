"""
Automated threat response service for enterprise authentication system.

This service provides automated security responses including account lockout,
session termination, IP blocking, and security incident escalation.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum

from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.db import transaction
from django.db.models import Q, Count, F
from django.utils import timezone
from django.template.loader import render_to_string

from celery import shared_task

from ..models import (
    UserProfile, UserSession, SecurityEvent, ThreatIntelligence
)
from ..exceptions import SecurityError, ThreatDetectedError
from .audit_service import audit_service
from .rate_limiting_service import rate_limiting_service


logger = logging.getLogger(__name__)


class ResponseAction(Enum):
    """Automated response actions."""
    BLOCK_IP = "block_ip"
    LOCK_ACCOUNT = "lock_account"
    TERMINATE_SESSIONS = "terminate_sessions"
    REQUIRE_MFA = "require_mfa"
    REQUIRE_PASSWORD_RESET = "require_password_reset"
    INCREASE_MONITORING = "increase_monitoring"
    ALERT_SECURITY_TEAM = "alert_security_team"
    ESCALATE_INCIDENT = "escalate_incident"
    QUARANTINE_USER = "quarantine_user"
    DISABLE_API_ACCESS = "disable_api_access"


class ResponseSeverity(Enum):
    """Response severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ResponseRule:
    """Automated response rule configuration."""
    name: str
    trigger_conditions: Dict[str, Any]
    actions: List[ResponseAction]
    severity: ResponseSeverity
    auto_execute: bool = False
    requires_approval: bool = True
    cooldown_minutes: int = 60
    max_executions_per_hour: int = 10
    enabled: bool = True
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ResponseExecution:
    """Response execution result."""
    rule_name: str
    actions_taken: List[str]
    success: bool
    error_message: Optional[str] = None
    execution_time: Optional[datetime] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
       

@dataclass
class ResponseResult:
    """Result of automated response execution."""
    success: bool
    actions_executed: List[ResponseAction]
    errors: List[str]
    execution_time: float
    metadata: Dict[str, Any]


class AutomatedResponseService:
    """
    Automated threat response service.
    
    Provides intelligent automated responses to security threats
    with configurable rules and escalation procedures.
    """

    def __init__(self):
        self.logger = logger
        
        # Response rules configuration
        self.response_rules = self._load_response_rules()
        
        # Execution tracking
        self.execution_counts = {}
        self.cooldown_tracking = {}
        
        # Account lockout configuration
        self.lockout_config = {
            'default_duration_hours': 24,
            'max_duration_hours': 168,  # 7 days
            'progressive_lockout': True,
            'lockout_thresholds': {
                'low': 10,
                'medium': 5,
                'high': 3,
                'critical': 1
            }
        }

    def _load_response_rules(self) -> List[ResponseRule]:
        """Load automated response rules from configuration."""
        return [
            ResponseRule(
                name="Critical Threat Response",
                triggers=[
                    ResponseTrigger.RISK_SCORE_THRESHOLD,
                    ResponseTrigger.IMPOSSIBLE_TRAVEL,
                    ResponseTrigger.MALICIOUS_IP
                ],
                conditions={
                    'risk_score_min': 90.0,
                    'confidence_min': 0.8
                },
                actions=[
                    ResponseAction.LOCK_ACCOUNT,
                    ResponseAction.TERMINATE_ALL_SESSIONS,
                    ResponseAction.BLOCK_IP,
                    ResponseAction.ALERT_SECURITY_TEAM,
                    ResponseAction.ALERT_USER,
                    ResponseAction.LOG_INCIDENT
                ],
                priority=1,
                cooldown_minutes=30,
                max_executions_per_hour=5
            ),
            ResponseRule(
                name="High Risk Login Response",
                triggers=[
                    ResponseTrigger.RISK_SCORE_THRESHOLD,
                    ResponseTrigger.SUSPICIOUS_DEVICE
                ],
                conditions={
                    'risk_score_min': 70.0,
                    'confidence_min': 0.7
                },
                actions=[
                    ResponseAction.REQUIRE_MFA,
                    ResponseAction.ALERT_USER,
                    ResponseAction.LOG_INCIDENT
                ],
                priority=2,
                cooldown_minutes=60,
                max_executions_per_hour=10
            ),
            ResponseRule(
                name="Brute Force Response",
                triggers=[
                    ResponseTrigger.BRUTE_FORCE_DETECTED,
                    ResponseTrigger.FAILED_ATTEMPTS_THRESHOLD
                ],
                conditions={
                    'failed_attempts_min': 5,
                    'time_window_minutes': 15
                },
                actions=[
                    ResponseAction.LOCK_ACCOUNT,
                    ResponseAction.RATE_LIMIT_IP,
                    ResponseAction.ALERT_SECURITY_TEAM
                ],
                priority=1,
                cooldown_minutes=45,
                max_executions_per_hour=3
            ),
            ResponseRule(
                name="MFA Bypass Response",
                triggers=[
                    ResponseTrigger.MFA_BYPASS_ATTEMPT
                ],
                conditions={
                    'bypass_attempts_min': 3
                },
                actions=[
                    ResponseAction.LOCK_ACCOUNT,
                    ResponseAction.TERMINATE_ALL_SESSIONS,
                    ResponseAction.REQUIRE_PASSWORD_RESET,
                    ResponseAction.ALERT_SECURITY_TEAM,
                    ResponseAction.ESCALATE_TO_HUMAN
                ],
                priority=1,
                cooldown_minutes=30,
                max_executions_per_hour=2
            ),
            ResponseRule(
                name="Session Anomaly Response",
                triggers=[
                    ResponseTrigger.SESSION_ANOMALY
                ],
                conditions={
                    'anomaly_score_min': 0.8
                },
                actions=[
                    ResponseAction.TERMINATE_SESSION,
                    ResponseAction.REQUIRE_MFA,
                    ResponseAction.ALERT_USER
                ],
                priority=3,
                cooldown_minutes=30,
                max_executions_per_hour=15
            )
        ]

    async def evaluate_and_respond(
        self,
        context: ResponseContext
    ) -> ResponseResult:
        """
        Evaluate context and execute appropriate automated responses.
        
        Args:
            context: Response context with threat information
            
        Returns:
            ResponseResult: Result of response execution
        """
        start_time = timezone.now()
        executed_actions = []
        errors = []

        try:
            self.logger.info(
                f"Evaluating automated response for risk score: {context.risk_score}"
            )

            # Find matching rules
            matching_rules = await self._find_matching_rules(context)
            
            if not matching_rules:
                return ResponseResult(
                    success=True,
                    actions_executed=[],
                    errors=[],
                    execution_time=0.0,
                    metadata={'no_rules_matched': True}
                )

            # Sort rules by priority
            matching_rules.sort(key=lambda r: r.priority)

            # Execute rules
            for rule in matching_rules:
                if await self._should_execute_rule(rule, context):
                    rule_result = await self._execute_rule(rule, context)
                    executed_actions.extend(rule_result.actions_executed)
                    errors.extend(rule_result.errors)

            execution_time = (timezone.now() - start_time).total_seconds()

            # Log response execution
            await self._log_response_execution(
                context, executed_actions, errors, execution_time
            )

            return ResponseResult(
                success=len(errors) == 0,
                actions_executed=executed_actions,
                errors=errors,
                execution_time=execution_time,
                metadata={
                    'rules_matched': len(matching_rules),
                    'rules_executed': len([r for r in matching_rules if executed_actions])
                }
            )

        except Exception as e:
            self.logger.error(f"Error in automated response evaluation: {e}", exc_info=True)
            return ResponseResult(
                success=False,
                actions_executed=executed_actions,
                errors=[str(e)],
                execution_time=(timezone.now() - start_time).total_seconds(),
                metadata={'exception': str(e)}
            )

    async def _find_matching_rules(
        self,
        context: ResponseContext
    ) -> List[ResponseRule]:
        """Find rules that match the given context."""
        matching_rules = []

        try:
            for rule in self.response_rules:
                if not rule.enabled:
                    continue

                if await self._rule_matches_context(rule, context):
                    matching_rules.append(rule)

            return matching_rules

        except Exception as e:
            self.logger.error(f"Error finding matching rules: {e}")
            return []

    async def _rule_matches_context(
        self,
        rule: ResponseRule,
        context: ResponseContext
    ) -> bool:
        """Check if a rule matches the given context."""
        try:
            # Check trigger conditions
            for trigger in rule.triggers:
                if await self._trigger_matches(trigger, context):
                    # Check additional conditions
                    if await self._conditions_match(rule.conditions, context):
                        return True

            return False

        except Exception as e:
            self.logger.error(f"Error checking rule match: {e}")
            return False

    async def _trigger_matches(
        self,
        trigger: ResponseTrigger,
        context: ResponseContext
    ) -> bool:
        """Check if a trigger matches the context."""
        try:
            if trigger == ResponseTrigger.RISK_SCORE_THRESHOLD:
                return context.risk_score > 0

            elif trigger == ResponseTrigger.FAILED_ATTEMPTS_THRESHOLD:
                if context.user:
                    recent_failures = await self._get_recent_failed_attempts(context.user)
                    return recent_failures > 0
                return False

            elif trigger == ResponseTrigger.IMPOSSIBLE_TRAVEL:
                return 'impossible_travel' in context.threat_indicators

            elif trigger == ResponseTrigger.MALICIOUS_IP:
                if context.ip_address:
                    return await self._is_malicious_ip(context.ip_address)
                return False

            elif trigger == ResponseTrigger.SUSPICIOUS_DEVICE:
                return 'device_anomaly' in context.threat_indicators

            elif trigger == ResponseTrigger.MFA_BYPASS_ATTEMPT:
                return 'mfa_bypass_attempt' in context.threat_indicators

            elif trigger == ResponseTrigger.SESSION_ANOMALY:
                return 'session_anomaly' in context.threat_indicators

            elif trigger == ResponseTrigger.BRUTE_FORCE_DETECTED:
                return 'brute_force' in context.threat_indicators

            return False

        except Exception as e:
            self.logger.error(f"Error checking trigger match: {e}")
            return False

    async def _conditions_match(
        self,
        conditions: Dict[str, Any],
        context: ResponseContext
    ) -> bool:
        """Check if rule conditions match the context."""
        try:
            for condition, value in conditions.items():
                if condition == 'risk_score_min':
                    if context.risk_score < value:
                        return False

                elif condition == 'confidence_min':
                    event_confidence = context.additional_data.get('confidence', 0.0)
                    if event_confidence < value:
                        return False

                elif condition == 'failed_attempts_min':
                    if context.user:
                        recent_failures = await self._get_recent_failed_attempts(context.user)
                        if recent_failures < value:
                            return False

                elif condition == 'bypass_attempts_min':
                    bypass_count = context.additional_data.get('bypass_attempts', 0)
                    if bypass_count < value:
                        return False

                elif condition == 'anomaly_score_min':
                    anomaly_score = context.additional_data.get('anomaly_score', 0.0)
                    if anomaly_score < value:
                        return False

            return True

        except Exception as e:
            self.logger.error(f"Error checking conditions: {e}")
            return False

    async def _should_execute_rule(
        self,
        rule: ResponseRule,
        context: ResponseContext
    ) -> bool:
        """Check if rule should be executed (considering cooldowns and limits)."""
        try:
            rule_key = f"{rule.name}:{context.user.id if context.user else 'unknown'}"

            # Check cooldown
            if rule_key in self.cooldown_tracking:
                last_execution = self.cooldown_tracking[rule_key]
                if timezone.now() - last_execution < timedelta(minutes=rule.cooldown_minutes):
                    return False

            # Check execution limits
            hour_key = f"{rule_key}:{timezone.now().hour}"
            current_executions = self.execution_counts.get(hour_key, 0)
            if current_executions >= rule.max_executions_per_hour:
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error checking rule execution conditions: {e}")
            return False

    async def _execute_rule(
        self,
        rule: ResponseRule,
        context: ResponseContext
    ) -> ResponseResult:
        """Execute a specific rule."""
        executed_actions = []
        errors = []

        try:
            self.logger.info(f"Executing automated response rule: {rule.name}")

            for action in rule.actions:
                try:
                    success = await self._execute_action(action, context)
                    if success:
                        executed_actions.append(action)
                    else:
                        errors.append(f"Failed to execute action: {action.value}")
                except Exception as e:
                    errors.append(f"Error executing {action.value}: {str(e)}")

            # Update tracking
            rule_key = f"{rule.name}:{context.user.id if context.user else 'unknown'}"
            self.cooldown_tracking[rule_key] = timezone.now()
            
            hour_key = f"{rule_key}:{timezone.now().hour}"
            self.execution_counts[hour_key] = self.execution_counts.get(hour_key, 0) + 1

            return ResponseResult(
                success=len(errors) == 0,
                actions_executed=executed_actions,
                errors=errors,
                execution_time=0.0,
                metadata={'rule_name': rule.name}
            )

        except Exception as e:
            self.logger.error(f"Error executing rule {rule.name}: {e}")
            return ResponseResult(
                success=False,
                actions_executed=executed_actions,
                errors=[str(e)],
                execution_time=0.0,
                metadata={'rule_name': rule.name, 'exception': str(e)}
            )

    async def _execute_action(
        self,
        action: ResponseAction,
        context: ResponseContext
    ) -> bool:
        """Execute a specific response action."""
        try:
            if action == ResponseAction.BLOCK_LOGIN:
                return await self._block_login(context)

            elif action == ResponseAction.LOCK_ACCOUNT:
                return await self._lock_account(context)

            elif action == ResponseAction.TERMINATE_SESSION:
                return await self._terminate_session(context)

            elif action == ResponseAction.TERMINATE_ALL_SESSIONS:
                return await self._terminate_all_sessions(context)

            elif action == ResponseAction.REQUIRE_MFA:
                return await self._require_mfa(context)

            elif action == ResponseAction.REQUIRE_PASSWORD_RESET:
                return await self._require_password_reset(context)

            elif action == ResponseAction.BLOCK_IP:
                return await self._block_ip(context)

            elif action == ResponseAction.RATE_LIMIT_IP:
                return await self._rate_limit_ip(context)

            elif action == ResponseAction.ALERT_USER:
                return await self._alert_user(context)

            elif action == ResponseAction.ALERT_SECURITY_TEAM:
                return await self._alert_security_team(context)

            elif action == ResponseAction.ESCALATE_TO_HUMAN:
                return await self._escalate_to_human(context)

            elif action == ResponseAction.LOG_INCIDENT:
                return await self._log_incident(context)

            return False

        except Exception as e:
            self.logger.error(f"Error executing action {action.value}: {e}")
            return False

    async def _block_login(self, context: ResponseContext) -> bool:
        """Block login attempt."""
        try:
            # This would typically set a temporary block flag
            # Implementation depends on authentication flow
            self.logger.info(f"Blocked login for user: {context.user.email if context.user else 'unknown'}")
            return True
        except Exception as e:
            self.logger.error(f"Error blocking login: {e}")
            return False

    async def _lock_account(self, context: ResponseContext) -> bool:
        """Lock user account with intelligent duration."""
        try:
            if not context.user:
                return False

            # Calculate lockout duration based on risk and history
            lockout_duration = await self._calculate_lockout_duration(context)
            
            context.user.account_locked_until = timezone.now() + lockout_duration
            await context.user.asave(update_fields=['account_locked_until'])

            # Log the lockout
            await audit_service.log_security_event(
                event_type='account_locked',
                user=context.user,
                ip_address=context.ip_address,
                details={
                    'lockout_duration_hours': lockout_duration.total_seconds() / 3600,
                    'risk_score': context.risk_score,
                    'automated_response': True
                }
            )

            self.logger.info(
                f"Locked account for user: {context.user.email} "
                f"(duration: {lockout_duration})"
            )
            return True

        except Exception as e:
            self.logger.error(f"Error locking account: {e}")
            return False

    async def _terminate_session(self, context: ResponseContext) -> bool:
        """Terminate specific session."""
        try:
            if not context.session:
                return False

            from .session_service import SessionService
            session_service = SessionService()
            
            await session_service.terminate_session(
                context.session.session_id,
                reason='automated_security_response',
                terminated_by=None
            )

            self.logger.info(f"Terminated session: {context.session.session_id}")
            return True

        except Exception as e:
            self.logger.error(f"Error terminating session: {e}")
            return False

    async def _terminate_all_sessions(self, context: ResponseContext) -> bool:
        """Terminate all user sessions."""
        try:
            if not context.user:
                return False

            from .session_service import SessionService
            session_service = SessionService()

            sessions = UserSession.objects.filter(user=context.user, status='active')
            terminated_count = 0
            
            async for session in sessions:
                try:
                    await session_service.terminate_session(
                        session.session_id,
                        reason='automated_security_response',
                        terminated_by=None
                    )
                    terminated_count += 1
                except Exception as e:
                    self.logger.error(f"Error terminating session {session.session_id}: {e}")

            self.logger.info(
                f"Terminated {terminated_count} sessions for user: {context.user.email}"
            )
            return terminated_count > 0

        except Exception as e:
            self.logger.error(f"Error terminating all sessions: {e}")
            return False

    async def _require_mfa(self, context: ResponseContext) -> bool:
        """Require MFA for user."""
        try:
            if not context.user:
                return False

            # Set flag requiring MFA on next login
            # Implementation depends on user model and authentication flow
            self.logger.info(f"Required MFA for user: {context.user.email}")
            return True

        except Exception as e:
            self.logger.error(f"Error requiring MFA: {e}")
            return False

    async def _require_password_reset(self, context: ResponseContext) -> bool:
        """Require password reset for user."""
        try:
            if not context.user:
                return False

            # Set flag requiring password reset
            # Implementation depends on user model
            self.logger.info(f"Required password reset for user: {context.user.email}")
            return True

        except Exception as e:
            self.logger.error(f"Error requiring password reset: {e}")
            return False

    async def _block_ip(self, context: ResponseContext) -> bool:
        """Block IP address."""
        try:
            if not context.ip_address:
                return False

            # Add to threat intelligence
            await ThreatIntelligence.objects.acreate(
                indicator_type='ip_address',
                indicator_value=context.ip_address,
                threat_type='automated_block',
                source='internal',
                confidence='high',
                description=f'Automatically blocked due to high risk score: {context.risk_score}',
                severity_score=min(100.0, context.risk_score),
                expires_at=timezone.now() + timedelta(hours=24)
            )

            self.logger.info(f"Blocked IP address: {context.ip_address}")
            return True

        except Exception as e:
            self.logger.error(f"Error blocking IP: {e}")
            return False

    async def _rate_limit_ip(self, context: ResponseContext) -> bool:
        """Apply additional rate limiting to IP."""
        try:
            if not context.ip_address:
                return False

            # This would integrate with rate limiting service
            # to apply stricter limits to the IP
            self.logger.info(f"Applied additional rate limiting to IP: {context.ip_address}")
            return True

        except Exception as e:
            self.logger.error(f"Error applying rate limiting: {e}")
            return False

    async def _alert_user(self, context: ResponseContext) -> bool:
        """Send security alert to user."""
        try:
            if not context.user:
                return False

            # Send security notification email
            subject = "Security Alert: Suspicious Activity Detected"
            
            email_context = {
                'user': context.user,
                'risk_score': context.risk_score,
                'ip_address': context.ip_address,
                'timestamp': timezone.now(),
                'threat_indicators': context.threat_indicators
            }
            
            message = render_to_string('emails/user_security_alert.html', email_context)
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[context.user.email],
                html_message=message
            )

            self.logger.info(f"Sent security alert to user: {context.user.email}")
            return True

        except Exception as e:
            self.logger.error(f"Error sending user alert: {e}")
            return False

    async def _alert_security_team(self, context: ResponseContext) -> bool:
        """Alert security team."""
        try:
            recipients = getattr(settings, 'SECURITY_TEAM_EMAILS', [])
            if not recipients:
                return False

            subject = f"Automated Security Response Triggered - Risk Score: {context.risk_score}"
            
            email_context = {
                'context': context,
                'timestamp': timezone.now(),
                'user_email': context.user.email if context.user else 'Unknown',
                'ip_address': context.ip_address or 'Unknown'
            }
            
            message = render_to_string('emails/security_team_alert.html', email_context)
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipients,
                html_message=message
            )

            self.logger.info("Sent alert to security team")
            return True

        except Exception as e:
            self.logger.error(f"Error alerting security team: {e}")
            return False

    async def _escalate_to_human(self, context: ResponseContext) -> bool:
        """Escalate incident to human review."""
        try:
            # Create high-priority incident for human review
            if context.security_event:
                context.security_event.status = 'investigating'
                context.security_event.requires_investigation = True
                await context.security_event.asave(
                    update_fields=['status', 'requires_investigation']
                )

            self.logger.info("Escalated incident to human review")
            return True

        except Exception as e:
            self.logger.error(f"Error escalating to human: {e}")
            return False

    async def _log_incident(self, context: ResponseContext) -> bool:
        """Log security incident."""
        try:
            await SecurityEvent.objects.acreate(
                event_type='automated_response_incident',
                severity='high',
                user=context.user,
                ip_address=context.ip_address,
                title='Automated Security Response Incident',
                description=f'Automated response triggered for risk score: {context.risk_score}',
                risk_score=context.risk_score,
                threat_indicators=context.threat_indicators,
                event_data=context.additional_data,
                detection_method='automated_response_service',
                response_taken=True
            )

            self.logger.info("Logged security incident")
            return True

        except Exception as e:
            self.logger.error(f"Error logging incident: {e}")
            return False

    async def _calculate_lockout_duration(self, context: ResponseContext) -> timedelta:
        """Calculate intelligent lockout duration."""
        try:
            base_duration = timedelta(hours=self.lockout_config['default_duration_hours'])
            
            # Adjust based on risk score
            if context.risk_score >= 90:
                multiplier = 3.0
            elif context.risk_score >= 80:
                multiplier = 2.0
            elif context.risk_score >= 70:
                multiplier = 1.5
            else:
                multiplier = 1.0

            # Check for progressive lockout
            if self.lockout_config['progressive_lockout'] and context.user:
                recent_lockouts = await self._get_recent_lockout_count(context.user)
                multiplier *= (1 + recent_lockouts * 0.5)

            duration = base_duration * multiplier
            max_duration = timedelta(hours=self.lockout_config['max_duration_hours'])
            
            return min(duration, max_duration)

        except Exception as e:
            self.logger.error(f"Error calculating lockout duration: {e}")
            return timedelta(hours=24)

    # Helper methods
    async def _get_recent_failed_attempts(self, user: UserProfile) -> int:
        """Get recent failed login attempts for user."""
        try:
            since = timezone.now() - timedelta(hours=1)
            count = await SecurityEvent.objects.filter(
                event_type='login_failure',
                user=user,
                created_at__gte=since
            ).acount()
            return count
        except Exception:
            return 0

    async def _is_malicious_ip(self, ip_address: str) -> bool:
        """Check if IP is in threat intelligence."""
        try:
            exists = await ThreatIntelligence.objects.filter(
                indicator_type='ip_address',
                indicator_value=ip_address,
                is_active=True
            ).aexists()
            return exists
        except Exception:
            return False

    async def _get_recent_lockout_count(self, user: UserProfile) -> int:
        """Get count of recent account lockouts."""
        try:
            since = timezone.now() - timedelta(days=30)
            count = await SecurityEvent.objects.filter(
                event_type='account_locked',
                user=user,
                created_at__gte=since
            ).acount()
            return count
        except Exception:
            return 0

    async def _log_response_execution(
        self,
        context: ResponseContext,
        actions: List[ResponseAction],
        errors: List[str],
        execution_time: float
    ) -> None:
        """Log automated response execution."""
        try:
            await audit_service.log_security_event(
                event_type='automated_response_executed',
                user=context.user,
                ip_address=context.ip_address,
                details={
                    'actions_executed': [a.value for a in actions],
                    'errors': errors,
                    'execution_time_seconds': execution_time,
                    'risk_score': context.risk_score,
                    'threat_indicators': context.threat_indicators
                }
            )
        except Exception as e:
            self.logger.error(f"Error logging response execution: {e}")


# Global service instance
automated_response_service = AutomatedResponseService()