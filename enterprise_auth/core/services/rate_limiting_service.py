"""
Comprehensive rate limiting service for enterprise authentication system.

This service provides multi-level rate limiting with progressive delays,
trusted source bypass, analytics, and monitoring capabilities.
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
from django.db.models import Q, Count, Sum, Avg
from django.utils import timezone
from django.contrib.auth import get_user_model

import redis
from redis.exceptions import RedisError

from ..models import UserProfile, SecurityEvent
from ..exceptions import RateLimitExceededError, RateLimitError
from .audit_service import audit_service


logger = logging.getLogger(__name__)
User = get_user_model()


class RateLimitType(Enum):
    """Types of rate limits."""
    IP = "ip"
    USER = "user"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    GLOBAL = "global"


class RateLimitAction(Enum):
    """Actions to take when rate limit is exceeded."""
    BLOCK = "block"
    DELAY = "delay"
    CAPTCHA = "captcha"
    MFA_REQUIRED = "mfa_required"
    LOG_ONLY = "log_only"


@dataclass
class RateLimitRule:
    """Rate limiting rule configuration."""
    name: str
    limit_type: RateLimitType
    requests: int
    window_seconds: int
    action: RateLimitAction
    progressive_delay: bool = True
    bypass_trusted: bool = True
    priority: int = 1
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class RateLimitResult:
    """Result of rate limit check."""
    allowed: bool
    limit_type: RateLimitType
    rule_name: str
    current_count: int
    limit: int
    window_seconds: int
    reset_time: datetime
    retry_after: Optional[int] = None
    delay_seconds: Optional[float] = None
    action: Optional[RateLimitAction] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'allowed': self.allowed,
            'limit_type': self.limit_type.value,
            'rule_name': self.rule_name,
            'current_count': self.current_count,
            'limit': self.limit,
            'window_seconds': self.window_seconds,
            'reset_time': self.reset_time.isoformat(),
            'retry_after': self.retry_after,
            'delay_seconds': self.delay_seconds,
            'action': self.action.value if self.action else None,
            'metadata': self.metadata
        }


@dataclass
class RateLimitContext:
    """Context for rate limit evaluation."""
    ip_address: str
    user: Optional[UserProfile] = None
    endpoint: Optional[str] = None
    application: Optional[str] = None
    user_agent: Optional[str] = None
    request_headers: Optional[Dict[str, str]] = None
    is_trusted_source: bool = False
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class RateLimitingService:
    """
    Comprehensive rate limiting service with multi-level controls.
    
    Provides IP, user, endpoint, and application-level rate limiting
    with progressive delays, trusted source bypass, and analytics.
    """

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.redis_client = self._initialize_redis()
        
        # Default rate limiting rules
        self.default_rules = self._load_default_rules()
        
        # Cache configuration
        self.cache_prefix = "rate_limit"
        self.analytics_cache_ttl = 3600  # 1 hour
        
        # Trusted sources cache
        self.trusted_sources_cache_key = f"{self.cache_prefix}:trusted_sources"
        self.trusted_sources_cache_ttl = 300  # 5 minutes
        
    def _initialize_redis(self) -> Optional[redis.Redis]:
        """Initialize Redis client for rate limiting."""
        try:
            redis_config = getattr(settings, 'REDIS_CONFIG', {})
            redis_client = redis.Redis(
                host=redis_config.get('HOST', 'localhost'),
                port=redis_config.get('PORT', 6379),
                db=redis_config.get('RATE_LIMIT_DB', 2),
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Test connection
            redis_client.ping()
            self.logger.info("Redis client initialized successfully for rate limiting")
            return redis_client
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Redis client: {e}")
            return None
    
    def _load_default_rules(self) -> List[RateLimitRule]:
        """Load default rate limiting rules."""
        return [
            # IP-based rate limits
            RateLimitRule(
                name="ip_login_burst",
                limit_type=RateLimitType.IP,
                requests=5,
                window_seconds=60,
                action=RateLimitAction.DELAY,
                progressive_delay=True,
                priority=1
            ),
            RateLimitRule(
                name="ip_login_sustained",
                limit_type=RateLimitType.IP,
                requests=20,
                window_seconds=3600,
                action=RateLimitAction.BLOCK,
                progressive_delay=True,
                priority=2
            ),
            RateLimitRule(
                name="ip_api_burst",
                limit_type=RateLimitType.IP,
                requests=100,
                window_seconds=60,
                action=RateLimitAction.DELAY,
                priority=3
            ),
            RateLimitRule(
                name="ip_api_sustained",
                limit_type=RateLimitType.IP,
                requests=1000,
                window_seconds=3600,
                action=RateLimitAction.BLOCK,
                priority=4
            ),
            
            # User-based rate limits
            RateLimitRule(
                name="user_login_attempts",
                limit_type=RateLimitType.USER,
                requests=10,
                window_seconds=300,
                action=RateLimitAction.DELAY,
                progressive_delay=True,
                bypass_trusted=False,
                priority=1
            ),
            RateLimitRule(
                name="user_password_reset",
                limit_type=RateLimitType.USER,
                requests=3,
                window_seconds=3600,
                action=RateLimitAction.BLOCK,
                bypass_trusted=False,
                priority=1
            ),
            RateLimitRule(
                name="user_mfa_attempts",
                limit_type=RateLimitType.USER,
                requests=5,
                window_seconds=300,
                action=RateLimitAction.DELAY,
                progressive_delay=True,
                bypass_trusted=False,
                priority=1
            ),
            
            # Endpoint-based rate limits
            RateLimitRule(
                name="endpoint_auth_login",
                limit_type=RateLimitType.ENDPOINT,
                requests=1000,
                window_seconds=60,
                action=RateLimitAction.DELAY,
                priority=2
            ),
            RateLimitRule(
                name="endpoint_auth_register",
                limit_type=RateLimitType.ENDPOINT,
                requests=100,
                window_seconds=60,
                action=RateLimitAction.BLOCK,
                priority=2
            ),
            
            # Application-level rate limits
            RateLimitRule(
                name="app_global_requests",
                limit_type=RateLimitType.APPLICATION,
                requests=10000,
                window_seconds=60,
                action=RateLimitAction.LOG_ONLY,
                priority=5
            ),
        ]
    
    async def check_rate_limit(
        self,
        context: RateLimitContext,
        endpoint: Optional[str] = None
    ) -> List[RateLimitResult]:
        """
        Check rate limits for the given context.
        
        Args:
            context: Rate limiting context
            endpoint: Specific endpoint to check (optional)
            
        Returns:
            List[RateLimitResult]: Results for all applicable rate limits
        """
        self.logger.debug(
            f"Checking rate limits for IP: {context.ip_address}, "
            f"User: {context.user.email if context.user else 'Anonymous'}, "
            f"Endpoint: {endpoint or context.endpoint}"
        )
        
        results = []
        
        # Get applicable rules
        applicable_rules = self._get_applicable_rules(context, endpoint)
        
        # Check trusted source bypass
        if context.is_trusted_source or await self._is_trusted_source(context):
            # Apply only non-bypassable rules
            applicable_rules = [
                rule for rule in applicable_rules 
                if not rule.bypass_trusted
            ]
            self.logger.debug(f"Trusted source detected, applying {len(applicable_rules)} non-bypassable rules")
        
        # Check each applicable rule
        for rule in applicable_rules:
            try:
                result = await self._check_single_rule(context, rule)
                results.append(result)
                
                # Log rate limit violations
                if not result.allowed:
                    await self._log_rate_limit_violation(context, result)
                
            except Exception as e:
                self.logger.error(f"Failed to check rule {rule.name}: {e}")
                continue
        
        # Sort results by priority (blocked results first)
        results.sort(key=lambda r: (r.allowed, r.rule_name))
        
        self.logger.debug(f"Rate limit check completed: {len(results)} rules checked")
        
        return results
    
    async def increment_counter(
        self,
        context: RateLimitContext,
        endpoint: Optional[str] = None,
        amount: int = 1
    ) -> None:
        """
        Increment rate limit counters.
        
        Args:
            context: Rate limiting context
            endpoint: Specific endpoint (optional)
            amount: Amount to increment (default: 1)
        """
        applicable_rules = self._get_applicable_rules(context, endpoint)
        
        for rule in applicable_rules:
            try:
                await self._increment_rule_counter(context, rule, amount)
            except Exception as e:
                self.logger.error(f"Failed to increment counter for rule {rule.name}: {e}")
    
    async def reset_rate_limit(
        self,
        context: RateLimitContext,
        rule_name: Optional[str] = None
    ) -> bool:
        """
        Reset rate limit counters.
        
        Args:
            context: Rate limiting context
            rule_name: Specific rule to reset (optional, resets all if None)
            
        Returns:
            bool: True if reset was successful
        """
        try:
            if rule_name:
                # Reset specific rule
                rule = next((r for r in self.default_rules if r.name == rule_name), None)
                if rule:
                    key = self._get_rate_limit_key(context, rule)
                    await self._reset_counter(key)
                    self.logger.info(f"Reset rate limit for rule {rule_name}")
                    return True
            else:
                # Reset all applicable rules
                applicable_rules = self._get_applicable_rules(context)
                for rule in applicable_rules:
                    key = self._get_rate_limit_key(context, rule)
                    await self._reset_counter(key)
                
                self.logger.info(f"Reset all rate limits for context")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to reset rate limit: {e}")
            return False
        
        return False
    
    async def get_rate_limit_status(
        self,
        context: RateLimitContext
    ) -> Dict[str, Any]:
        """
        Get current rate limit status for context.
        
        Args:
            context: Rate limiting context
            
        Returns:
            Dict[str, Any]: Current status for all applicable rules
        """
        status = {}
        applicable_rules = self._get_applicable_rules(context)
        
        for rule in applicable_rules:
            try:
                key = self._get_rate_limit_key(context, rule)
                current_count = await self._get_current_count(key)
                
                status[rule.name] = {
                    'current_count': current_count,
                    'limit': rule.requests,
                    'window_seconds': rule.window_seconds,
                    'remaining': max(0, rule.requests - current_count),
                    'reset_time': self._get_reset_time(rule.window_seconds).isoformat()
                }
                
            except Exception as e:
                self.logger.error(f"Failed to get status for rule {rule.name}: {e}")
                status[rule.name] = {'error': str(e)}
        
        return status
    
    async def get_analytics(
        self,
        time_range: timedelta = timedelta(hours=24)
    ) -> Dict[str, Any]:
        """
        Get rate limiting analytics.
        
        Args:
            time_range: Time range for analytics
            
        Returns:
            Dict[str, Any]: Analytics data
        """
        cache_key = f"{self.cache_prefix}:analytics:{int(time_range.total_seconds())}"
        cached_analytics = cache.get(cache_key)
        
        if cached_analytics:
            return cached_analytics
        
        try:
            since = timezone.now() - time_range
            
            # Get rate limit violations from security events
            violations = SecurityEvent.objects.filter(
                event_type='rate_limit_exceeded',
                created_at__gte=since
            )
            
            analytics = {
                'total_violations': violations.count(),
                'violations_by_type': {},
                'violations_by_ip': {},
                'violations_by_endpoint': {},
                'violations_over_time': {},
                'top_violating_ips': [],
                'top_violated_rules': []
            }
            
            # Violations by type
            for violation in violations:
                rule_name = violation.event_data.get('rule_name', 'unknown')
                analytics['violations_by_type'][rule_name] = (
                    analytics['violations_by_type'].get(rule_name, 0) + 1
                )
            
            # Violations by IP
            ip_violations = violations.values('ip_address').annotate(
                count=Count('id')
            ).order_by('-count')[:10]
            
            for item in ip_violations:
                analytics['violations_by_ip'][item['ip_address']] = item['count']
            
            # Top violating IPs
            analytics['top_violating_ips'] = [
                {'ip': item['ip_address'], 'count': item['count']}
                for item in ip_violations
            ]
            
            # Top violated rules
            rule_violations = list(analytics['violations_by_type'].items())
            rule_violations.sort(key=lambda x: x[1], reverse=True)
            analytics['top_violated_rules'] = [
                {'rule': rule, 'count': count}
                for rule, count in rule_violations[:10]
            ]
            
            # Cache analytics
            cache.set(cache_key, analytics, self.analytics_cache_ttl)
            
            return analytics
            
        except Exception as e:
            self.logger.error(f"Failed to get analytics: {e}")
            return {}
    
    async def add_trusted_source(
        self,
        ip_address: str,
        reason: str,
        expires_at: Optional[datetime] = None
    ) -> bool:
        """
        Add IP address to trusted sources.
        
        Args:
            ip_address: IP address to trust
            reason: Reason for trusting
            expires_at: Optional expiration time
            
        Returns:
            bool: True if added successfully
        """
        try:
            trusted_sources = await self._get_trusted_sources()
            
            trusted_sources[ip_address] = {
                'reason': reason,
                'added_at': timezone.now().isoformat(),
                'expires_at': expires_at.isoformat() if expires_at else None
            }
            
            await self._save_trusted_sources(trusted_sources)
            
            self.logger.info(f"Added trusted source: {ip_address} - {reason}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add trusted source {ip_address}: {e}")
            return False
    
    async def remove_trusted_source(self, ip_address: str) -> bool:
        """
        Remove IP address from trusted sources.
        
        Args:
            ip_address: IP address to remove
            
        Returns:
            bool: True if removed successfully
        """
        try:
            trusted_sources = await self._get_trusted_sources()
            
            if ip_address in trusted_sources:
                del trusted_sources[ip_address]
                await self._save_trusted_sources(trusted_sources)
                
                self.logger.info(f"Removed trusted source: {ip_address}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to remove trusted source {ip_address}: {e}")
            return False
    
    # Private helper methods
    
    def _get_applicable_rules(
        self,
        context: RateLimitContext,
        endpoint: Optional[str] = None
    ) -> List[RateLimitRule]:
        """Get applicable rate limiting rules for context."""
        applicable_rules = []
        
        for rule in self.default_rules:
            if self._is_rule_applicable(rule, context, endpoint):
                applicable_rules.append(rule)
        
        # Sort by priority
        applicable_rules.sort(key=lambda r: r.priority)
        
        return applicable_rules
    
    def _is_rule_applicable(
        self,
        rule: RateLimitRule,
        context: RateLimitContext,
        endpoint: Optional[str] = None
    ) -> bool:
        """Check if a rule is applicable to the context."""
        if rule.limit_type == RateLimitType.IP:
            return True
        elif rule.limit_type == RateLimitType.USER:
            return context.user is not None
        elif rule.limit_type == RateLimitType.ENDPOINT:
            return endpoint is not None or context.endpoint is not None
        elif rule.limit_type == RateLimitType.APPLICATION:
            return context.application is not None
        elif rule.limit_type == RateLimitType.GLOBAL:
            return True
        
        return False
    
    async def _check_single_rule(
        self,
        context: RateLimitContext,
        rule: RateLimitRule
    ) -> RateLimitResult:
        """Check a single rate limiting rule."""
        key = self._get_rate_limit_key(context, rule)
        current_count = await self._get_current_count(key)
        reset_time = self._get_reset_time(rule.window_seconds)
        
        # Check if limit is exceeded
        if current_count >= rule.requests:
            # Calculate retry after and delay
            retry_after = int((reset_time - timezone.now()).total_seconds())
            delay_seconds = None
            
            if rule.progressive_delay:
                delay_seconds = self._calculate_progressive_delay(
                    current_count, rule.requests
                )
            
            return RateLimitResult(
                allowed=False,
                limit_type=rule.limit_type,
                rule_name=rule.name,
                current_count=current_count,
                limit=rule.requests,
                window_seconds=rule.window_seconds,
                reset_time=reset_time,
                retry_after=retry_after,
                delay_seconds=delay_seconds,
                action=rule.action,
                metadata={'key': key}
            )
        
        return RateLimitResult(
            allowed=True,
            limit_type=rule.limit_type,
            rule_name=rule.name,
            current_count=current_count,
            limit=rule.requests,
            window_seconds=rule.window_seconds,
            reset_time=reset_time,
            metadata={'key': key}
        )
    
    def _get_rate_limit_key(
        self,
        context: RateLimitContext,
        rule: RateLimitRule
    ) -> str:
        """Generate rate limit key for context and rule."""
        key_parts = [self.cache_prefix, rule.name]
        
        if rule.limit_type == RateLimitType.IP:
            key_parts.append(f"ip:{context.ip_address}")
        elif rule.limit_type == RateLimitType.USER and context.user:
            key_parts.append(f"user:{context.user.id}")
        elif rule.limit_type == RateLimitType.ENDPOINT:
            endpoint = context.endpoint or "unknown"
            key_parts.append(f"endpoint:{endpoint}")
        elif rule.limit_type == RateLimitType.APPLICATION and context.application:
            key_parts.append(f"app:{context.application}")
        elif rule.limit_type == RateLimitType.GLOBAL:
            key_parts.append("global")
        
        # Add time window to key for automatic expiration
        window_start = int(time.time() // rule.window_seconds)
        key_parts.append(str(window_start))
        
        return ":".join(key_parts)
    
    async def _get_current_count(self, key: str) -> int:
        """Get current count for rate limit key."""
        try:
            if self.redis_client:
                count = self.redis_client.get(key)
                return int(count) if count else 0
            else:
                # Fallback to Django cache
                return cache.get(key, 0)
        except Exception as e:
            self.logger.error(f"Failed to get count for key {key}: {e}")
            return 0
    
    async def _increment_rule_counter(
        self,
        context: RateLimitContext,
        rule: RateLimitRule,
        amount: int = 1
    ) -> None:
        """Increment counter for a specific rule."""
        key = self._get_rate_limit_key(context, rule)
        
        try:
            if self.redis_client:
                # Use Redis pipeline for atomic operations
                pipe = self.redis_client.pipeline()
                pipe.incr(key, amount)
                pipe.expire(key, rule.window_seconds)
                pipe.execute()
            else:
                # Fallback to Django cache
                current = cache.get(key, 0)
                cache.set(key, current + amount, rule.window_seconds)
                
        except Exception as e:
            self.logger.error(f"Failed to increment counter for key {key}: {e}")
    
    async def _reset_counter(self, key: str) -> None:
        """Reset counter for rate limit key."""
        try:
            if self.redis_client:
                self.redis_client.delete(key)
            else:
                cache.delete(key)
        except Exception as e:
            self.logger.error(f"Failed to reset counter for key {key}: {e}")
    
    def _get_reset_time(self, window_seconds: int) -> datetime:
        """Get reset time for rate limit window."""
        current_window = int(time.time() // window_seconds)
        next_window_start = (current_window + 1) * window_seconds
        return datetime.fromtimestamp(next_window_start, tz=timezone.utc)
    
    def _calculate_progressive_delay(
        self,
        current_count: int,
        limit: int
    ) -> float:
        """Calculate progressive delay based on current count."""
        if current_count <= limit:
            return 0.0
        
        # Exponential backoff with jitter
        excess = current_count - limit
        base_delay = min(60.0, 2 ** min(excess, 10))  # Cap at 60 seconds
        
        # Add jitter (±20%)
        import random
        jitter = random.uniform(0.8, 1.2)
        
        return base_delay * jitter
    
    async def _is_trusted_source(self, context: RateLimitContext) -> bool:
        """Check if context represents a trusted source."""
        try:
            trusted_sources = await self._get_trusted_sources()
            
            if context.ip_address in trusted_sources:
                source_info = trusted_sources[context.ip_address]
                
                # Check expiration
                if source_info.get('expires_at'):
                    expires_at = datetime.fromisoformat(source_info['expires_at'])
                    if expires_at <= timezone.now():
                        # Remove expired trusted source
                        await self.remove_trusted_source(context.ip_address)
                        return False
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to check trusted source: {e}")
            return False
    
    async def _get_trusted_sources(self) -> Dict[str, Any]:
        """Get trusted sources from cache."""
        try:
            trusted_sources = cache.get(self.trusted_sources_cache_key, {})
            return trusted_sources
        except Exception as e:
            self.logger.error(f"Failed to get trusted sources: {e}")
            return {}
    
    async def _save_trusted_sources(self, trusted_sources: Dict[str, Any]) -> None:
        """Save trusted sources to cache."""
        try:
            cache.set(
                self.trusted_sources_cache_key,
                trusted_sources,
                self.trusted_sources_cache_ttl
            )
        except Exception as e:
            self.logger.error(f"Failed to save trusted sources: {e}")
    
    async def _log_rate_limit_violation(
        self,
        context: RateLimitContext,
        result: RateLimitResult
    ) -> None:
        """Log rate limit violation as security event."""
        try:
            SecurityEvent.objects.create(
                event_type='rate_limit_exceeded',
                severity='medium' if result.action == RateLimitAction.DELAY else 'high',
                user=context.user,
                ip_address=context.ip_address,
                user_agent=context.user_agent,
                request_id=context.correlation_id,
                title=f"Rate limit exceeded: {result.rule_name}",
                description=(
                    f"Rate limit exceeded for rule '{result.rule_name}': "
                    f"{result.current_count}/{result.limit} requests in "
                    f"{result.window_seconds}s window"
                ),
                risk_score=50.0 if result.action == RateLimitAction.BLOCK else 25.0,
                event_data=result.to_dict(),
                detection_method="RateLimitingService"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to log rate limit violation: {e}")


# Global service instance
rate_limiting_service = RateLimitingService()