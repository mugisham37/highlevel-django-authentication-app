"""
Redis-based rate limiting system for the enterprise authentication backend.
Implements multiple rate limiting algorithms with distributed counters.
"""

import logging
import time
import json
from typing import Dict, List, Optional, Tuple, Union
from datetime import datetime, timedelta
from django.conf import settings
from .redis_config import get_redis_connection
from .cache_manager import CacheKeyManager
import math

logger = logging.getLogger(__name__)


class RateLimitResult:
    """
    Result object for rate limit checks.
    """
    
    def __init__(self, allowed: bool, limit: int, remaining: int, 
                 reset_time: int, retry_after: int = None):
        self.allowed = allowed
        self.limit = limit
        self.remaining = remaining
        self.reset_time = reset_time
        self.retry_after = retry_after
    
    def to_dict(self) -> Dict[str, Union[bool, int]]:
        """Convert to dictionary for API responses."""
        result = {
            'allowed': self.allowed,
            'limit': self.limit,
            'remaining': self.remaining,
            'reset_time': self.reset_time
        }
        if self.retry_after is not None:
            result['retry_after'] = self.retry_after
        return result


class TokenBucketRateLimiter:
    """
    Token bucket rate limiting algorithm implementation.
    Allows burst traffic up to bucket capacity while maintaining average rate.
    """
    
    def __init__(self, redis_conn=None):
        self.redis_conn = redis_conn or get_redis_connection('rate_limit')
    
    def check_rate_limit(self, key: str, limit: int, window_seconds: int, 
                        burst_limit: int = None) -> RateLimitResult:
        """
        Check rate limit using token bucket algorithm.
        
        Args:
            key: Unique identifier for rate limiting
            limit: Number of tokens per window
            window_seconds: Time window in seconds
            burst_limit: Maximum burst capacity (defaults to limit)
            
        Returns:
            RateLimitResult object
        """
        if burst_limit is None:
            burst_limit = limit
        
        current_time = time.time()
        bucket_key = CacheKeyManager.generate_key('rate_limit', 'bucket', key)
        
        try:
            # Use Lua script for atomic operations
            lua_script = """
            local bucket_key = KEYS[1]
            local limit = tonumber(ARGV[1])
            local window_seconds = tonumber(ARGV[2])
            local burst_limit = tonumber(ARGV[3])
            local current_time = tonumber(ARGV[4])
            
            local bucket_data = redis.call('HMGET', bucket_key, 'tokens', 'last_refill')
            local tokens = tonumber(bucket_data[1]) or burst_limit
            local last_refill = tonumber(bucket_data[2]) or current_time
            
            -- Calculate tokens to add based on time elapsed
            local time_elapsed = current_time - last_refill
            local tokens_to_add = math.floor(time_elapsed * (limit / window_seconds))
            
            -- Refill tokens up to burst limit
            tokens = math.min(burst_limit, tokens + tokens_to_add)
            
            local allowed = tokens >= 1
            local remaining = tokens
            
            if allowed then
                tokens = tokens - 1
                remaining = tokens
            end
            
            -- Update bucket state
            redis.call('HMSET', bucket_key, 'tokens', tokens, 'last_refill', current_time)
            redis.call('EXPIRE', bucket_key, window_seconds * 2)
            
            -- Calculate reset time (when bucket will be full)
            local reset_time = current_time + ((burst_limit - tokens) * (window_seconds / limit))
            
            return {allowed and 1 or 0, limit, remaining, math.floor(reset_time)}
            """
            
            result = self.redis_conn.eval(
                lua_script, 1, bucket_key, 
                limit, window_seconds, burst_limit, current_time
            )
            
            allowed, rate_limit, remaining, reset_time = result
            retry_after = None
            
            if not allowed:
                # Calculate retry after time
                retry_after = max(1, int(reset_time - current_time))
            
            return RateLimitResult(
                allowed=bool(allowed),
                limit=rate_limit,
                remaining=int(remaining),
                reset_time=int(reset_time),
                retry_after=retry_after
            )
            
        except Exception as e:
            logger.error(f"Token bucket rate limit check failed for {key}: {e}")
            # Fail open - allow request but log error
            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=limit - 1,
                reset_time=int(current_time + window_seconds)
            )


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiting algorithm implementation.
    Provides more accurate rate limiting than fixed windows.
    """
    
    def __init__(self, redis_conn=None):
        self.redis_conn = redis_conn or get_redis_connection('rate_limit')
    
    def check_rate_limit(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        """
        Check rate limit using sliding window algorithm.
        
        Args:
            key: Unique identifier for rate limiting
            limit: Maximum requests per window
            window_seconds: Time window in seconds
            
        Returns:
            RateLimitResult object
        """
        current_time = time.time()
        window_key = CacheKeyManager.generate_key('rate_limit', 'sliding', key)
        
        try:
            # Use Lua script for atomic sliding window operations
            lua_script = """
            local window_key = KEYS[1]
            local limit = tonumber(ARGV[1])
            local window_seconds = tonumber(ARGV[2])
            local current_time = tonumber(ARGV[3])
            
            -- Remove expired entries
            local cutoff_time = current_time - window_seconds
            redis.call('ZREMRANGEBYSCORE', window_key, '-inf', cutoff_time)
            
            -- Count current requests in window
            local current_count = redis.call('ZCARD', window_key)
            
            local allowed = current_count < limit
            local remaining = math.max(0, limit - current_count)
            
            if allowed then
                -- Add current request to window
                redis.call('ZADD', window_key, current_time, current_time)
                remaining = remaining - 1
            end
            
            -- Set expiration
            redis.call('EXPIRE', window_key, window_seconds)
            
            -- Calculate reset time (when oldest entry expires)
            local oldest_entries = redis.call('ZRANGE', window_key, 0, 0, 'WITHSCORES')
            local reset_time = current_time + window_seconds
            if #oldest_entries > 0 then
                reset_time = oldest_entries[2] + window_seconds
            end
            
            return {allowed and 1 or 0, limit, remaining, math.floor(reset_time)}
            """
            
            result = self.redis_conn.eval(
                lua_script, 1, window_key,
                limit, window_seconds, current_time
            )
            
            allowed, rate_limit, remaining, reset_time = result
            retry_after = None
            
            if not allowed:
                retry_after = max(1, int(reset_time - current_time))
            
            return RateLimitResult(
                allowed=bool(allowed),
                limit=rate_limit,
                remaining=int(remaining),
                reset_time=int(reset_time),
                retry_after=retry_after
            )
            
        except Exception as e:
            logger.error(f"Sliding window rate limit check failed for {key}: {e}")
            # Fail open - allow request but log error
            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=limit - 1,
                reset_time=int(current_time + window_seconds)
            )


class ProgressiveRateLimiter:
    """
    Progressive rate limiting with exponential backoff for repeated violations.
    Increases penalties for persistent violators.
    """
    
    def __init__(self, redis_conn=None):
        self.redis_conn = redis_conn or get_redis_connection('rate_limit')
        self.base_limiter = SlidingWindowRateLimiter(redis_conn)
    
    def check_rate_limit(self, key: str, limit: int, window_seconds: int,
                        max_violations: int = 5) -> RateLimitResult:
        """
        Check rate limit with progressive penalties.
        
        Args:
            key: Unique identifier for rate limiting
            limit: Base limit per window
            window_seconds: Time window in seconds
            max_violations: Maximum violations before severe penalty
            
        Returns:
            RateLimitResult object
        """
        violations_key = CacheKeyManager.generate_key('rate_limit', 'violations', key)
        
        try:
            # Get current violation count
            violations = int(self.redis_conn.get(violations_key) or 0)
            
            # Calculate adjusted limit based on violations
            if violations > 0:
                # Reduce limit exponentially: limit / (2^violations)
                penalty_factor = min(2 ** violations, 16)  # Cap at 16x penalty
                adjusted_limit = max(1, limit // penalty_factor)
                adjusted_window = window_seconds * penalty_factor
            else:
                adjusted_limit = limit
                adjusted_window = window_seconds
            
            # Check rate limit with adjusted parameters
            result = self.base_limiter.check_rate_limit(key, adjusted_limit, adjusted_window)
            
            if not result.allowed:
                # Increment violation count
                self.redis_conn.incr(violations_key)
                self.redis_conn.expire(violations_key, window_seconds * 10)  # Keep violations for 10x window
                
                # Update retry_after with progressive delay
                if violations >= max_violations:
                    # Severe penalty for persistent violators
                    result.retry_after = window_seconds * (2 ** min(violations, 8))
                
                logger.warning(f"Rate limit violation for {key}: {violations + 1} violations")
            else:
                # Reset violations on successful request
                if violations > 0:
                    self.redis_conn.delete(violations_key)
            
            return result
            
        except Exception as e:
            logger.error(f"Progressive rate limit check failed for {key}: {e}")
            # Fallback to base limiter
            return self.base_limiter.check_rate_limit(key, limit, window_seconds)


class MultiLevelRateLimiter:
    """
    Multi-level rate limiting system supporting different scopes and algorithms.
    """
    
    def __init__(self):
        self.redis_conn = get_redis_connection('rate_limit')
        self.token_bucket = TokenBucketRateLimiter(self.redis_conn)
        self.sliding_window = SlidingWindowRateLimiter(self.redis_conn)
        self.progressive = ProgressiveRateLimiter(self.redis_conn)
        
        # Default rate limit configurations
        self.default_limits = {
            'ip': {'limit': 100, 'window': 3600, 'algorithm': 'sliding_window'},
            'user': {'limit': 1000, 'window': 3600, 'algorithm': 'token_bucket'},
            'endpoint': {'limit': 50, 'window': 60, 'algorithm': 'sliding_window'},
            'application': {'limit': 10000, 'window': 3600, 'algorithm': 'token_bucket'}
        }
    
    def check_multiple_limits(self, checks: List[Dict[str, Union[str, int]]]) -> List[RateLimitResult]:
        """
        Check multiple rate limits atomically.
        
        Args:
            checks: List of rate limit check configurations
            
        Returns:
            List of RateLimitResult objects
        """
        results = []
        
        for check in checks:
            scope = check.get('scope', 'ip')
            key = check['key']
            algorithm = check.get('algorithm', self.default_limits.get(scope, {}).get('algorithm', 'sliding_window'))
            limit = check.get('limit', self.default_limits.get(scope, {}).get('limit', 100))
            window = check.get('window', self.default_limits.get(scope, {}).get('window', 3600))
            
            # Generate scoped key
            scoped_key = f"{scope}:{key}"
            
            # Choose algorithm
            if algorithm == 'token_bucket':
                result = self.token_bucket.check_rate_limit(scoped_key, limit, window)
            elif algorithm == 'progressive':
                result = self.progressive.check_rate_limit(scoped_key, limit, window)
            else:  # sliding_window
                result = self.sliding_window.check_rate_limit(scoped_key, limit, window)
            
            results.append(result)
            
            # If any limit is exceeded, we can short-circuit
            if not result.allowed:
                break
        
        return results
    
    def check_ip_rate_limit(self, ip_address: str, endpoint: str = None) -> RateLimitResult:
        """
        Check IP-based rate limit.
        
        Args:
            ip_address: Client IP address
            endpoint: Optional endpoint-specific limiting
            
        Returns:
            RateLimitResult object
        """
        checks = [
            {
                'scope': 'ip',
                'key': ip_address,
                'algorithm': 'progressive'  # Use progressive for IP limiting
            }
        ]
        
        if endpoint:
            checks.append({
                'scope': 'endpoint',
                'key': f"{ip_address}:{endpoint}",
                'algorithm': 'sliding_window'
            })
        
        results = self.check_multiple_limits(checks)
        
        # Return the most restrictive result
        for result in results:
            if not result.allowed:
                return result
        
        return results[0] if results else RateLimitResult(True, 100, 99, int(time.time() + 3600))
    
    def check_user_rate_limit(self, user_id: str, endpoint: str = None) -> RateLimitResult:
        """
        Check user-based rate limit.
        
        Args:
            user_id: User identifier
            endpoint: Optional endpoint-specific limiting
            
        Returns:
            RateLimitResult object
        """
        checks = [
            {
                'scope': 'user',
                'key': user_id,
                'algorithm': 'token_bucket'
            }
        ]
        
        if endpoint:
            checks.append({
                'scope': 'endpoint',
                'key': f"user:{user_id}:{endpoint}",
                'algorithm': 'sliding_window',
                'limit': 20,  # More restrictive per-endpoint limit
                'window': 60
            })
        
        results = self.check_multiple_limits(checks)
        
        # Return the most restrictive result
        for result in results:
            if not result.allowed:
                return result
        
        return results[0] if results else RateLimitResult(True, 1000, 999, int(time.time() + 3600))
    
    def get_rate_limit_stats(self, scope: str, key: str) -> Dict[str, Union[int, float]]:
        """
        Get rate limiting statistics for a specific key.
        
        Args:
            scope: Rate limit scope (ip, user, endpoint, application)
            key: Identifier within scope
            
        Returns:
            Dictionary with rate limiting statistics
        """
        try:
            scoped_key = f"{scope}:{key}"
            
            # Get current window data
            window_key = CacheKeyManager.generate_key('rate_limit', 'sliding', scoped_key)
            bucket_key = CacheKeyManager.generate_key('rate_limit', 'bucket', scoped_key)
            violations_key = CacheKeyManager.generate_key('rate_limit', 'violations', scoped_key)
            
            current_time = time.time()
            
            # Sliding window stats
            window_count = self.redis_conn.zcard(window_key) or 0
            
            # Token bucket stats
            bucket_data = self.redis_conn.hmget(bucket_key, 'tokens', 'last_refill')
            tokens = float(bucket_data[0]) if bucket_data[0] else 0
            last_refill = float(bucket_data[1]) if bucket_data[1] else current_time
            
            # Violations
            violations = int(self.redis_conn.get(violations_key) or 0)
            
            return {
                'scope': scope,
                'key': key,
                'current_window_requests': window_count,
                'available_tokens': tokens,
                'last_refill_time': last_refill,
                'violations_count': violations,
                'timestamp': current_time
            }
            
        except Exception as e:
            logger.error(f"Failed to get rate limit stats for {scope}:{key}: {e}")
            return {}
    
    def reset_rate_limit(self, scope: str, key: str):
        """
        Reset rate limiting counters for a specific key.
        
        Args:
            scope: Rate limit scope
            key: Identifier within scope
        """
        try:
            scoped_key = f"{scope}:{key}"
            
            # Delete all rate limiting keys for this scope:key
            patterns = [
                CacheKeyManager.generate_key('rate_limit', 'sliding', scoped_key),
                CacheKeyManager.generate_key('rate_limit', 'bucket', scoped_key),
                CacheKeyManager.generate_key('rate_limit', 'violations', scoped_key)
            ]
            
            for pattern in patterns:
                self.redis_conn.delete(pattern)
            
            logger.info(f"Reset rate limits for {scope}:{key}")
            
        except Exception as e:
            logger.error(f"Failed to reset rate limits for {scope}:{key}: {e}")


# Global rate limiter instance
rate_limiter = MultiLevelRateLimiter()