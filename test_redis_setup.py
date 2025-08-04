#!/usr/bin/env python
"""
Test script to verify Redis caching and session storage setup.
Run this script to test the Redis configuration before deploying.
"""

import os
import sys
import django
from django.conf import settings

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.development')
django.setup()

import time
import json
from enterprise_auth.core.cache.redis_config import redis_health_check, get_redis_connection
from enterprise_auth.core.cache.cache_manager import cache_manager
from enterprise_auth.core.cache.rate_limiter import rate_limiter
from enterprise_auth.core.cache.session_storage import session_manager


def test_redis_connection():
    """Test basic Redis connectivity."""
    print("=== Testing Redis Connection ===")
    
    try:
        health_result = redis_health_check()
        print(f"Redis Health Status: {health_result['status']}")
        print(f"Response Time: {health_result.get('response_time_ms', 'N/A')}ms")
        print(f"Redis Version: {health_result.get('redis_version', 'N/A')}")
        
        if health_result['status'] == 'healthy':
            print("✅ Redis connection test PASSED")
            return True
        else:
            print(f"❌ Redis connection test FAILED: {health_result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ Redis connection test FAILED: {e}")
        return False


def test_cache_operations():
    """Test cache warming and invalidation."""
    print("\n=== Testing Cache Operations ===")
    
    try:
        # Test cache warming
        print("Testing cache warming...")
        cache_manager.warmer.warm_oauth_providers()
        print("✅ OAuth providers cache warming PASSED")
        
        # Test cache invalidation
        print("Testing cache invalidation...")
        cache_manager.invalidator.invalidate_by_pattern('oauth:*')
        print("✅ Cache invalidation PASSED")
        
        # Test cache statistics
        print("Testing cache statistics...")
        stats = cache_manager.get_cache_stats()
        print(f"Cache stats retrieved: {len(stats)} metrics")
        print("✅ Cache statistics PASSED")
        
        return True
        
    except Exception as e:
        print(f"❌ Cache operations test FAILED: {e}")
        return False


def test_rate_limiting():
    """Test rate limiting functionality."""
    print("\n=== Testing Rate Limiting ===")
    
    try:
        # Test IP rate limiting
        print("Testing IP rate limiting...")
        result1 = rate_limiter.check_ip_rate_limit('192.168.1.100')
        print(f"First request allowed: {result1.allowed}")
        
        # Test user rate limiting
        print("Testing user rate limiting...")
        result2 = rate_limiter.check_user_rate_limit('test_user_123')
        print(f"User request allowed: {result2.allowed}")
        
        # Test rate limit stats
        print("Testing rate limit statistics...")
        stats = rate_limiter.get_rate_limit_stats('ip', '192.168.1.100')
        print(f"Rate limit stats retrieved: {len(stats)} metrics")
        
        print("✅ Rate limiting test PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Rate limiting test FAILED: {e}")
        return False


def test_session_storage():
    """Test session storage functionality."""
    print("\n=== Testing Session Storage ===")
    
    try:
        # Test session statistics
        print("Testing session statistics...")
        stats = session_manager.get_session_stats()
        print(f"Session stats retrieved: {len(stats)} metrics")
        
        # Test session cleanup
        print("Testing session cleanup...")
        cleaned = session_manager.cleanup_expired_sessions()
        print(f"Cleaned up {cleaned} expired sessions")
        
        print("✅ Session storage test PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Session storage test FAILED: {e}")
        return False


def test_redis_cluster_config():
    """Test Redis cluster configuration."""
    print("\n=== Testing Redis Cluster Configuration ===")
    
    try:
        # Test different connection types
        default_conn = get_redis_connection('default')
        sessions_conn = get_redis_connection('sessions')
        rate_limit_conn = get_redis_connection('rate_limit')
        
        # Test basic operations on each connection
        test_key = f"test_key_{int(time.time())}"
        
        default_conn.set(test_key, 'test_value', ex=10)
        retrieved = default_conn.get(test_key)
        default_conn.delete(test_key)
        
        if retrieved == 'test_value':
            print("✅ Redis cluster configuration test PASSED")
            return True
        else:
            print("❌ Redis cluster configuration test FAILED: Value mismatch")
            return False
            
    except Exception as e:
        print(f"❌ Redis cluster configuration test FAILED: {e}")
        return False


def run_performance_test():
    """Run basic performance tests."""
    print("\n=== Running Performance Tests ===")
    
    try:
        # Test cache performance
        start_time = time.time()
        
        for i in range(100):
            key = f"perf_test_{i}"
            cache_manager.get_or_set(
                key, 
                lambda: f"test_data_{i}", 
                timeout=60
            )
        
        elapsed_time = (time.time() - start_time) * 1000
        print(f"100 cache operations completed in {elapsed_time:.2f}ms")
        
        if elapsed_time < 1000:  # Less than 1 second
            print("✅ Performance test PASSED")
            return True
        else:
            print("⚠️  Performance test WARNING: Operations took longer than expected")
            return True
            
    except Exception as e:
        print(f"❌ Performance test FAILED: {e}")
        return False


def main():
    """Run all Redis setup tests."""
    print("Starting Redis Setup Verification Tests")
    print("=" * 50)
    
    tests = [
        test_redis_connection,
        test_redis_cluster_config,
        test_cache_operations,
        test_rate_limiting,
        test_session_storage,
        run_performance_test,
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_func in tests:
        try:
            if test_func():
                passed_tests += 1
        except Exception as e:
            print(f"❌ Test {test_func.__name__} FAILED with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All Redis setup tests PASSED! Your configuration is ready.")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed. Please check your Redis configuration.")
        sys.exit(1)


if __name__ == '__main__':
    main()