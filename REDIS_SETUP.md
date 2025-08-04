# Redis Caching and Session Storage Setup

This document explains the Redis caching and session storage implementation for the enterprise authentication backend.

## Overview

The Redis setup provides:

1. **High Availability Redis Cluster Configuration** - Supports Redis Cluster and Sentinel modes
2. **Enhanced Session Storage** - Secure session storage with proper serialization
3. **Cache Warming and Invalidation Strategies** - Intelligent caching patterns
4. **Rate Limiting Counters** - Multi-level rate limiting with Redis backing

## Configuration

### Environment Variables

Add these variables to your `.env` file:

```bash
# Basic Redis Configuration
REDIS_URL=redis://localhost:6379/1
REDIS_SESSION_URL=redis://localhost:6379/2
REDIS_RATE_LIMIT_URL=redis://localhost:6379/3
REDIS_CACHE_WARMING_URL=redis://localhost:6379/4

# Redis Cluster Configuration (optional)
REDIS_CLUSTER_ENABLED=False
REDIS_CLUSTER_NODES=host1:6379,host2:6379,host3:6379
REDIS_SENTINEL_ENABLED=False
REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379,sentinel3:26379
REDIS_MASTER_NAME=mymaster

# Redis Connection Settings
REDIS_CONNECTION_POOL_SIZE=100
REDIS_CONNECTION_TIMEOUT=5
REDIS_HEALTH_CHECK_INTERVAL=30
```

### Django Settings

The Redis configuration is automatically loaded in `settings/base.py` with:

- Multiple Redis databases for different purposes
- Connection pooling and retry logic
- Graceful fallback on Redis failures
- Enhanced session storage with security features

## Features

### 1. Redis Cluster Support

```python
from enterprise_auth.core.cache.redis_config import get_redis_connection

# Get connection for specific purpose
redis_conn = get_redis_connection('cache')  # or 'sessions', 'rate_limit'
```

### 2. Cache Management

```python
from enterprise_auth.core.cache.cache_manager import cache_manager

# Cache warming
cache_manager.warmer.warm_user_data(['user1', 'user2'])
cache_manager.warmer.warm_oauth_providers()

# Cache invalidation
cache_manager.invalidator.invalidate_user_cache('user123')
cache_manager.invalidator.invalidate_by_pattern('oauth:*')

# Smart caching
value = cache_manager.get_or_set('key', lambda: expensive_operation(), timeout=300)
```

### 3. Rate Limiting

```python
from enterprise_auth.core.cache.rate_limiter import rate_limiter

# Check IP rate limit
result = rate_limiter.check_ip_rate_limit('192.168.1.100')
if not result.allowed:
    return HttpResponse('Rate limited', status=429)

# Check user rate limit
result = rate_limiter.check_user_rate_limit('user123', endpoint='login')
```

### 4. Session Management

```python
from enterprise_auth.core.cache.session_storage import session_manager

# Get user sessions
sessions = session_manager.get_user_sessions('user123')

# Terminate user sessions
terminated = session_manager.terminate_user_sessions('user123', exclude_session='current_session')

# Cleanup expired sessions
cleaned = session_manager.cleanup_expired_sessions()
```

## Management Commands

### Cache Management

```bash
# Warm cache
python manage.py cache_management warm --scope user --key user123
python manage.py cache_management warm --scope oauth
python manage.py cache_management warm  # Warm all

# Invalidate cache
python manage.py cache_management invalidate --scope user --key user123
python manage.py cache_management invalidate --pattern "oauth:*"

# Get statistics
python manage.py cache_management stats
python manage.py cache_management stats --scope ip --key 192.168.1.100

# Health check
python manage.py cache_management health

# Cleanup
python manage.py cache_management cleanup
python manage.py cache_management session_cleanup --key user123

# Reset rate limits
python manage.py cache_management reset_rate_limits --scope ip --key 192.168.1.100
```

## Health Check Endpoints

### Redis Health

```
GET /api/v1/core/health/redis/
```

### Cache Statistics

```
GET /api/v1/core/health/cache/
```

### System Health

```
GET /api/v1/core/health/system/
```

## Celery Tasks

Automatic background tasks are configured for:

- **Cache Warming**: Every 30 minutes for users, hourly for OAuth/roles
- **Session Cleanup**: Every hour
- **Rate Limit Cleanup**: Every 2 hours
- **Comprehensive Warming**: Every 6 hours

### Manual Task Execution

```python
from enterprise_auth.core.tasks.cache_tasks import *

# Warm user cache
warm_user_cache.delay(['user1', 'user2'])

# Cleanup sessions
cleanup_expired_sessions.delay()

# Invalidate user cache
invalidate_user_cache.delay('user123')
```

## Testing

Run the Redis setup verification:

```bash
python test_redis_setup.py
```

This will test:

- Redis connectivity
- Cache operations
- Rate limiting
- Session storage
- Performance benchmarks

## Production Deployment

### Redis Cluster Setup

1. **Configure Redis Cluster**:

   ```bash
   REDIS_CLUSTER_ENABLED=True
   REDIS_CLUSTER_NODES=redis1:6379,redis2:6379,redis3:6379
   ```

2. **Configure Redis Sentinel** (alternative):
   ```bash
   REDIS_SENTINEL_ENABLED=True
   REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379
   REDIS_MASTER_NAME=mymaster
   ```

### Monitoring

- Use the health check endpoints for monitoring
- Set up alerts for Redis connection failures
- Monitor cache hit rates and performance metrics
- Track session storage usage

### Security

- Use Redis AUTH for authentication
- Enable TLS for Redis connections in production
- Restrict Redis network access
- Regular security updates for Redis

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure Redis is running and accessible
2. **Memory Issues**: Monitor Redis memory usage and configure maxmemory
3. **Performance**: Check connection pool settings and network latency
4. **Cluster Issues**: Verify cluster node configuration and health

### Debug Commands

```bash
# Check Redis connectivity
redis-cli ping

# Monitor Redis operations
redis-cli monitor

# Check memory usage
redis-cli info memory

# List all keys (development only)
redis-cli keys "*"
```

## Performance Optimization

### Connection Pooling

- Configured with max_connections=100 for default cache
- Health checks every 30 seconds
- Automatic retry on timeout

### Cache Strategies

- Multi-layer caching (application + Redis)
- Intelligent cache warming based on usage patterns
- Efficient invalidation with pattern matching

### Session Optimization

- Secure serialization with integrity checking
- Metadata separation for efficient queries
- Automatic cleanup of expired sessions

This Redis setup provides enterprise-grade caching and session management with high availability, security, and performance optimization.
