"""
Redis configuration and connection management for enterprise authentication system.
Provides high availability Redis cluster configuration with proper connection pooling,
failover handling, and performance optimization.
"""

import logging
import redis
from redis.sentinel import Sentinel
from redis.exceptions import ConnectionError, TimeoutError
from django.conf import settings
from django.core.cache import cache
from decouple import config
from typing import Dict, List, Optional, Any, Union
import json
import time

logger = logging.getLogger(__name__)


class RedisClusterConfig:
    """
    Redis cluster configuration for high availability setup.
    Supports both Redis Cluster and Redis Sentinel configurations.
    """
    
    def __init__(self):
        self.cluster_enabled = config('REDIS_CLUSTER_ENABLED', default=False, cast=bool)
        self.sentinel_enabled = config('REDIS_SENTINEL_ENABLED', default=False, cast=bool)
        self.cluster_nodes = self._parse_cluster_nodes()
        self.sentinel_hosts = self._parse_sentinel_hosts()
        self.master_name = config('REDIS_MASTER_NAME', default='mymaster')
        
    def _parse_cluster_nodes(self) -> List[Dict[str, Union[str, int]]]:
        """Parse Redis cluster nodes from environment configuration."""
        nodes_config = config('REDIS_CLUSTER_NODES', default='')
        if not nodes_config:
            return []
            
        nodes = []
        for node in nodes_config.split(','):
            if ':' in node:
                host, port = node.strip().split(':')
                nodes.append({'host': host, 'port': int(port)})
        return nodes
    
    def _parse_sentinel_hosts(self) -> List[tuple]:
        """Parse Redis Sentinel hosts from environment configuration."""
        sentinel_config = config('REDIS_SENTINEL_HOSTS', default='')
        if not sentinel_config:
            return []
            
        hosts = []
        for host_port in sentinel_config.split(','):
            if ':' in host_port:
                host, port = host_port.strip().split(':')
                hosts.append((host, int(port)))
        return hosts
    
    def get_redis_connection(self, db: int = 0) -> redis.Redis:
        """
        Get Redis connection based on configuration (cluster, sentinel, or standalone).
        
        Args:
            db: Database number for standalone Redis
            
        Returns:
            Redis connection instance
        """
        if self.cluster_enabled and self.cluster_nodes:
            return self._get_cluster_connection()
        elif self.sentinel_enabled and self.sentinel_hosts:
            return self._get_sentinel_connection(db)
        else:
            return self._get_standalone_connection(db)
    
    def _get_cluster_connection(self) -> redis.RedisCluster:
        """Get Redis Cluster connection."""
        try:
            from rediscluster import RedisCluster
            
            return RedisCluster(
                startup_nodes=self.cluster_nodes,
                decode_responses=True,
                skip_full_coverage_check=True,
                health_check_interval=30,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                max_connections=100,
                max_connections_per_node=20
            )
        except ImportError:
            logger.error("redis-py-cluster not installed. Install with: pip install redis-py-cluster")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to Redis cluster: {e}")
            raise
    
    def _get_sentinel_connection(self, db: int = 0) -> redis.Redis:
        """Get Redis connection through Sentinel for high availability."""
        try:
            sentinel = Sentinel(
                self.sentinel_hosts,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True
            )
            
            # Get master connection for writes
            master = sentinel.master_for(
                self.master_name,
                socket_timeout=5,
                socket_connect_timeout=5,
                db=db,
                decode_responses=True,
                max_connections=50,
                retry_on_timeout=True
            )
            
            return master
        except Exception as e:
            logger.error(f"Failed to connect to Redis via Sentinel: {e}")
            raise
    
    def _get_standalone_connection(self, db: int = 0) -> redis.Redis:
        """Get standalone Redis connection."""
        redis_url = config('REDIS_URL', default='redis://localhost:6379/0')
        
        try:
            return redis.from_url(
                redis_url,
                db=db,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                max_connections=50,
                health_check_interval=30
            )
        except Exception as e:
            logger.error(f"Failed to connect to standalone Redis: {e}")
            raise


class RedisConnectionManager:
    """
    Manages Redis connections for different purposes with connection pooling
    and automatic failover handling.
    """
    
    def __init__(self):
        self.config = RedisClusterConfig()
        self._connections = {}
        self._connection_pools = {}
    
    def get_connection(self, purpose: str = 'default', db: int = 0) -> redis.Redis:
        """
        Get Redis connection for specific purpose with connection pooling.
        
        Args:
            purpose: Connection purpose (default, sessions, rate_limit, cache)
            db: Database number (ignored for cluster mode)
            
        Returns:
            Redis connection instance
        """
        connection_key = f"{purpose}_{db}"
        
        if connection_key not in self._connections:
            try:
                self._connections[connection_key] = self.config.get_redis_connection(db)
                logger.info(f"Created Redis connection for {purpose} (db: {db})")
            except Exception as e:
                logger.error(f"Failed to create Redis connection for {purpose}: {e}")
                raise
        
        return self._connections[connection_key]
    
    def health_check(self) -> Dict[str, bool]:
        """
        Perform health check on all Redis connections.
        
        Returns:
            Dictionary with connection status for each purpose
        """
        health_status = {}
        
        for connection_key, connection in self._connections.items():
            try:
                connection.ping()
                health_status[connection_key] = True
                logger.debug(f"Redis connection {connection_key} is healthy")
            except Exception as e:
                health_status[connection_key] = False
                logger.error(f"Redis connection {connection_key} failed health check: {e}")
        
        return health_status
    
    def close_connections(self):
        """Close all Redis connections."""
        for connection_key, connection in self._connections.items():
            try:
                connection.close()
                logger.info(f"Closed Redis connection: {connection_key}")
            except Exception as e:
                logger.error(f"Error closing Redis connection {connection_key}: {e}")
        
        self._connections.clear()


# Global connection manager instance
redis_manager = RedisConnectionManager()


def get_redis_connection(purpose: str = 'default', db: int = 0) -> redis.Redis:
    """
    Get Redis connection for specific purpose.
    
    Args:
        purpose: Connection purpose (default, sessions, rate_limit, cache)
        db: Database number
        
    Returns:
        Redis connection instance
    """
    return redis_manager.get_connection(purpose, db)


def redis_health_check() -> Dict[str, Any]:
    """
    Comprehensive Redis health check.
    
    Returns:
        Health check results with connection status and performance metrics
    """
    start_time = time.time()
    
    try:
        # Test basic connection
        redis_conn = get_redis_connection('default')
        
        # Test basic operations
        test_key = 'health_check_test'
        redis_conn.set(test_key, 'test_value', ex=10)
        retrieved_value = redis_conn.get(test_key)
        redis_conn.delete(test_key)
        
        # Get Redis info
        redis_info = redis_conn.info()
        
        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        return {
            'status': 'healthy',
            'response_time_ms': round(response_time, 2),
            'redis_version': redis_info.get('redis_version'),
            'connected_clients': redis_info.get('connected_clients'),
            'used_memory_human': redis_info.get('used_memory_human'),
            'keyspace_hits': redis_info.get('keyspace_hits', 0),
            'keyspace_misses': redis_info.get('keyspace_misses', 0),
            'connections': redis_manager.health_check()
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e),
            'response_time_ms': (time.time() - start_time) * 1000
        }