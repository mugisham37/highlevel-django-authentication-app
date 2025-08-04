"""
Enhanced Redis-based session storage with proper serialization and security features.
Provides advanced session management capabilities for the enterprise authentication system.
"""

import logging
import json
import pickle
import time
import hashlib
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta
from django.contrib.sessions.backends.base import SessionBase
from django.core.exceptions import SuspiciousOperation
from django.conf import settings
from .redis_config import get_redis_connection
from .cache_manager import CacheKeyManager
import uuid

logger = logging.getLogger(__name__)


class SecureSessionSerializer:
    """
    Secure session data serializer with encryption and integrity checking.
    """
    
    def __init__(self):
        self.secret_key = getattr(settings, 'SECRET_KEY', '')
    
    def serialize(self, session_data: Dict[str, Any]) -> bytes:
        """
        Serialize session data with integrity protection.
        
        Args:
            session_data: Session data dictionary
            
        Returns:
            Serialized and signed session data
        """
        try:
            # Add metadata
            session_data['_serialized_at'] = time.time()
            session_data['_version'] = '1.0'
            
            # Serialize to JSON first (more secure than pickle)
            json_data = json.dumps(session_data, default=str, sort_keys=True)
            
            # Create integrity hash
            integrity_hash = hashlib.sha256(
                (json_data + self.secret_key).encode()
            ).hexdigest()
            
            # Combine data and hash
            final_data = {
                'data': json_data,
                'integrity_hash': integrity_hash
            }
            
            return json.dumps(final_data).encode()
            
        except Exception as e:
            logger.error(f"Session serialization failed: {e}")
            raise
    
    def deserialize(self, serialized_data: bytes) -> Dict[str, Any]:
        """
        Deserialize and verify session data integrity.
        
        Args:
            serialized_data: Serialized session data
            
        Returns:
            Deserialized session data dictionary
        """
        try:
            # Parse outer structure
            final_data = json.loads(serialized_data.decode())
            json_data = final_data['data']
            stored_hash = final_data['integrity_hash']
            
            # Verify integrity
            expected_hash = hashlib.sha256(
                (json_data + self.secret_key).encode()
            ).hexdigest()
            
            if stored_hash != expected_hash:
                raise SuspiciousOperation("Session data integrity check failed")
            
            # Deserialize actual data
            session_data = json.loads(json_data)
            
            # Remove metadata
            session_data.pop('_serialized_at', None)
            session_data.pop('_version', None)
            
            return session_data
            
        except Exception as e:
            logger.error(f"Session deserialization failed: {e}")
            raise


class RedisSessionStore(SessionBase):
    """
    Redis-based session store with enhanced security and performance features.
    """
    
    def __init__(self, session_key=None):
        super().__init__(session_key)
        self.redis_conn = get_redis_connection('sessions')
        self.serializer = SecureSessionSerializer()
        self.key_prefix = getattr(settings, 'SESSION_REDIS_PREFIX', 'session')
        self.default_timeout = getattr(settings, 'SESSION_COOKIE_AGE', 3600)
    
    def _get_session_key(self, session_key: str = None) -> str:
        """
        Generate Redis key for session storage.
        
        Args:
            session_key: Session key (uses self.session_key if None)
            
        Returns:
            Redis key for session
        """
        key = session_key or self.session_key
        if not key:
            raise ValueError("Session key is required")
        
        return CacheKeyManager.generate_key('session', 'data', key)
    
    def _get_metadata_key(self, session_key: str = None) -> str:
        """
        Generate Redis key for session metadata.
        
        Args:
            session_key: Session key (uses self.session_key if None)
            
        Returns:
            Redis key for session metadata
        """
        key = session_key or self.session_key
        if not key:
            raise ValueError("Session key is required")
        
        return CacheKeyManager.generate_key('session', 'meta', key)
    
    def load(self) -> Dict[str, Any]:
        """
        Load session data from Redis.
        
        Returns:
            Session data dictionary
        """
        try:
            if not self.session_key:
                self._session_key = self._get_new_session_key()
                self._session_cache = {}
                return self._session_cache
            
            session_key = self._get_session_key()
            serialized_data = self.redis_conn.get(session_key)
            
            if serialized_data is None:
                # Session doesn't exist, create new one
                self._session_key = self._get_new_session_key()
                self._session_cache = {}
                return self._session_cache
            
            # Deserialize session data
            session_data = self.serializer.deserialize(serialized_data)
            
            # Update last accessed time
            self._update_session_metadata()
            
            return session_data
            
        except Exception as e:
            logger.error(f"Failed to load session {self.session_key}: {e}")
            # Create new session on load failure
            self._session_key = self._get_new_session_key()
            self._session_cache = {}
            return self._session_cache
    
    def exists(self, session_key: str) -> bool:
        """
        Check if session exists in Redis.
        
        Args:
            session_key: Session key to check
            
        Returns:
            True if session exists, False otherwise
        """
        try:
            redis_key = self._get_session_key(session_key)
            return bool(self.redis_conn.exists(redis_key))
        except Exception as e:
            logger.error(f"Failed to check session existence {session_key}: {e}")
            return False
    
    def create(self) -> None:
        """Create a new session."""
        while True:
            self._session_key = self._get_new_session_key()
            try:
                self.save(must_create=True)
                self.modified = True
                return
            except Exception:
                # Key collision, try again
                continue
    
    def save(self, must_create: bool = False) -> None:
        """
        Save session data to Redis.
        
        Args:
            must_create: If True, session must not already exist
        """
        try:
            if not self.session_key:
                raise ValueError("Session key is required for save")
            
            session_key = self._get_session_key()
            metadata_key = self._get_metadata_key()
            
            # Check if session must be created
            if must_create and self.redis_conn.exists(session_key):
                raise Exception("Session already exists")
            
            # Serialize session data
            serialized_data = self.serializer.serialize(self._get_session(no_load=True))
            
            # Prepare session metadata
            metadata = {
                'created_at': time.time(),
                'last_accessed': time.time(),
                'user_agent': getattr(self, '_user_agent', ''),
                'ip_address': getattr(self, '_ip_address', ''),
                'user_id': self.get('_auth_user_id', ''),
                'is_authenticated': bool(self.get('_auth_user_id')),
                'session_version': '1.0'
            }
            
            # Use pipeline for atomic operations
            pipe = self.redis_conn.pipeline()
            
            # Set session data with expiration
            pipe.setex(session_key, self.get_expiry_age(), serialized_data)
            
            # Set metadata with same expiration
            pipe.setex(metadata_key, self.get_expiry_age(), json.dumps(metadata))
            
            # Execute pipeline
            pipe.execute()
            
            logger.debug(f"Saved session {self.session_key}")
            
        except Exception as e:
            logger.error(f"Failed to save session {self.session_key}: {e}")
            raise
    
    def delete(self, session_key: str = None) -> None:
        """
        Delete session from Redis.
        
        Args:
            session_key: Session key to delete (uses self.session_key if None)
        """
        try:
            key = session_key or self.session_key
            if not key:
                return
            
            redis_key = self._get_session_key(key)
            metadata_key = self._get_metadata_key(key)
            
            # Delete both session data and metadata
            pipe = self.redis_conn.pipeline()
            pipe.delete(redis_key)
            pipe.delete(metadata_key)
            pipe.execute()
            
            logger.debug(f"Deleted session {key}")
            
        except Exception as e:
            logger.error(f"Failed to delete session {session_key or self.session_key}: {e}")
    
    def _get_new_session_key(self) -> str:
        """
        Generate a new session key.
        
        Returns:
            New session key
        """
        return uuid.uuid4().hex
    
    def _update_session_metadata(self):
        """Update session metadata with current access time."""
        try:
            if not self.session_key:
                return
            
            metadata_key = self._get_metadata_key()
            
            # Get existing metadata
            existing_metadata = self.redis_conn.get(metadata_key)
            if existing_metadata:
                metadata = json.loads(existing_metadata)
            else:
                metadata = {}
            
            # Update last accessed time
            metadata['last_accessed'] = time.time()
            
            # Update metadata in Redis
            self.redis_conn.setex(
                metadata_key, 
                self.get_expiry_age(), 
                json.dumps(metadata)
            )
            
        except Exception as e:
            logger.error(f"Failed to update session metadata {self.session_key}: {e}")
    
    def get_session_metadata(self, session_key: str = None) -> Dict[str, Any]:
        """
        Get session metadata.
        
        Args:
            session_key: Session key (uses self.session_key if None)
            
        Returns:
            Session metadata dictionary
        """
        try:
            key = session_key or self.session_key
            if not key:
                return {}
            
            metadata_key = self._get_metadata_key(key)
            metadata_json = self.redis_conn.get(metadata_key)
            
            if metadata_json:
                return json.loads(metadata_json)
            
            return {}
            
        except Exception as e:
            logger.error(f"Failed to get session metadata {session_key or self.session_key}: {e}")
            return {}
    
    def set_session_context(self, user_agent: str = None, ip_address: str = None):
        """
        Set session context information.
        
        Args:
            user_agent: User agent string
            ip_address: Client IP address
        """
        if user_agent:
            self._user_agent = user_agent
        if ip_address:
            self._ip_address = ip_address


class SessionManager:
    """
    High-level session management with advanced features.
    """
    
    def __init__(self):
        self.redis_conn = get_redis_connection('sessions')
        self.serializer = SecureSessionSerializer()
    
    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of session information dictionaries
        """
        try:
            # Search for sessions by user_id pattern
            pattern = CacheKeyManager.generate_key('session', 'meta', '*')
            session_keys = self.redis_conn.keys(pattern)
            
            user_sessions = []
            
            for key in session_keys:
                try:
                    metadata_json = self.redis_conn.get(key)
                    if metadata_json:
                        metadata = json.loads(metadata_json)
                        if metadata.get('user_id') == user_id:
                            # Extract session key from Redis key
                            session_key = key.split(':')[-1]
                            
                            session_info = {
                                'session_key': session_key,
                                'created_at': metadata.get('created_at'),
                                'last_accessed': metadata.get('last_accessed'),
                                'user_agent': metadata.get('user_agent', ''),
                                'ip_address': metadata.get('ip_address', ''),
                                'is_current': False  # Will be set by caller if needed
                            }
                            user_sessions.append(session_info)
                            
                except Exception as e:
                    logger.error(f"Error processing session key {key}: {e}")
                    continue
            
            # Sort by last accessed time (most recent first)
            user_sessions.sort(key=lambda x: x.get('last_accessed', 0), reverse=True)
            
            return user_sessions
            
        except Exception as e:
            logger.error(f"Failed to get user sessions for {user_id}: {e}")
            return []
    
    def terminate_user_sessions(self, user_id: str, exclude_session: str = None) -> int:
        """
        Terminate all sessions for a user.
        
        Args:
            user_id: User identifier
            exclude_session: Session key to exclude from termination
            
        Returns:
            Number of sessions terminated
        """
        try:
            user_sessions = self.get_user_sessions(user_id)
            terminated_count = 0
            
            for session_info in user_sessions:
                session_key = session_info['session_key']
                
                if exclude_session and session_key == exclude_session:
                    continue
                
                try:
                    # Delete session data and metadata
                    data_key = CacheKeyManager.generate_key('session', 'data', session_key)
                    meta_key = CacheKeyManager.generate_key('session', 'meta', session_key)
                    
                    pipe = self.redis_conn.pipeline()
                    pipe.delete(data_key)
                    pipe.delete(meta_key)
                    pipe.execute()
                    
                    terminated_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to terminate session {session_key}: {e}")
            
            logger.info(f"Terminated {terminated_count} sessions for user {user_id}")
            return terminated_count
            
        except Exception as e:
            logger.error(f"Failed to terminate user sessions for {user_id}: {e}")
            return 0
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from Redis.
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            # Get all session keys
            data_pattern = CacheKeyManager.generate_key('session', 'data', '*')
            meta_pattern = CacheKeyManager.generate_key('session', 'meta', '*')
            
            data_keys = self.redis_conn.keys(data_pattern)
            meta_keys = self.redis_conn.keys(meta_pattern)
            
            cleaned_count = 0
            
            # Check each session for expiration
            for key in data_keys:
                try:
                    ttl = self.redis_conn.ttl(key)
                    if ttl == -2:  # Key doesn't exist
                        cleaned_count += 1
                    elif ttl == -1:  # Key exists but has no expiration
                        # Set default expiration
                        self.redis_conn.expire(key, 3600)
                        
                except Exception as e:
                    logger.error(f"Error checking session key {key}: {e}")
            
            # Clean up orphaned metadata keys
            for key in meta_keys:
                try:
                    session_key = key.split(':')[-1]
                    data_key = CacheKeyManager.generate_key('session', 'data', session_key)
                    
                    if not self.redis_conn.exists(data_key):
                        self.redis_conn.delete(key)
                        cleaned_count += 1
                        
                except Exception as e:
                    logger.error(f"Error cleaning metadata key {key}: {e}")
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired sessions")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")
            return 0
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get session storage statistics.
        
        Returns:
            Dictionary with session statistics
        """
        try:
            data_pattern = CacheKeyManager.generate_key('session', 'data', '*')
            meta_pattern = CacheKeyManager.generate_key('session', 'meta', '*')
            
            data_keys = self.redis_conn.keys(data_pattern)
            meta_keys = self.redis_conn.keys(meta_pattern)
            
            # Count authenticated vs anonymous sessions
            authenticated_count = 0
            anonymous_count = 0
            
            for key in meta_keys:
                try:
                    metadata_json = self.redis_conn.get(key)
                    if metadata_json:
                        metadata = json.loads(metadata_json)
                        if metadata.get('is_authenticated', False):
                            authenticated_count += 1
                        else:
                            anonymous_count += 1
                except Exception:
                    continue
            
            return {
                'total_sessions': len(data_keys),
                'authenticated_sessions': authenticated_count,
                'anonymous_sessions': anonymous_count,
                'metadata_keys': len(meta_keys),
                'orphaned_metadata': len(meta_keys) - len(data_keys),
                'timestamp': time.time()
            }
            
        except Exception as e:
            logger.error(f"Failed to get session stats: {e}")
            return {}


# Global session manager instance
session_manager = SessionManager()