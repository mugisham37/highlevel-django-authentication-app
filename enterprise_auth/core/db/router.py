"""
Database router for read/write splitting and query optimization.

This router implements intelligent database routing to:
- Direct write operations to the primary database
- Route read operations to read replicas when available
- Handle failover scenarios gracefully
- Optimize query performance through proper routing
"""

import logging
from django.conf import settings
from django.db import connections
from django.db.utils import ConnectionDoesNotExist

logger = logging.getLogger(__name__)


class DatabaseRouter:
    """
    A router to control all database operations on models for different
    databases, implementing read/write splitting for performance optimization.
    """

    # Models that should always use the primary database
    PRIMARY_ONLY_MODELS = {
        'sessions.session',
        'admin.logentry',
        'contenttypes.contenttype',
        'auth.permission',
        'auth.group',
        'auth.user',
        'users.userprofile',
        'users.useridentity',
        'auth.refreshtoken',
        'auth.tokenblacklist',
        'security.securityevent',
        'auth.mfadevice',
        'sessions.usersession',
    }

    # Apps that should always use the primary database
    PRIMARY_ONLY_APPS = {
        'admin',
        'auth',
        'contenttypes',
        'sessions',
        'users',
        'security',
    }

    def db_for_read(self, model, **hints):
        """
        Suggest the database to read from.
        
        Routes read operations to read replicas when available,
        falling back to primary database if replicas are unavailable.
        """
        model_name = f"{model._meta.app_label}.{model._meta.model_name}"
        
        # Always use primary for certain models
        if (model_name in self.PRIMARY_ONLY_MODELS or 
            model._meta.app_label in self.PRIMARY_ONLY_APPS):
            return 'default'
        
        # Check if we're in a transaction - if so, use primary to ensure consistency
        if self._in_transaction():
            return 'default'
        
        # Try to use read replica if available
        if self._has_read_replica():
            try:
                # Test connection to read replica
                connection = connections['read_replica']
                connection.ensure_connection()
                logger.debug(f"Routing read for {model_name} to read_replica")
                return 'read_replica'
            except (ConnectionDoesNotExist, Exception) as e:
                logger.warning(f"Read replica unavailable, falling back to primary: {e}")
                return 'default'
        
        return 'default'

    def db_for_write(self, model, **hints):
        """
        Suggest the database to write to.
        
        All write operations are directed to the primary database
        to ensure data consistency and avoid replication lag issues.
        """
        model_name = f"{model._meta.app_label}.{model._meta.model_name}"
        logger.debug(f"Routing write for {model_name} to default (primary)")
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if models are in the same database.
        
        This prevents cross-database relations which can cause
        performance issues and data consistency problems.
        """
        db_set = {'default'}
        if self._has_read_replica():
            db_set.add('read_replica')
        
        if obj1._state.db in db_set and obj2._state.db in db_set:
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Ensure that migrations only run on the primary database.
        
        Read replicas should not have migrations applied directly
        as they receive schema changes through replication.
        """
        if db == 'default':
            return True
        elif db == 'read_replica':
            # Never migrate on read replicas
            return False
        return None

    def _has_read_replica(self):
        """Check if read replica is configured."""
        return 'read_replica' in settings.DATABASES

    def _in_transaction(self):
        """
        Check if we're currently in a database transaction.
        
        During transactions, we should use the primary database
        to ensure consistency and avoid read-after-write issues.
        """
        try:
            from django.db import transaction
            return transaction.get_connection().in_atomic_block
        except Exception:
            return False


class ReadWriteRouter(DatabaseRouter):
    """
    Enhanced database router with additional read/write optimization features.
    
    This router extends the base DatabaseRouter with:
    - Query type detection for better routing decisions
    - Load balancing across multiple read replicas
    - Automatic failover handling
    - Performance monitoring and metrics
    """

    def __init__(self):
        super().__init__()
        self.read_replica_count = 0
        self.current_replica_index = 0
        self._initialize_replicas()

    def _initialize_replicas(self):
        """Initialize read replica configuration."""
        replica_configs = {}
        for db_name, config in settings.DATABASES.items():
            if db_name.startswith('read_replica'):
                replica_configs[db_name] = config
        
        self.read_replicas = list(replica_configs.keys())
        self.read_replica_count = len(self.read_replicas)
        logger.info(f"Initialized {self.read_replica_count} read replicas: {self.read_replicas}")

    def db_for_read(self, model, **hints):
        """
        Enhanced read routing with load balancing across multiple replicas.
        """
        model_name = f"{model._meta.app_label}.{model._meta.model_name}"
        
        # Always use primary for certain models
        if (model_name in self.PRIMARY_ONLY_MODELS or 
            model._meta.app_label in self.PRIMARY_ONLY_APPS):
            return 'default'
        
        # Check if we're in a transaction
        if self._in_transaction():
            return 'default'
        
        # Load balance across available read replicas
        if self.read_replica_count > 0:
            replica_db = self._get_next_replica()
            try:
                connection = connections[replica_db]
                connection.ensure_connection()
                logger.debug(f"Routing read for {model_name} to {replica_db}")
                return replica_db
            except Exception as e:
                logger.warning(f"Replica {replica_db} unavailable, trying next: {e}")
                # Try other replicas or fall back to primary
                return self._fallback_read_routing(model_name)
        
        return 'default'

    def _get_next_replica(self):
        """Get next read replica using round-robin load balancing."""
        if self.read_replica_count == 0:
            return 'default'
        
        replica = self.read_replicas[self.current_replica_index]
        self.current_replica_index = (self.current_replica_index + 1) % self.read_replica_count
        return replica

    def _fallback_read_routing(self, model_name):
        """Handle failover when primary replica is unavailable."""
        # Try other replicas
        for replica_db in self.read_replicas:
            try:
                connection = connections[replica_db]
                connection.ensure_connection()
                logger.info(f"Failover: routing read for {model_name} to {replica_db}")
                return replica_db
            except Exception as e:
                logger.warning(f"Replica {replica_db} also unavailable: {e}")
                continue
        
        # All replicas failed, use primary
        logger.warning(f"All replicas unavailable, using primary for {model_name}")
        return 'default'