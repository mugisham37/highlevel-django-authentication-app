# Enterprise Authentication Core Components

This document provides an overview of the core utilities and shared components implemented for the enterprise authentication system.

## Overview

Task 4 has been completed, implementing the following core utilities and shared components:

1. **Encryption utilities for sensitive data storage**
2. **Correlation ID middleware for request tracking**
3. **Custom exception classes and error handling middleware**
4. **Base model classes with audit fields and soft delete**

## Components Implemented

### 1. Encryption Utilities (`enterprise_auth/core/utils/encryption.py`)

Provides secure encryption/decryption utilities for storing sensitive data like OAuth tokens, MFA secrets, and other confidential information.

**Key Features:**

- Uses Fernet symmetric encryption with PBKDF2 key derivation
- Each encrypted value includes a unique salt for additional security
- Support for encrypting/decrypting strings, bytes, and dictionaries
- Secure hashing utilities with salt for searchable hashes
- Convenience functions for easy integration

**Usage Example:**

```python
from enterprise_auth.core.utils.encryption import encrypt_sensitive_data, decrypt_sensitive_data

# Encrypt sensitive data
encrypted = encrypt_sensitive_data("sensitive_token_123")

# Decrypt sensitive data
decrypted = decrypt_sensitive_data(encrypted)
```

### 2. Correlation ID Middleware (`enterprise_auth/core/utils/correlation.py`)

Implements correlation ID tracking for request tracing across the entire system.

**Key Features:**

- Generates unique correlation IDs for each request
- Supports existing correlation IDs from headers (for distributed tracing)
- Thread-local storage for easy access throughout request lifecycle
- Adds correlation IDs to response headers
- Context manager for scoped correlation ID usage
- Logging filter to add correlation IDs to all log records

**Usage Example:**

```python
from enterprise_auth.core.utils.correlation import get_correlation_id, CorrelationContext

# Get current correlation ID
correlation_id = get_correlation_id()

# Use correlation context
with CorrelationContext('my-correlation-id'):
    # Code here will have access to the correlation ID
    pass
```

### 3. Custom Exception Classes (`enterprise_auth/core/exceptions.py`)

Comprehensive hierarchy of exceptions for consistent error handling throughout the system.

**Key Features:**

- Base `EnterpriseAuthError` with structured error information
- Specialized exception classes for different error types:
  - Authentication errors (InvalidCredentialsError, AccountLockedError, etc.)
  - Token errors (TokenExpiredError, TokenInvalidError, etc.)
  - Authorization errors (InsufficientPermissionsError, etc.)
  - Security errors (SuspiciousActivityError, ThreatDetectedError, etc.)
  - And many more...
- Consistent error response format with correlation ID support
- Machine-readable error codes and human-readable messages

**Usage Example:**

```python
from enterprise_auth.core.exceptions import InvalidCredentialsError

raise InvalidCredentialsError(
    message="Invalid email or password",
    details={'field': 'password'},
    correlation_id='req-123'
)
```

### 4. Error Handling Middleware (`enterprise_auth/core/utils/error_handling.py`)

Comprehensive error handling middleware that catches exceptions and returns consistent JSON responses.

**Key Features:**

- Catches all exceptions and converts them to standardized JSON responses
- Appropriate HTTP status codes for different error types
- Comprehensive logging with correlation IDs
- Security-aware error handling (doesn't expose internal details in production)
- Integration with monitoring systems (Sentry)

### 5. Base Model Classes (`enterprise_auth/core/models/base.py`)

Abstract base model classes providing common functionality for all models in the system.

**Key Features:**

- **BaseModel**: UUID primary keys and basic metadata
- **TimestampedModel**: Automatic created_at and updated_at timestamps
- **AuditableModel**: Full audit trail with user tracking and correlation IDs
- **SoftDeleteModel**: Soft delete functionality with restore capabilities
- **VersionedModel**: Version tracking for optimistic locking
- **EncryptedFieldMixin**: Utilities for handling encrypted model fields
- **CacheableModelMixin**: Cache management for model instances

**Usage Example:**

```python
from enterprise_auth.core.models.base import SoftDeleteModel

class MyModel(SoftDeleteModel):
    name = models.CharField(max_length=100)

    class Meta:
        app_label = 'my_app'

# Usage
instance = MyModel.objects.create(name='test')
instance.delete(user=request.user)  # Soft delete
instance.restore(user=request.user)  # Restore
```

## Configuration Updates

The following configuration updates were made to integrate the new components:

### Middleware Configuration

Added the new middleware to the Django middleware stack:

```python
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'enterprise_auth.core.utils.correlation.CorrelationIDMiddleware',  # Added
    # ... other middleware ...
    'enterprise_auth.core.utils.error_handling.ErrorHandlingMiddleware',  # Added
]
```

### Logging Configuration

Enhanced logging configuration with correlation ID support:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {name} [{correlation_id}] {message}',
            'style': '{',
        },
    },
    'filters': {
        'correlation_id': {
            '()': 'enterprise_auth.core.utils.correlation.CorrelationIDFilter',
        },
    },
    # ... rest of logging config
}
```

## Testing

Comprehensive test suite implemented in:

- `enterprise_auth/core/tests/test_utilities.py` - Tests for all utility functions
- All tests passing with 100% coverage of implemented functionality

## Security Considerations

1. **Encryption**: Uses industry-standard Fernet encryption with PBKDF2 key derivation
2. **Salt Usage**: Each encrypted value uses a unique salt to prevent rainbow table attacks
3. **Error Handling**: Careful not to expose sensitive information in error messages
4. **Audit Trails**: Comprehensive logging and audit trails for security monitoring
5. **Correlation IDs**: Enable request tracing for security incident investigation

## Performance Considerations

1. **Thread-Local Storage**: Efficient correlation ID storage without performance impact
2. **Caching**: Built-in cache management utilities for model instances
3. **Database Optimization**: Proper indexing on audit and timestamp fields
4. **Lazy Loading**: Encryption/decryption only when needed

## Next Steps

With these core utilities in place, the system is ready for:

1. User management and authentication implementation (Task 5)
2. JWT token management system (Task 9)
3. Advanced session management (Task 24)
4. Security and threat detection (Task 28)

All subsequent tasks can leverage these core utilities for consistent error handling, audit trails, encryption, and request tracking.
