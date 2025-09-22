# 🚀 Postman Testing Guide for Enterprise Django Authentication API

## 📋 Table of Contents
1. [Quick Setup](#quick-setup)
2. [Base Configuration](#base-configuration)
3. [Health Check Endpoints](#health-check-endpoints)
4. [Authentication Endpoints](#authentication-endpoints)
5. [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
6. [Session Management](#session-management)
7. [OAuth Integration](#oauth-integration)
8. [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
9. [Admin Endpoints](#admin-endpoints)
10. [Environment Variables](#environment-variables)

## 🚀 Quick Setup

### Prerequisites
- ✅ Django server running on `http://127.0.0.1:8000`
- ✅ Postman installed
- ✅ Superuser created: `admin@example.com` / `admin123`

### Base URL
```
http://127.0.0.1:8000
```

## ⚙️ Base Configuration

### Postman Environment Variables
Create a new environment in Postman with these variables:

| Variable | Initial Value | Current Value |
|----------|--------------|---------------|
| `base_url` | `http://127.0.0.1:8000` | |
| `access_token` | | (will be set after login) |
| `refresh_token` | | (will be set after login) |
| `user_id` | | (will be set after login) |

## 🏥 Health Check Endpoints

### 1. Basic Health Check
```http
GET {{base_url}}/health/
```
**Expected Response:**
```json
{
    "status": "healthy",
    "service": "enterprise-auth-backend",
    "version": "1.0.0"
}
```

### 2. Readiness Check
```http
GET {{base_url}}/ready/
```

### 3. Redis Health Check
```http
GET {{base_url}}/api/v1/core/health/redis/
```

### 4. System Health Check
```http
GET {{base_url}}/api/v1/core/health/system/
```

## 🔐 Authentication Endpoints

### 1. User Login (Primary)
```http
POST {{base_url}}/api/v1/core/auth/login/
Content-Type: application/json

{
    "email": "admin@example.com",
    "password": "admin123"
}
```

**Expected Response:**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": "uuid-here",
        "email": "admin@example.com",
        "first_name": "Admin",
        "last_name": "User"
    },
    "token_type": "Bearer",
    "expires_in": 3600
}
```

**Postman Test Script:**
```javascript
if (pm.response.code === 200) {
    const response = pm.response.json();
    pm.environment.set("access_token", response.access_token);
    pm.environment.set("refresh_token", response.refresh_token);
    pm.environment.set("user_id", response.user.id);
}
```

### 2. Refresh Token
```http
POST {{base_url}}/api/v1/core/auth/refresh/
Content-Type: application/json

{
    "refresh_token": "{{refresh_token}}"
}
```

### 3. Get User Profile
```http
GET {{base_url}}/api/v1/core/auth/profile/
Authorization: Bearer {{access_token}}
```

### 4. Validate Token
```http
POST {{base_url}}/api/v1/core/auth/validate/
Content-Type: application/json
Authorization: Bearer {{access_token}}

{
    "token": "{{access_token}}"
}
```

### 5. Token Introspection
```http
POST {{base_url}}/api/v1/core/auth/introspect/
Content-Type: application/json
Authorization: Bearer {{access_token}}

{
    "token": "{{access_token}}"
}
```

### 6. Logout
```http
POST {{base_url}}/api/v1/core/auth/logout/
Authorization: Bearer {{access_token}}
```

### 7. Revoke All User Tokens
```http
POST {{base_url}}/api/v1/core/auth/revoke-all/
Authorization: Bearer {{access_token}}
```

## 🔒 Multi-Factor Authentication (MFA)

### 1. Get MFA Status
```http
GET {{base_url}}/api/v1/core/mfa/status/
Authorization: Bearer {{access_token}}
```

### 2. Setup TOTP (Time-based One-Time Password)
```http
POST {{base_url}}/api/v1/core/mfa/setup/totp/
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
    "device_name": "My Phone"
}
```

### 3. Confirm TOTP Setup
```http
POST {{base_url}}/api/v1/core/mfa/confirm/totp/
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
    "device_id": "device-uuid-from-setup",
    "token": "123456"
}
```

### 4. Verify TOTP
```http
POST {{base_url}}/api/v1/core/mfa/verify/totp/
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
    "token": "123456"
}
```

### 5. List MFA Devices
```http
GET {{base_url}}/api/v1/core/mfa/devices/
Authorization: Bearer {{access_token}}
```

### 6. Generate Backup Codes
```http
POST {{base_url}}/api/v1/core/mfa/backup-codes/regenerate/
Authorization: Bearer {{access_token}}
```

### 7. Verify Backup Code
```http
POST {{base_url}}/api/v1/core/mfa/verify/backup-code/
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
    "backup_code": "ABC123DEF"
}
```

## 📱 Session Management

### 1. List User Sessions
```http
GET {{base_url}}/api/v1/core/sessions/
Authorization: Bearer {{access_token}}
```

### 2. Get Current Session
```http
GET {{base_url}}/api/v1/core/sessions/current/
Authorization: Bearer {{access_token}}
```

### 3. Get Session Details
```http
GET {{base_url}}/api/v1/core/sessions/{session_id}/
Authorization: Bearer {{access_token}}
```

### 4. Extend Current Session
```http
POST {{base_url}}/api/v1/core/sessions/current/extend/
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
    "extend_by_minutes": 30
}
```

### 5. Terminate Specific Session
```http
DELETE {{base_url}}/api/v1/core/sessions/{session_id}/terminate/
Authorization: Bearer {{access_token}}
```

### 6. Terminate All Sessions
```http
POST {{base_url}}/api/v1/core/sessions/terminate-all/
Authorization: Bearer {{access_token}}
```

### 7. Get Session Statistics
```http
GET {{base_url}}/api/v1/core/sessions/statistics/
Authorization: Bearer {{access_token}}
```

## 🔗 OAuth Integration

### 1. List OAuth Providers
```http
GET {{base_url}}/api/v1/core/oauth/providers/
```

### 2. OAuth Provider Health
```http
GET {{base_url}}/api/v1/core/oauth/health/
```

### 3. List User OAuth Identities
```http
GET {{base_url}}/api/v1/core/oauth/identities/
Authorization: Bearer {{access_token}}
```

### 4. OAuth Metrics Summary
```http
GET {{base_url}}/api/v1/core/oauth/metrics/
Authorization: Bearer {{access_token}}
```

## 👥 Role-Based Access Control (RBAC)

### 1. List Roles
```http
GET {{base_url}}/api/v1/core/rbac/roles/
Authorization: Bearer {{access_token}}
```

### 2. Create Role
```http
POST {{base_url}}/api/v1/core/rbac/roles/
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
    "name": "Test Role",
    "description": "A test role for demonstration",
    "permissions": []
}
```

### 3. Get Role Details
```http
GET {{base_url}}/api/v1/core/rbac/roles/{role_id}/
Authorization: Bearer {{access_token}}
```

### 4. List Permissions
```http
GET {{base_url}}/api/v1/core/rbac/permissions/
Authorization: Bearer {{access_token}}
```

### 5. Get User Roles
```http
GET {{base_url}}/api/v1/core/rbac/users/{user_id}/roles/
Authorization: Bearer {{access_token}}
```

## 👨‍💼 Admin Endpoints

### 1. Django Admin (Web Interface)
```
http://127.0.0.1:8000/admin/
```
- Username: `admin@example.com`
- Password: `admin123`

### 2. Admin Session Statistics
```http
GET {{base_url}}/api/v1/core/admin/sessions/statistics/
Authorization: Bearer {{access_token}}
```

### 3. Admin Terminate User Sessions
```http
POST {{base_url}}/api/v1/core/admin/users/{user_id}/sessions/terminate/
Authorization: Bearer {{access_token}}
```

## 📊 Monitoring & Metrics

### 1. Prometheus Metrics
```http
GET {{base_url}}/api/v1/core/metrics/
```

### 2. Cache Statistics
```http
GET {{base_url}}/api/v1/core/health/cache/
Authorization: Bearer {{access_token}}
```

## 🔧 Sample Postman Collection JSON

Here's a basic Postman collection you can import:

```json
{
    "info": {
        "name": "Enterprise Django Auth API",
        "description": "Comprehensive API testing for Django Enterprise Authentication",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    },
    "auth": {
        "type": "bearer",
        "bearer": [
            {
                "key": "token",
                "value": "{{access_token}}",
                "type": "string"
            }
        ]
    },
    "variable": [
        {
            "key": "base_url",
            "value": "http://127.0.0.1:8000"
        }
    ]
}
```

## 🧪 Testing Scenarios

### Scenario 1: Complete Authentication Flow
1. Health Check → Login → Get Profile → Logout
2. Login → Setup MFA → Verify MFA → Logout

### Scenario 2: Session Management
1. Login → List Sessions → Get Current Session → Extend Session → Terminate Session

### Scenario 3: Token Management
1. Login → Validate Token → Refresh Token → Revoke Token

## ⚠️ Important Notes

1. **CSRF Token**: Not required for API endpoints in development
2. **Rate Limiting**: May be implemented, test gradually
3. **OAuth Providers**: Currently disabled due to missing configuration
4. **HTTPS**: Use HTTP in development, HTTPS in production
5. **Token Expiry**: Access tokens expire, use refresh tokens

## 🔍 Debugging Tips

1. **Check Server Logs**: Monitor the Django console for errors
2. **Response Headers**: Check for authentication and rate limiting headers
3. **Status Codes**: 
   - 200: Success
   - 401: Unauthorized
   - 403: Forbidden
   - 422: Validation Error
   - 500: Server Error

## 📝 Environment Setup Script

Add this to your Postman pre-request script for automatic token refresh:

```javascript
// Auto-refresh token if expired
if (pm.environment.get("access_token") && pm.environment.get("refresh_token")) {
    // Check if token needs refresh (implement as needed)
    // This is a placeholder for more sophisticated token management
}
```

Happy Testing! 🎉