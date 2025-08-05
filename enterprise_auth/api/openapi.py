"""
OpenAPI Specification Generation

Generates comprehensive OpenAPI 3.0 specification for the EnterpriseAuth API.
"""
from typing import Dict, Any, List
from django.urls import reverse
from django.conf import settings
from rest_framework import status
from drf_spectacular.openapi import AutoSchema
from drf_spectacular.utils import extend_schema_serializer
from drf_spectacular.plumbing import build_object_type, build_array_type

from .models import APIKeyScope, APIKeyTier, WebhookEventType, WebhookDeliveryStatus
from .serializers import (
    APIKeySerializer, WebhookEndpointSerializer, WebhookDeliverySerializer,
    APIRequestLogSerializer, APIErrorSerializer, APIVersionSerializer,
    APIHealthSerializer
)


def generate_openapi_spec() -> Dict[str, Any]:
    """
    Generate complete OpenAPI 3.0 specification.
    
    Returns:
        OpenAPI specification dictionary
    """
    return {
        "openapi": "3.0.3",
        "info": get_api_info(),
        "servers": get_servers(),
        "security": get_security_schemes(),
        "paths": get_paths(),
        "components": get_components(),
        "tags": get_tags()
    }


def get_api_info() -> Dict[str, Any]:
    """Get API information section."""
    return {
        "title": "EnterpriseAuth API",
        "description": """
# EnterpriseAuth API

A comprehensive, enterprise-grade authentication API that provides:

- **User Management**: Complete user lifecycle management with multi-factor authentication
- **JWT Token Management**: Secure token generation, validation, and refresh with device binding
- **OAuth2 Integration**: Support for Google, GitHub, Microsoft, and other OAuth providers
- **API Key Management**: Scoped API keys with rate limiting and IP restrictions
- **Webhook System**: Real-time event notifications with reliable delivery
- **Session Management**: Advanced session tracking with security monitoring
- **Role-Based Access Control**: Fine-grained permissions and role management
- **Security Features**: Threat detection, rate limiting, and audit logging

## Authentication

The API supports multiple authentication methods:

### API Key Authentication
```
Authorization: Bearer ea_your_api_key_here
```

### JWT Token Authentication
```
Authorization: Bearer your_jwt_token_here
```

## Rate Limiting

API requests are rate limited based on:
- **Global limits**: 100 requests/minute, 1000 requests/hour per IP
- **API key limits**: Configurable per key based on tier
- **Endpoint limits**: Specific limits for sensitive endpoints

Rate limit headers are included in responses:
- `X-Rate-Limit-Limit`: Request limit
- `X-Rate-Limit-Remaining`: Remaining requests
- `X-Rate-Limit-Reset`: Reset timestamp

## Error Handling

All errors follow a consistent format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": {},
    "request_id": "req_123456789",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## Webhooks

The API can send webhook notifications for various events. Webhooks include:
- **Signature verification** using HMAC-SHA256
- **Automatic retries** with exponential backoff
- **Delivery tracking** and status monitoring
- **Event filtering** by subscription

## SDKs

Official SDKs are available for:
- **Python**: `pip install enterpriseauth-sdk`
- **JavaScript/TypeScript**: `npm install @enterpriseauth/sdk`

## Support

- **Documentation**: https://docs.enterpriseauth.com
- **Support**: support@enterpriseauth.com
- **GitHub**: https://github.com/enterpriseauth/api
        """,
        "version": "1.0.0",
        "contact": {
            "name": "EnterpriseAuth Support",
            "email": "support@enterpriseauth.com",
            "url": "https://docs.enterpriseauth.com"
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        }
    }


def get_servers() -> List[Dict[str, Any]]:
    """Get API servers configuration."""
    servers = []
    
    # Production server
    if hasattr(settings, 'API_BASE_URL'):
        servers.append({
            "url": settings.API_BASE_URL,
            "description": "Production API"
        })
    
    # Development server
    servers.append({
        "url": "http://localhost:8000/api/v1",
        "description": "Development server"
    })
    
    return servers


def get_security_schemes() -> List[Dict[str, Any]]:
    """Get security schemes."""
    return [
        {
            "ApiKeyAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "API Key",
                "description": "API key authentication using Bearer token"
            }
        },
        {
            "JWTAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT token authentication"
            }
        }
    ]


def get_paths() -> Dict[str, Any]:
    """Get API paths specification."""
    return {
        "/": {
            "get": {
                "tags": ["API Information"],
                "summary": "Get API version information",
                "description": "Returns information about the API version and capabilities",
                "responses": {
                    "200": {
                        "description": "API version information",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIVersion"}
                            }
                        }
                    }
                }
            }
        },
        "/health/": {
            "get": {
                "tags": ["Health"],
                "summary": "API health check",
                "description": "Check API health and status",
                "responses": {
                    "200": {
                        "description": "API is healthy",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIHealth"}
                            }
                        }
                    },
                    "503": {
                        "description": "API is unhealthy",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIHealth"}
                            }
                        }
                    }
                }
            }
        },
        "/keys/": {
            "get": {
                "tags": ["API Keys"],
                "summary": "List API keys",
                "description": "Retrieve a paginated list of API keys",
                "security": [{"ApiKeyAuth": []}, {"JWTAuth": []}],
                "parameters": [
                    {
                        "name": "page",
                        "in": "query",
                        "description": "Page number",
                        "schema": {"type": "integer", "minimum": 1}
                    },
                    {
                        "name": "page_size",
                        "in": "query",
                        "description": "Number of items per page",
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100}
                    },
                    {
                        "name": "is_active",
                        "in": "query",
                        "description": "Filter by active status",
                        "schema": {"type": "boolean"}
                    },
                    {
                        "name": "tier",
                        "in": "query",
                        "description": "Filter by tier",
                        "schema": {"type": "string", "enum": ["basic", "premium", "enterprise"]}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "List of API keys",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "pagination": {"$ref": "#/components/schemas/Pagination"},
                                        "results": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/APIKeyList"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            },
            "post": {
                "tags": ["API Keys"],
                "summary": "Create API key",
                "description": "Create a new API key with specified configuration",
                "security": [{"ApiKeyAuth": []}, {"JWTAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/APIKeyCreate"}
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "API key created successfully",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIKey"}
                            }
                        }
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"$ref": "#/components/responses/RateLimited"}
                }
            }
        },
        "/keys/{id}/": {
            "get": {
                "tags": ["API Keys"],
                "summary": "Get API key details",
                "description": "Retrieve details of a specific API key",
                "security": [{"ApiKeyAuth": []}, {"JWTAuth": []}],
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "description": "API key ID",
                        "schema": {"type": "string", "format": "uuid"}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "API key details",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIKey"}
                            }
                        }
                    },
                    "404": {"$ref": "#/components/responses/NotFound"},
                    "401": {"$ref": "#/components/responses/Unauthorized"}
                }
            },
            "put": {
                "tags": ["API Keys"],
                "summary": "Update API key",
                "description": "Update API key configuration",
                "security": [{"ApiKeyAuth": []}, {"JWTAuth": []}],
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "description": "API key ID",
                        "schema": {"type": "string", "format": "uuid"}
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/APIKeyUpdate"}
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "API key updated successfully",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIKey"}
                            }
                        }
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                    "401": {"$ref": "#/components/responses/Unauthorized"}
                }
            },
            "delete": {
                "tags": ["API Keys"],
                "summary": "Delete API key",
                "description": "Delete an API key permanently",
                "security": [{"ApiKeyAuth": []}, {"JWTAuth": []}],
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "description": "API key ID",
                        "schema": {"type": "string", "format": "uuid"}
                    }
                ],
                "responses": {
                    "204": {"description": "API key deleted successfully"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                    "401": {"$ref": "#/components/responses/Unauthorized"}
                }
            }
        },
        "/webhooks/": {
            "get": {
                "tags": ["Webhooks"],
                "summary": "List webhook endpoints",
                "description": "Retrieve a paginated list of webhook endpoints",
                "security": [{"ApiKeyAuth": []}, {"JWTAuth": []}],
                "parameters": [
                    {
                        "name": "page",
                        "in": "query",
                        "description": "Page number",
                        "schema": {"type": "integer", "minimum": 1}
                    },
                    {
                        "name": "is_active",
                        "in": "query",
                        "description": "Filter by active status",
                        "schema": {"type": "boolean"}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "List of webhook endpoints",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "pagination": {"$ref": "#/components/schemas/Pagination"},
                                        "results": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/WebhookEndpointList"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"}
                }
            },
            "post": {
                "tags": ["Webhooks"],
                "summary": "Create webhook endpoint",
                "description": "Register a new webhook endpoint",
                "security": [{"ApiKeyAuth": []}, {"JWTAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/WebhookEndpointCreate"}
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "Webhook endpoint created successfully",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/WebhookEndpoint"}
                            }
                        }
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "401": {"$ref": "#/components/responses/Unauthorized"}
                }
            }
        },
        "/analytics/": {
            "get": {
                "tags": ["Analytics"],
                "summary": "Get API analytics",
                "description": "Retrieve API usage analytics and metrics",
                "security": [{"ApiKeyAuth": []}, {"JWTAuth": []}],
                "parameters": [
                    {
                        "name": "period",
                        "in": "query",
                        "description": "Time period",
                        "schema": {"type": "string", "enum": ["day", "week", "month"]}
                    },
                    {
                        "name": "api_key_id",
                        "in": "query",
                        "description": "Filter by API key",
                        "schema": {"type": "string", "format": "uuid"}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "API analytics data",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/APIAnalytics"}
                            }
                        }
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"}
                }
            }
        }
    }


def get_components() -> Dict[str, Any]:
    """Get OpenAPI components."""
    return {
        "schemas": get_schemas(),
        "responses": get_responses(),
        "securitySchemes": {
            "ApiKeyAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "API Key",
                "description": "API key authentication using Bearer token"
            },
            "JWTAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT token authentication"
            }
        }
    }


def get_schemas() -> Dict[str, Any]:
    """Get OpenAPI schemas."""
    return {
        "APIVersion": {
            "type": "object",
            "properties": {
                "version": {"type": "string", "example": "v1"},
                "supported_versions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "example": ["v1"]
                },
                "deprecated_versions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "example": []
                },
                "documentation_url": {
                    "type": "string",
                    "format": "uri",
                    "example": "https://docs.enterpriseauth.com/api/v1/"
                },
                "changelog_url": {
                    "type": "string",
                    "format": "uri",
                    "example": "https://docs.enterpriseauth.com/changelog/"
                }
            }
        },
        "APIHealth": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["healthy", "unhealthy"]},
                "version": {"type": "string", "example": "v1"},
                "timestamp": {"type": "string", "format": "date-time"},
                "checks": {
                    "type": "object",
                    "properties": {
                        "database": {"type": "string", "enum": ["healthy", "unhealthy"]},
                        "cache": {"type": "string", "enum": ["healthy", "unhealthy"]}
                    }
                },
                "uptime_seconds": {"type": "integer", "example": 86400}
            }
        },
        "APIKey": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "name": {"type": "string", "example": "Production API Key"},
                "description": {"type": "string", "example": "API key for production environment"},
                "key_id": {"type": "string", "example": "ak_1234567890abcdef"},
                "key_prefix": {"type": "string", "example": "ea_12345"},
                "generated_key": {
                    "type": "string",
                    "description": "Only returned on creation",
                    "example": "ea_1234567890abcdef_secretkey"
                },
                "created_by": {"type": "string", "example": "user@example.com"},
                "organization": {"type": "string", "example": "Acme Corp"},
                "scopes": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["read_only", "read_write", "admin", "webhook_only"]},
                    "example": ["read_write"]
                },
                "tier": {"type": "string", "enum": ["basic", "premium", "enterprise"], "example": "premium"},
                "allowed_ips": {
                    "type": "array",
                    "items": {"type": "string", "format": "ipv4"},
                    "example": ["192.168.1.1", "10.0.0.1"]
                },
                "is_active": {"type": "boolean", "example": True},
                "expires_at": {"type": "string", "format": "date-time", "nullable": True},
                "last_used_at": {"type": "string", "format": "date-time", "nullable": True},
                "usage_count": {"type": "integer", "example": 1250},
                "rate_limit_per_minute": {"type": "integer", "example": 60},
                "rate_limit_per_hour": {"type": "integer", "example": 1000},
                "rate_limit_per_day": {"type": "integer", "example": 10000},
                "created_at": {"type": "string", "format": "date-time"},
                "updated_at": {"type": "string", "format": "date-time"}
            }
        },
        "APIKeyList": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "name": {"type": "string", "example": "Production API Key"},
                "key_prefix": {"type": "string", "example": "ea_12345"},
                "created_by": {"type": "string", "example": "user@example.com"},
                "organization": {"type": "string", "example": "Acme Corp"},
                "tier": {"type": "string", "enum": ["basic", "premium", "enterprise"]},
                "is_active": {"type": "boolean"},
                "is_expired": {"type": "boolean"},
                "expires_at": {"type": "string", "format": "date-time", "nullable": True},
                "last_used_at": {"type": "string", "format": "date-time", "nullable": True},
                "usage_count": {"type": "integer"},
                "created_at": {"type": "string", "format": "date-time"}
            }
        },
        "APIKeyCreate": {
            "type": "object",
            "required": ["name", "scopes"],
            "properties": {
                "name": {"type": "string", "example": "Production API Key"},
                "description": {"type": "string", "example": "API key for production environment"},
                "organization": {"type": "string", "example": "Acme Corp"},
                "scopes": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["read_only", "read_write", "admin", "webhook_only"]},
                    "minItems": 1,
                    "example": ["read_write"]
                },
                "tier": {"type": "string", "enum": ["basic", "premium", "enterprise"], "default": "basic"},
                "allowed_ips": {
                    "type": "array",
                    "items": {"type": "string", "format": "ipv4"},
                    "example": ["192.168.1.1"]
                },
                "expires_at": {"type": "string", "format": "date-time", "nullable": True},
                "rate_limit_per_minute": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 60},
                "rate_limit_per_hour": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000},
                "rate_limit_per_day": {"type": "integer", "minimum": 1, "maximum": 100000, "default": 10000}
            }
        },
        "APIKeyUpdate": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
                "organization": {"type": "string"},
                "scopes": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["read_only", "read_write", "admin", "webhook_only"]},
                    "minItems": 1
                },
                "tier": {"type": "string", "enum": ["basic", "premium", "enterprise"]},
                "allowed_ips": {
                    "type": "array",
                    "items": {"type": "string", "format": "ipv4"}
                },
                "is_active": {"type": "boolean"},
                "expires_at": {"type": "string", "format": "date-time", "nullable": True},
                "rate_limit_per_minute": {"type": "integer", "minimum": 1, "maximum": 1000},
                "rate_limit_per_hour": {"type": "integer", "minimum": 1, "maximum": 10000},
                "rate_limit_per_day": {"type": "integer", "minimum": 1, "maximum": 100000}
            }
        },
        "WebhookEndpoint": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "name": {"type": "string", "example": "Production Webhook"},
                "description": {"type": "string", "example": "Webhook for production events"},
                "url": {"type": "string", "format": "uri", "example": "https://api.example.com/webhooks"},
                "secret_key": {"type": "string", "example": "whsec_1234567890abcdef"},
                "verification_token": {"type": "string", "example": "wht_1234567890abcdef"},
                "created_by": {"type": "string", "example": "user@example.com"},
                "organization": {"type": "string", "example": "Acme Corp"},
                "subscribed_events": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(WebhookEventType.values)},
                    "example": ["user.created", "user.login"]
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "example": {"Authorization": "Bearer token123"}
                },
                "timeout_seconds": {"type": "integer", "example": 30},
                "max_retries": {"type": "integer", "example": 3},
                "is_active": {"type": "boolean", "example": True},
                "is_verified": {"type": "boolean", "example": True},
                "total_deliveries": {"type": "integer", "example": 1500},
                "successful_deliveries": {"type": "integer", "example": 1450},
                "failed_deliveries": {"type": "integer", "example": 50},
                "success_rate": {"type": "number", "format": "float", "example": 96.67},
                "last_delivery_at": {"type": "string", "format": "date-time", "nullable": True},
                "created_at": {"type": "string", "format": "date-time"},
                "updated_at": {"type": "string", "format": "date-time"}
            }
        },
        "WebhookEndpointList": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "name": {"type": "string"},
                "url": {"type": "string", "format": "uri"},
                "created_by": {"type": "string"},
                "organization": {"type": "string"},
                "is_active": {"type": "boolean"},
                "is_verified": {"type": "boolean"},
                "event_count": {"type": "integer"},
                "total_deliveries": {"type": "integer"},
                "success_rate": {"type": "number", "format": "float"},
                "last_delivery_at": {"type": "string", "format": "date-time", "nullable": True},
                "created_at": {"type": "string", "format": "date-time"}
            }
        },
        "WebhookEndpointCreate": {
            "type": "object",
            "required": ["name", "url", "subscribed_events"],
            "properties": {
                "name": {"type": "string", "example": "Production Webhook"},
                "description": {"type": "string", "example": "Webhook for production events"},
                "url": {"type": "string", "format": "uri", "example": "https://api.example.com/webhooks"},
                "organization": {"type": "string", "example": "Acme Corp"},
                "subscribed_events": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(WebhookEventType.values)},
                    "minItems": 1,
                    "example": ["user.created", "user.login"]
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "example": {"Authorization": "Bearer token123"}
                },
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 300, "default": 30},
                "max_retries": {"type": "integer", "minimum": 0, "maximum": 10, "default": 3}
            }
        },
        "APIAnalytics": {
            "type": "object",
            "properties": {
                "period": {"type": "string", "enum": ["day", "week", "month"]},
                "start_date": {"type": "string", "format": "date-time"},
                "end_date": {"type": "string", "format": "date-time"},
                "total_requests": {"type": "integer", "example": 10000},
                "successful_requests": {"type": "integer", "example": 9500},
                "error_requests": {"type": "integer", "example": 500},
                "success_rate": {"type": "number", "format": "float", "example": 95.0},
                "average_response_time_ms": {"type": "number", "format": "float", "example": 125.5},
                "top_endpoints": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "count": {"type": "integer"}
                        }
                    }
                },
                "status_code_distribution": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "status_code": {"type": "integer"},
                            "count": {"type": "integer"}
                        }
                    }
                }
            }
        },
        "Pagination": {
            "type": "object",
            "properties": {
                "count": {"type": "integer", "example": 100},
                "next": {"type": "string", "format": "uri", "nullable": True},
                "previous": {"type": "string", "format": "uri", "nullable": True},
                "page_size": {"type": "integer", "example": 20},
                "total_pages": {"type": "integer", "example": 5},
                "current_page": {"type": "integer", "example": 1}
            }
        },
        "Error": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "example": "VALIDATION_ERROR"},
                        "message": {"type": "string", "example": "Invalid input data"},
                        "details": {"type": "object"},
                        "request_id": {"type": "string", "example": "req_123456789"},
                        "timestamp": {"type": "string", "format": "date-time"}
                    }
                }
            }
        }
    }


def get_responses() -> Dict[str, Any]:
    """Get common API responses."""
    return {
        "BadRequest": {
            "description": "Bad request",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}
                }
            }
        },
        "Unauthorized": {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}
                }
            }
        },
        "Forbidden": {
            "description": "Forbidden",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}
                }
            }
        },
        "NotFound": {
            "description": "Not found",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}
                }
            }
        },
        "RateLimited": {
            "description": "Rate limit exceeded",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}
                }
            }
        },
        "InternalServerError": {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}
                }
            }
        }
    }


def get_tags() -> List[Dict[str, Any]]:
    """Get API tags for organization."""
    return [
        {
            "name": "API Information",
            "description": "API version and capability information"
        },
        {
            "name": "Health",
            "description": "API health and status endpoints"
        },
        {
            "name": "API Keys",
            "description": "API key management operations"
        },
        {
            "name": "Webhooks",
            "description": "Webhook endpoint management"
        },
        {
            "name": "Analytics",
            "description": "API usage analytics and metrics"
        }
    ]


class EnterpriseAuthAutoSchema(AutoSchema):
    """Custom OpenAPI schema generator for EnterpriseAuth API."""
    
    def get_operation_id(self, path, method):
        """Generate operation ID for OpenAPI."""
        # Remove /api/v1/ prefix
        clean_path = path.replace('/api/v1/', '').strip('/')
        
        # Convert path to operation name
        parts = clean_path.split('/')
        operation_parts = []
        
        for part in parts:
            if part.startswith('{') and part.endswith('}'):
                # Skip path parameters
                continue
            operation_parts.append(part.replace('-', '_'))
        
        # Add method prefix
        method_prefix = {
            'GET': 'get',
            'POST': 'create',
            'PUT': 'update',
            'PATCH': 'partial_update',
            'DELETE': 'delete'
        }.get(method.upper(), method.lower())
        
        if operation_parts:
            operation_name = '_'.join(operation_parts)
            return f"{method_prefix}_{operation_name}"
        else:
            return f"{method_prefix}_root"
    
    def get_tags(self, path, method):
        """Get tags for operation."""
        if '/keys/' in path:
            return ['API Keys']
        elif '/webhooks/' in path:
            return ['Webhooks']
        elif '/analytics/' in path:
            return ['Analytics']
        elif '/health/' in path:
            return ['Health']
        else:
            return ['API Information']