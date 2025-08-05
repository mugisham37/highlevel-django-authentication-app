"""
API Documentation Generator

Generates comprehensive API documentation with examples and integration guides.
"""
import json
from typing import Dict, Any, List
from django.conf import settings
from django.urls import reverse
from django.template.loader import render_to_string

from .openapi import generate_openapi_spec
from .models import APIKeyScope, APIKeyTier, WebhookEventType


class APIDocumentationGenerator:
    """Generate comprehensive API documentation."""
    
    def __init__(self):
        self.base_url = getattr(settings, 'API_BASE_URL', 'https://api.enterpriseauth.com/v1')
    
    def generate_full_documentation(self) -> Dict[str, Any]:
        """Generate complete API documentation."""
        return {
            'openapi_spec': generate_openapi_spec(),
            'getting_started': self.generate_getting_started_guide(),
            'authentication': self.generate_authentication_guide(),
            'api_keys': self.generate_api_key_guide(),
            'webhooks': self.generate_webhook_guide(),
            'rate_limiting': self.generate_rate_limiting_guide(),
            'error_handling': self.generate_error_handling_guide(),
            'sdk_examples': self.generate_sdk_examples(),
            'integration_examples': self.generate_integration_examples(),
            'changelog': self.generate_changelog()
        }
    
    def generate_getting_started_guide(self) -> Dict[str, Any]:
        """Generate getting started guide."""
        return {
            'title': 'Getting Started with EnterpriseAuth API',
            'description': 'Quick start guide for integrating with the EnterpriseAuth API',
            'steps': [
                {
                    'step': 1,
                    'title': 'Create an API Key',
                    'description': 'First, create an API key through the dashboard or API',
                    'code_example': {
                        'curl': '''curl -X POST "{base_url}/keys/" \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "name": "My First API Key",
    "scopes": ["read_write"],
    "tier": "basic"
  }}'
'''.format(base_url=self.base_url),
                        'python': '''from enterpriseauth import EnterpriseAuthClient

client = EnterpriseAuthClient(jwt_token="YOUR_JWT_TOKEN")

api_key = client.create_api_key(
    name="My First API Key",
    scopes=["read_write"],
    tier="basic"
)

print(f"Generated API Key: {api_key.generated_key}")
''',
                        'javascript': '''import EnterpriseAuthClient from '@enterpriseauth/sdk';

const client = new EnterpriseAuthClient({
  jwtToken: 'YOUR_JWT_TOKEN'
});

const apiKey = await client.createApiKey({
  name: 'My First API Key',
  scopes: ['read_write'],
  tier: 'basic'
});

console.log('Generated API Key:', apiKey.generated_key);
'''
                    }
                },
                {
                    'step': 2,
                    'title': 'Make Your First API Call',
                    'description': 'Use your API key to make authenticated requests',
                    'code_example': {
                        'curl': '''curl -X GET "{base_url}/health/" \\
  -H "Authorization: Bearer YOUR_API_KEY"
'''.format(base_url=self.base_url),
                        'python': '''client = EnterpriseAuthClient(api_key="YOUR_API_KEY")

health = client.get_health_status()
print(f"API Status: {health['status']}")
''',
                        'javascript': '''const client = new EnterpriseAuthClient({
  apiKey: 'YOUR_API_KEY'
});

const health = await client.getHealthStatus();
console.log('API Status:', health.status);
'''
                    }
                },
                {
                    'step': 3,
                    'title': 'Set Up Webhooks (Optional)',
                    'description': 'Configure webhooks to receive real-time notifications',
                    'code_example': {
                        'curl': '''curl -X POST "{base_url}/webhooks/" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "name": "My Webhook",
    "url": "https://your-app.com/webhooks/enterpriseauth",
    "subscribed_events": ["user.created", "user.login"]
  }}'
'''.format(base_url=self.base_url),
                        'python': '''webhook = client.create_webhook(
    name="My Webhook",
    url="https://your-app.com/webhooks/enterpriseauth",
    subscribed_events=["user.created", "user.login"]
)

print(f"Webhook Secret: {webhook.secret_key}")
''',
                        'javascript': '''const webhook = await client.createWebhook({
  name: 'My Webhook',
  url: 'https://your-app.com/webhooks/enterpriseauth',
  subscribed_events: ['user.created', 'user.login']
});

console.log('Webhook Secret:', webhook.secret_key);
'''
                    }
                }
            ]
        }
    
    def generate_authentication_guide(self) -> Dict[str, Any]:
        """Generate authentication guide."""
        return {
            'title': 'Authentication',
            'description': 'Learn how to authenticate with the EnterpriseAuth API',
            'methods': [
                {
                    'name': 'API Key Authentication',
                    'description': 'Use API keys for server-to-server authentication',
                    'header_format': 'Authorization: Bearer YOUR_API_KEY',
                    'example': {
                        'curl': 'curl -H "Authorization: Bearer ea_1234567890abcdef_secretkey" ...',
                        'python': 'client = EnterpriseAuthClient(api_key="ea_1234567890abcdef_secretkey")',
                        'javascript': 'const client = new EnterpriseAuthClient({ apiKey: "ea_1234567890abcdef_secretkey" });'
                    },
                    'security_notes': [
                        'Store API keys securely and never expose them in client-side code',
                        'Use environment variables or secure key management systems',
                        'Rotate API keys regularly',
                        'Use IP restrictions when possible'
                    ]
                },
                {
                    'name': 'JWT Token Authentication',
                    'description': 'Use JWT tokens for user-authenticated requests',
                    'header_format': 'Authorization: Bearer YOUR_JWT_TOKEN',
                    'example': {
                        'curl': 'curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." ...',
                        'python': 'client = EnterpriseAuthClient(jwt_token="eyJhbGciOiJSUzI1NiIs...")',
                        'javascript': 'const client = new EnterpriseAuthClient({ jwtToken: "eyJhbGciOiJSUzI1NiIs..." });'
                    },
                    'security_notes': [
                        'JWT tokens have shorter lifespans than API keys',
                        'Implement token refresh logic in your applications',
                        'Validate token expiration before making requests'
                    ]
                }
            ]
        }
    
    def generate_api_key_guide(self) -> Dict[str, Any]:
        """Generate API key management guide."""
        return {
            'title': 'API Key Management',
            'description': 'Complete guide to managing API keys',
            'scopes': [
                {
                    'name': scope.value,
                    'label': scope.label,
                    'description': self.get_scope_description(scope.value)
                }
                for scope in APIKeyScope
            ],
            'tiers': [
                {
                    'name': tier.value,
                    'label': tier.label,
                    'description': self.get_tier_description(tier.value),
                    'limits': self.get_tier_limits(tier.value)
                }
                for tier in APIKeyTier
            ],
            'best_practices': [
                'Use the principle of least privilege - only grant necessary scopes',
                'Set expiration dates for temporary access',
                'Use IP restrictions for additional security',
                'Monitor API key usage regularly',
                'Rotate keys periodically',
                'Delete unused keys promptly'
            ],
            'examples': {
                'create_key': {
                    'python': '''# Create a basic API key
api_key = client.create_api_key(
    name="Production API Key",
    scopes=["read_write"],
    tier="premium",
    allowed_ips=["192.168.1.100", "10.0.0.50"],
    expires_at="2024-12-31T23:59:59Z",
    rate_limit_per_minute=120,
    rate_limit_per_hour=5000
)
''',
                    'javascript': '''// Create a basic API key
const apiKey = await client.createApiKey({
  name: 'Production API Key',
  scopes: ['read_write'],
  tier: 'premium',
  allowed_ips: ['192.168.1.100', '10.0.0.50'],
  expires_at: '2024-12-31T23:59:59Z',
  rate_limit_per_minute: 120,
  rate_limit_per_hour: 5000
});
'''
                },
                'list_keys': {
                    'python': '''# List API keys with filtering
keys = client.list_api_keys(
    page=1,
    page_size=20,
    is_active=True,
    tier="premium"
)

for key in keys.results:
    print(f"{key.name}: {key.usage_count} requests")
''',
                    'javascript': '''// List API keys with filtering
const keys = await client.listApiKeys({
  page: 1,
  page_size: 20,
  is_active: true,
  tier: 'premium'
});

keys.results.forEach(key => {
  console.log(`${key.name}: ${key.usage_count} requests`);
});
'''
                }
            }
        }
    
    def generate_webhook_guide(self) -> Dict[str, Any]:
        """Generate webhook guide."""
        return {
            'title': 'Webhooks',
            'description': 'Real-time event notifications via HTTP callbacks',
            'event_types': [
                {
                    'name': event.value,
                    'label': event.label,
                    'description': self.get_event_description(event.value),
                    'example_payload': self.get_event_example_payload(event.value)
                }
                for event in WebhookEventType
            ],
            'security': {
                'signature_verification': {
                    'description': 'All webhooks include HMAC-SHA256 signatures for verification',
                    'header_format': 'X-Webhook-Signature: t=1640995200,v1=signature_hash',
                    'verification_examples': {
                        'python': '''import hmac
import hashlib

def verify_webhook_signature(payload, signature, secret, timestamp=None):
    if timestamp:
        message = f"{timestamp}.{payload}"
    else:
        message = payload
    
    expected_signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Extract signature from header
    if ',' in signature:
        parts = signature.split(',')
        for part in parts:
            if part.startswith('v1='):
                provided_signature = part[3:]
                return hmac.compare_digest(expected_signature, provided_signature)
    
    return hmac.compare_digest(expected_signature, signature)
''',
                        'javascript': '''const crypto = require('crypto');

function verifyWebhookSignature(payload, signature, secret, timestamp = null) {
  let message = payload;
  
  if (timestamp) {
    message = `${timestamp}.${payload}`;
  }
  
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('hex');
  
  // Extract signature from header
  if (signature.includes(',')) {
    const parts = signature.split(',');
    for (const part of parts) {
      if (part.startsWith('v1=')) {
        const providedSignature = part.substring(3);
        return crypto.timingSafeEqual(
          Buffer.from(expectedSignature),
          Buffer.from(providedSignature)
        );
      }
    }
  }
  
  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature),
    Buffer.from(signature)
  );
}
'''
                    }
                }
            },
            'retry_logic': {
                'description': 'Failed webhooks are automatically retried with exponential backoff',
                'schedule': [
                    'Immediate delivery attempt',
                    'Retry after 2 minutes if failed',
                    'Retry after 4 minutes if failed',
                    'Retry after 8 minutes if failed',
                    'Mark as abandoned after 3 failed attempts'
                ]
            },
            'examples': {
                'create_webhook': {
                    'python': '''# Create a webhook endpoint
webhook = client.create_webhook(
    name="User Events Webhook",
    url="https://your-app.com/webhooks/enterpriseauth",
    subscribed_events=[
        "user.created",
        "user.login",
        "user.logout",
        "security.alert"
    ],
    headers={"Authorization": "Bearer your-app-token"},
    timeout_seconds=30,
    max_retries=3
)

print(f"Webhook Secret: {webhook.secret_key}")
''',
                    'javascript': '''// Create a webhook endpoint
const webhook = await client.createWebhook({
  name: 'User Events Webhook',
  url: 'https://your-app.com/webhooks/enterpriseauth',
  subscribed_events: [
    'user.created',
    'user.login',
    'user.logout',
    'security.alert'
  ],
  headers: { Authorization: 'Bearer your-app-token' },
  timeout_seconds: 30,
  max_retries: 3
});

console.log('Webhook Secret:', webhook.secret_key);
'''
                },
                'webhook_handler': {
                    'python': '''from flask import Flask, request, jsonify
import hmac
import hashlib

app = Flask(__name__)
WEBHOOK_SECRET = "your_webhook_secret"

@app.route('/webhooks/enterpriseauth', methods=['POST'])
def handle_webhook():
    payload = request.get_data()
    signature = request.headers.get('X-Webhook-Signature')
    
    # Verify signature
    if not verify_webhook_signature(payload, signature, WEBHOOK_SECRET):
        return jsonify({'error': 'Invalid signature'}), 401
    
    # Parse webhook data
    webhook_data = request.get_json()
    event_type = webhook_data['event_type']
    data = webhook_data['data']
    
    # Handle different event types
    if event_type == 'user.created':
        handle_user_created(data)
    elif event_type == 'user.login':
        handle_user_login(data)
    elif event_type == 'security.alert':
        handle_security_alert(data)
    
    return jsonify({'status': 'success'})
''',
                    'javascript': '''const express = require('express');
const crypto = require('crypto');

const app = express();
const WEBHOOK_SECRET = 'your_webhook_secret';

app.use(express.raw({ type: 'application/json' }));

app.post('/webhooks/enterpriseauth', (req, res) => {
  const payload = req.body;
  const signature = req.headers['x-webhook-signature'];
  
  // Verify signature
  if (!verifyWebhookSignature(payload, signature, WEBHOOK_SECRET)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  // Parse webhook data
  const webhookData = JSON.parse(payload);
  const eventType = webhookData.event_type;
  const data = webhookData.data;
  
  // Handle different event types
  switch (eventType) {
    case 'user.created':
      handleUserCreated(data);
      break;
    case 'user.login':
      handleUserLogin(data);
      break;
    case 'security.alert':
      handleSecurityAlert(data);
      break;
  }
  
  res.json({ status: 'success' });
});
'''
                }
            }
        }
    
    def generate_rate_limiting_guide(self) -> Dict[str, Any]:
        """Generate rate limiting guide."""
        return {
            'title': 'Rate Limiting',
            'description': 'Understanding API rate limits and how to handle them',
            'limits': {
                'global': {
                    'description': 'Global limits apply to all requests from an IP address',
                    'limits': [
                        '100 requests per minute per IP',
                        '1,000 requests per hour per IP'
                    ]
                },
                'api_key': {
                    'description': 'API key limits are configurable based on tier',
                    'basic': {
                        'minute': 60,
                        'hour': 1000,
                        'day': 10000
                    },
                    'premium': {
                        'minute': 120,
                        'hour': 5000,
                        'day': 50000
                    },
                    'enterprise': {
                        'minute': 300,
                        'hour': 20000,
                        'day': 200000
                    }
                },
                'endpoint_specific': {
                    'description': 'Some endpoints have additional limits',
                    'authentication': '10 requests per minute',
                    'admin': '30 requests per minute'
                }
            },
            'headers': {
                'description': 'Rate limit information is included in response headers',
                'headers': [
                    'X-Rate-Limit-Limit: Request limit',
                    'X-Rate-Limit-Remaining: Remaining requests',
                    'X-Rate-Limit-Reset: Reset timestamp'
                ]
            },
            'handling': {
                'description': 'Best practices for handling rate limits',
                'strategies': [
                    'Implement exponential backoff for retries',
                    'Monitor rate limit headers',
                    'Cache responses when possible',
                    'Use webhooks instead of polling',
                    'Distribute requests across time'
                ],
                'example': {
                    'python': '''import time
import random

def make_request_with_retry(client, method, *args, **kwargs):
    max_retries = 3
    base_delay = 1
    
    for attempt in range(max_retries):
        try:
            return getattr(client, method)(*args, **kwargs)
        except RateLimitError as e:
            if attempt == max_retries - 1:
                raise
            
            # Wait for the retry-after time plus some jitter
            delay = e.retry_after + random.uniform(0, 1)
            time.sleep(delay)
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            
            # Exponential backoff for other errors
            delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
            time.sleep(delay)
'''
                }
            }
        }
    
    def generate_error_handling_guide(self) -> Dict[str, Any]:
        """Generate error handling guide."""
        return {
            'title': 'Error Handling',
            'description': 'Understanding API errors and how to handle them',
            'error_format': {
                'description': 'All errors follow a consistent JSON format',
                'example': {
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'Invalid input data',
                        'details': {
                            'field': 'email',
                            'reason': 'invalid_format'
                        },
                        'request_id': 'req_123456789',
                        'timestamp': '2024-01-15T10:30:00Z'
                    }
                }
            },
            'status_codes': [
                {
                    'code': 400,
                    'name': 'Bad Request',
                    'description': 'Invalid request data or parameters',
                    'common_causes': [
                        'Missing required fields',
                        'Invalid field values',
                        'Malformed JSON'
                    ]
                },
                {
                    'code': 401,
                    'name': 'Unauthorized',
                    'description': 'Authentication failed',
                    'common_causes': [
                        'Missing or invalid API key',
                        'Expired JWT token',
                        'Invalid credentials'
                    ]
                },
                {
                    'code': 403,
                    'name': 'Forbidden',
                    'description': 'Insufficient permissions',
                    'common_causes': [
                        'API key lacks required scope',
                        'User lacks required permissions',
                        'Resource access denied'
                    ]
                },
                {
                    'code': 404,
                    'name': 'Not Found',
                    'description': 'Resource not found',
                    'common_causes': [
                        'Invalid resource ID',
                        'Resource deleted',
                        'Incorrect endpoint URL'
                    ]
                },
                {
                    'code': 429,
                    'name': 'Too Many Requests',
                    'description': 'Rate limit exceeded',
                    'common_causes': [
                        'Too many requests per minute',
                        'API key rate limit exceeded',
                        'Global rate limit exceeded'
                    ]
                },
                {
                    'code': 500,
                    'name': 'Internal Server Error',
                    'description': 'Server error occurred',
                    'common_causes': [
                        'Temporary server issue',
                        'Database connectivity problem',
                        'Unexpected error condition'
                    ]
                }
            ],
            'best_practices': [
                'Always check HTTP status codes',
                'Parse error responses for detailed information',
                'Implement appropriate retry logic',
                'Log errors with request IDs for debugging',
                'Handle network timeouts gracefully',
                'Provide meaningful error messages to users'
            ]
        }
    
    def generate_sdk_examples(self) -> Dict[str, Any]:
        """Generate SDK usage examples."""
        return {
            'title': 'SDK Examples',
            'description': 'Code examples using official SDKs',
            'python': {
                'installation': 'pip install enterpriseauth-sdk',
                'examples': [
                    {
                        'title': 'Basic Usage',
                        'code': '''from enterpriseauth import EnterpriseAuthClient

# Initialize client
client = EnterpriseAuthClient(api_key="your_api_key")

# Check API health
health = client.get_health_status()
print(f"API Status: {health.status}")

# List API keys
keys = client.list_api_keys(page_size=10)
for key in keys.results:
    print(f"Key: {key.name} - Usage: {key.usage_count}")
'''
                    },
                    {
                        'title': 'Webhook Management',
                        'code': '''# Create webhook
webhook = client.create_webhook(
    name="My Webhook",
    url="https://myapp.com/webhooks",
    subscribed_events=["user.created", "user.login"]
)

# Test webhook
result = client.test_webhook(webhook.id)
print(f"Test result: {result.message}")

# List webhook deliveries
deliveries = client.list_webhook_deliveries(
    endpoint_id=webhook.id,
    status="failed"
)
'''
                    }
                ]
            },
            'javascript': {
                'installation': 'npm install @enterpriseauth/sdk',
                'examples': [
                    {
                        'title': 'Basic Usage',
                        'code': '''import EnterpriseAuthClient from '@enterpriseauth/sdk';

// Initialize client
const client = new EnterpriseAuthClient({
  apiKey: 'your_api_key'
});

// Check API health
const health = await client.getHealthStatus();
console.log('API Status:', health.status);

// List API keys
const keys = await client.listApiKeys({ page_size: 10 });
keys.results.forEach(key => {
  console.log(`Key: ${key.name} - Usage: ${key.usage_count}`);
});
'''
                    },
                    {
                        'title': 'Error Handling',
                        'code': '''import { 
  EnterpriseAuthClient, 
  RateLimitError, 
  AuthenticationError 
} from '@enterpriseauth/sdk';

const client = new EnterpriseAuthClient({ apiKey: 'your_api_key' });

try {
  const apiKey = await client.createApiKey({
    name: 'Test Key',
    scopes: ['read_only']
  });
  console.log('Created:', apiKey.name);
} catch (error) {
  if (error instanceof RateLimitError) {
    console.log(`Rate limited. Retry after ${error.retryAfter} seconds`);
  } else if (error instanceof AuthenticationError) {
    console.log('Authentication failed:', error.message);
  } else {
    console.log('Error:', error.message);
  }
}
'''
                    }
                ]
            }
        }
    
    def generate_integration_examples(self) -> Dict[str, Any]:
        """Generate integration examples for different frameworks."""
        return {
            'title': 'Integration Examples',
            'description': 'Examples for integrating with popular frameworks',
            'frameworks': [
                {
                    'name': 'Django',
                    'description': 'Integration with Django applications',
                    'example': '''# settings.py
ENTERPRISEAUTH_API_KEY = 'your_api_key'

# middleware.py
from enterpriseauth import EnterpriseAuthClient
from django.conf import settings

class EnterpriseAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.client = EnterpriseAuthClient(
            api_key=settings.ENTERPRISEAUTH_API_KEY
        )
    
    def __call__(self, request):
        # Add client to request
        request.enterpriseauth = self.client
        response = self.get_response(request)
        return response

# views.py
def user_profile(request):
    # Use EnterpriseAuth client
    analytics = request.enterpriseauth.get_analytics(period='week')
    return render(request, 'profile.html', {'analytics': analytics})
'''
                },
                {
                    'name': 'Express.js',
                    'description': 'Integration with Express.js applications',
                    'example': '''const express = require('express');
const EnterpriseAuthClient = require('@enterpriseauth/sdk');

const app = express();
const authClient = new EnterpriseAuthClient({
  apiKey: process.env.ENTERPRISEAUTH_API_KEY
});

// Middleware to add client to request
app.use((req, res, next) => {
  req.enterpriseauth = authClient;
  next();
});

// Route using EnterpriseAuth
app.get('/api/analytics', async (req, res) => {
  try {
    const analytics = await req.enterpriseauth.getAnalytics({
      period: 'week'
    });
    res.json(analytics);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
'''
                },
                {
                    'name': 'React',
                    'description': 'Frontend integration with React',
                    'example': '''import React, { useState, useEffect } from 'react';
import EnterpriseAuthClient from '@enterpriseauth/sdk';

const client = new EnterpriseAuthClient({
  apiKey: process.env.REACT_APP_ENTERPRISEAUTH_API_KEY
});

function APIKeyManager() {
  const [apiKeys, setApiKeys] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchApiKeys() {
      try {
        const response = await client.listApiKeys();
        setApiKeys(response.results);
      } catch (error) {
        console.error('Failed to fetch API keys:', error);
      } finally {
        setLoading(false);
      }
    }

    fetchApiKeys();
  }, []);

  const createApiKey = async (keyData) => {
    try {
      const newKey = await client.createApiKey(keyData);
      setApiKeys([...apiKeys, newKey]);
    } catch (error) {
      console.error('Failed to create API key:', error);
    }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>API Keys</h2>
      {apiKeys.map(key => (
        <div key={key.id}>
          <h3>{key.name}</h3>
          <p>Usage: {key.usage_count} requests</p>
        </div>
      ))}
    </div>
  );
}
'''
                }
            ]
        }
    
    def generate_changelog(self) -> Dict[str, Any]:
        """Generate API changelog."""
        return {
            'title': 'API Changelog',
            'description': 'Version history and changes',
            'versions': [
                {
                    'version': '1.0.0',
                    'date': '2024-01-15',
                    'type': 'major',
                    'changes': [
                        'Initial API release',
                        'API key management endpoints',
                        'Webhook system implementation',
                        'Rate limiting and security features',
                        'Python and JavaScript SDKs',
                        'Comprehensive documentation'
                    ]
                }
            ]
        }
    
    # Helper methods
    
    def get_scope_description(self, scope: str) -> str:
        """Get description for API key scope."""
        descriptions = {
            'read_only': 'Read-only access to resources. Cannot create, update, or delete.',
            'read_write': 'Full read and write access to resources. Cannot access admin functions.',
            'admin': 'Full administrative access including user management and system configuration.',
            'webhook_only': 'Limited access for webhook-related operations only.'
        }
        return descriptions.get(scope, 'Unknown scope')
    
    def get_tier_description(self, tier: str) -> str:
        """Get description for API key tier."""
        descriptions = {
            'basic': 'Basic tier with standard rate limits and features.',
            'premium': 'Premium tier with higher rate limits and priority support.',
            'enterprise': 'Enterprise tier with highest limits and dedicated support.'
        }
        return descriptions.get(tier, 'Unknown tier')
    
    def get_tier_limits(self, tier: str) -> Dict[str, int]:
        """Get rate limits for API key tier."""
        limits = {
            'basic': {
                'requests_per_minute': 60,
                'requests_per_hour': 1000,
                'requests_per_day': 10000
            },
            'premium': {
                'requests_per_minute': 120,
                'requests_per_hour': 5000,
                'requests_per_day': 50000
            },
            'enterprise': {
                'requests_per_minute': 300,
                'requests_per_hour': 20000,
                'requests_per_day': 200000
            }
        }
        return limits.get(tier, {})
    
    def get_event_description(self, event_type: str) -> str:
        """Get description for webhook event type."""
        descriptions = {
            'user.created': 'Triggered when a new user account is created',
            'user.updated': 'Triggered when user profile information is updated',
            'user.deleted': 'Triggered when a user account is deleted',
            'user.login': 'Triggered when a user successfully logs in',
            'user.logout': 'Triggered when a user logs out',
            'user.password_changed': 'Triggered when a user changes their password',
            'user.email_verified': 'Triggered when a user verifies their email address',
            'user.mfa_enabled': 'Triggered when multi-factor authentication is enabled',
            'user.mfa_disabled': 'Triggered when multi-factor authentication is disabled',
            'session.created': 'Triggered when a new user session is created',
            'session.terminated': 'Triggered when a user session is terminated',
            'security.alert': 'Triggered when a security event is detected',
            'role.assigned': 'Triggered when a role is assigned to a user',
            'role.revoked': 'Triggered when a role is revoked from a user'
        }
        return descriptions.get(event_type, 'Unknown event type')
    
    def get_event_example_payload(self, event_type: str) -> Dict[str, Any]:
        """Get example payload for webhook event type."""
        examples = {
            'user.created': {
                'user_id': '123e4567-e89b-12d3-a456-426614174000',
                'email': 'user@example.com',
                'first_name': 'John',
                'last_name': 'Doe',
                'organization': 'Acme Corp',
                'department': 'Engineering',
                'is_email_verified': False,
                'timestamp': '2024-01-15T10:30:00Z'
            },
            'user.login': {
                'user_id': '123e4567-e89b-12d3-a456-426614174000',
                'login_method': 'password',
                'ip_address': '192.168.1.100',
                'user_agent': 'Mozilla/5.0...',
                'device_type': 'desktop',
                'location': {
                    'country': 'United States',
                    'city': 'San Francisco'
                },
                'mfa_used': True,
                'risk_score': 0.2,
                'timestamp': '2024-01-15T10:30:00Z'
            },
            'security.alert': {
                'alert_type': 'suspicious_login',
                'severity': 'high',
                'user_id': '123e4567-e89b-12d3-a456-426614174000',
                'ip_address': '192.168.1.100',
                'description': 'Login from unusual location',
                'threat_indicators': ['unusual_location', 'new_device'],
                'risk_score': 0.8,
                'response_taken': True,
                'timestamp': '2024-01-15T10:30:00Z'
            }
        }
        return examples.get(event_type, {
            'event_type': event_type,
            'timestamp': '2024-01-15T10:30:00Z',
            'data': 'Event-specific data here'
        })