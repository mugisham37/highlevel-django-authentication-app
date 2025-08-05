"""
EnterpriseAuth Python SDK Models

Data models for API responses.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime


class BaseModel:
    """Base model class with common functionality."""
    
    def __init__(self, data: Dict[str, Any]):
        self._data = data
        self._populate_attributes()
    
    def _populate_attributes(self):
        """Populate object attributes from data dictionary."""
        for key, value in self._data.items():
            # Convert datetime strings to datetime objects
            if key.endswith('_at') and isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass
            
            setattr(self, key, value)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BaseModel':
        """Create model instance from dictionary."""
        return cls(data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return self._data.copy()
    
    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f"{class_name}({self._data})"


class User(BaseModel):
    """User model."""
    
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        
        # User-specific attributes
        self.id: str = data.get('id', '')
        self.email: str = data.get('email', '')
        self.first_name: str = data.get('first_name', '')
        self.last_name: str = data.get('last_name', '')
        self.phone_number: Optional[str] = data.get('phone_number')
        self.is_email_verified: bool = data.get('is_email_verified', False)
        self.is_phone_verified: bool = data.get('is_phone_verified', False)
        self.organization: Optional[str] = data.get('organization')
        self.department: Optional[str] = data.get('department')
        self.employee_id: Optional[str] = data.get('employee_id')
        self.created_at: Optional[datetime] = None
        self.updated_at: Optional[datetime] = None
        
        # Convert datetime fields
        if 'created_at' in data:
            self.created_at = self._parse_datetime(data['created_at'])
        if 'updated_at' in data:
            self.updated_at = self._parse_datetime(data['updated_at'])
    
    @property
    def full_name(self) -> str:
        """Get user's full name."""
        return f"{self.first_name} {self.last_name}".strip()
    
    def _parse_datetime(self, dt_str: str) -> Optional[datetime]:
        """Parse datetime string."""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None


class APIKey(BaseModel):
    """API Key model."""
    
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        
        # API Key specific attributes
        self.id: str = data.get('id', '')
        self.name: str = data.get('name', '')
        self.description: str = data.get('description', '')
        self.key_id: str = data.get('key_id', '')
        self.key_prefix: str = data.get('key_prefix', '')
        self.generated_key: Optional[str] = data.get('generated_key')
        self.created_by: str = data.get('created_by', '')
        self.organization: Optional[str] = data.get('organization')
        self.scopes: List[str] = data.get('scopes', [])
        self.tier: str = data.get('tier', 'basic')
        self.allowed_ips: List[str] = data.get('allowed_ips', [])
        self.is_active: bool = data.get('is_active', True)
        self.expires_at: Optional[datetime] = None
        self.last_used_at: Optional[datetime] = None
        self.usage_count: int = data.get('usage_count', 0)
        self.rate_limit_per_minute: int = data.get('rate_limit_per_minute', 60)
        self.rate_limit_per_hour: int = data.get('rate_limit_per_hour', 1000)
        self.rate_limit_per_day: int = data.get('rate_limit_per_day', 10000)
        self.created_at: Optional[datetime] = None
        self.updated_at: Optional[datetime] = None
        
        # Convert datetime fields
        if 'expires_at' in data and data['expires_at']:
            self.expires_at = self._parse_datetime(data['expires_at'])
        if 'last_used_at' in data and data['last_used_at']:
            self.last_used_at = self._parse_datetime(data['last_used_at'])
        if 'created_at' in data:
            self.created_at = self._parse_datetime(data['created_at'])
        if 'updated_at' in data:
            self.updated_at = self._parse_datetime(data['updated_at'])
    
    @property
    def is_expired(self) -> bool:
        """Check if API key is expired."""
        if not self.expires_at:
            return False
        return datetime.now(self.expires_at.tzinfo) > self.expires_at
    
    @property
    def masked_key(self) -> str:
        """Get masked version of the API key."""
        return f"{self.key_prefix}...****"
    
    def _parse_datetime(self, dt_str: str) -> Optional[datetime]:
        """Parse datetime string."""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None


class WebhookEndpoint(BaseModel):
    """Webhook Endpoint model."""
    
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        
        # Webhook specific attributes
        self.id: str = data.get('id', '')
        self.name: str = data.get('name', '')
        self.description: str = data.get('description', '')
        self.url: str = data.get('url', '')
        self.secret_key: str = data.get('secret_key', '')
        self.verification_token: str = data.get('verification_token', '')
        self.created_by: str = data.get('created_by', '')
        self.organization: Optional[str] = data.get('organization')
        self.subscribed_events: List[str] = data.get('subscribed_events', [])
        self.headers: Dict[str, str] = data.get('headers', {})
        self.timeout_seconds: int = data.get('timeout_seconds', 30)
        self.max_retries: int = data.get('max_retries', 3)
        self.is_active: bool = data.get('is_active', True)
        self.is_verified: bool = data.get('is_verified', False)
        self.total_deliveries: int = data.get('total_deliveries', 0)
        self.successful_deliveries: int = data.get('successful_deliveries', 0)
        self.failed_deliveries: int = data.get('failed_deliveries', 0)
        self.success_rate: float = data.get('success_rate', 0.0)
        self.last_delivery_at: Optional[datetime] = None
        self.created_at: Optional[datetime] = None
        self.updated_at: Optional[datetime] = None
        
        # Convert datetime fields
        if 'last_delivery_at' in data and data['last_delivery_at']:
            self.last_delivery_at = self._parse_datetime(data['last_delivery_at'])
        if 'created_at' in data:
            self.created_at = self._parse_datetime(data['created_at'])
        if 'updated_at' in data:
            self.updated_at = self._parse_datetime(data['updated_at'])
    
    @property
    def event_count(self) -> int:
        """Get number of subscribed events."""
        return len(self.subscribed_events)
    
    def is_subscribed_to(self, event_type: str) -> bool:
        """Check if endpoint is subscribed to an event type."""
        return event_type in self.subscribed_events
    
    def _parse_datetime(self, dt_str: str) -> Optional[datetime]:
        """Parse datetime string."""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None


class WebhookDelivery(BaseModel):
    """Webhook Delivery model."""
    
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        
        # Delivery specific attributes
        self.id: str = data.get('id', '')
        self.endpoint_name: str = data.get('endpoint_name', '')
        self.endpoint_url: str = data.get('endpoint_url', '')
        self.event_type: str = data.get('event_type', '')
        self.event_id: str = data.get('event_id', '')
        self.status: str = data.get('status', 'pending')
        self.attempt_count: int = data.get('attempt_count', 0)
        self.max_attempts: int = data.get('max_attempts', 3)
        self.response_status_code: Optional[int] = data.get('response_status_code')
        self.response_headers: Dict[str, str] = data.get('response_headers', {})
        self.response_body: str = data.get('response_body', '')
        self.error_message: str = data.get('error_message', '')
        self.duration_ms: Optional[int] = data.get('duration_ms')
        self.is_retryable: bool = data.get('is_retryable', False)
        self.scheduled_at: Optional[datetime] = None
        self.first_attempted_at: Optional[datetime] = None
        self.last_attempted_at: Optional[datetime] = None
        self.delivered_at: Optional[datetime] = None
        self.next_retry_at: Optional[datetime] = None
        self.created_at: Optional[datetime] = None
        
        # Convert datetime fields
        datetime_fields = [
            'scheduled_at', 'first_attempted_at', 'last_attempted_at',
            'delivered_at', 'next_retry_at', 'created_at'
        ]
        for field in datetime_fields:
            if field in data and data[field]:
                setattr(self, field, self._parse_datetime(data[field]))
    
    @property
    def is_successful(self) -> bool:
        """Check if delivery was successful."""
        return self.status == 'delivered'
    
    @property
    def is_failed(self) -> bool:
        """Check if delivery failed."""
        return self.status in ['failed', 'abandoned']
    
    @property
    def is_pending(self) -> bool:
        """Check if delivery is pending."""
        return self.status in ['pending', 'retrying']
    
    def _parse_datetime(self, dt_str: str) -> Optional[datetime]:
        """Parse datetime string."""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None


class Session(BaseModel):
    """Session model."""
    
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        
        # Session specific attributes
        self.id: str = data.get('id', '')
        self.session_id: str = data.get('session_id', '')
        self.user_id: str = data.get('user_id', '')
        self.device_fingerprint: str = data.get('device_fingerprint', '')
        self.ip_address: str = data.get('ip_address', '')
        self.user_agent: str = data.get('user_agent', '')
        self.device_type: str = data.get('device_type', '')
        self.browser: str = data.get('browser', '')
        self.operating_system: str = data.get('operating_system', '')
        self.country: str = data.get('country', '')
        self.city: str = data.get('city', '')
        self.status: str = data.get('status', 'active')
        self.risk_score: float = data.get('risk_score', 0.0)
        self.is_trusted_device: bool = data.get('is_trusted_device', False)
        self.login_method: str = data.get('login_method', '')
        self.created_at: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None
        self.expires_at: Optional[datetime] = None
        
        # Convert datetime fields
        if 'created_at' in data:
            self.created_at = self._parse_datetime(data['created_at'])
        if 'last_activity' in data:
            self.last_activity = self._parse_datetime(data['last_activity'])
        if 'expires_at' in data:
            self.expires_at = self._parse_datetime(data['expires_at'])
    
    @property
    def is_active(self) -> bool:
        """Check if session is active."""
        return self.status == 'active'
    
    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        if not self.expires_at:
            return False
        return datetime.now(self.expires_at.tzinfo) > self.expires_at
    
    @property
    def location(self) -> str:
        """Get formatted location string."""
        if self.city and self.country:
            return f"{self.city}, {self.country}"
        elif self.country:
            return self.country
        else:
            return "Unknown"
    
    def _parse_datetime(self, dt_str: str) -> Optional[datetime]:
        """Parse datetime string."""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None


class PaginatedResponse:
    """Paginated response wrapper."""
    
    def __init__(self, data: Dict[str, Any], model_class: type):
        self.pagination = data.get('pagination', {})
        self.results = [
            model_class.from_dict(item) for item in data.get('results', [])
        ]
    
    @property
    def count(self) -> int:
        """Total number of items."""
        return self.pagination.get('count', 0)
    
    @property
    def next_page(self) -> Optional[str]:
        """URL for next page."""
        return self.pagination.get('next')
    
    @property
    def previous_page(self) -> Optional[str]:
        """URL for previous page."""
        return self.pagination.get('previous')
    
    @property
    def page_size(self) -> int:
        """Number of items per page."""
        return self.pagination.get('page_size', 20)
    
    @property
    def total_pages(self) -> int:
        """Total number of pages."""
        return self.pagination.get('total_pages', 1)
    
    @property
    def current_page(self) -> int:
        """Current page number."""
        return self.pagination.get('current_page', 1)
    
    def __iter__(self):
        """Iterate over results."""
        return iter(self.results)
    
    def __len__(self):
        """Get number of results in current page."""
        return len(self.results)
    
    def __getitem__(self, index):
        """Get result by index."""
        return self.results[index]