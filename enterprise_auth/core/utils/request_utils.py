"""
Request utilities for enterprise authentication system.

This module provides utilities for extracting information from
Django HTTP requests for audit logging and security purposes.
"""

import uuid
from typing import Dict, Any, Optional
from django.http import HttpRequest
from django.utils import timezone


def get_client_ip(request: HttpRequest) -> Optional[str]:
    """
    Get the client IP address from the request.
    
    This function checks various headers to find the real client IP,
    accounting for proxies and load balancers.
    
    Args:
        request: Django HTTP request
        
    Returns:
        Client IP address or None if not found
    """
    # Check for forwarded headers (common with load balancers)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the first IP in the chain
        return x_forwarded_for.split(',')[0].strip()
    
    # Check for real IP header (common with some proxies)
    x_real_ip = request.META.get('HTTP_X_REAL_IP')
    if x_real_ip:
        return x_real_ip.strip()
    
    # Check for Cloudflare connecting IP
    cf_connecting_ip = request.META.get('HTTP_CF_CONNECTING_IP')
    if cf_connecting_ip:
        return cf_connecting_ip.strip()
    
    # Fall back to remote address
    return request.META.get('REMOTE_ADDR')


def get_user_agent(request: HttpRequest) -> Optional[str]:
    """
    Get the user agent string from the request.
    
    Args:
        request: Django HTTP request
        
    Returns:
        User agent string or None if not found
    """
    return request.META.get('HTTP_USER_AGENT')


def get_request_id(request: HttpRequest) -> str:
    """
    Get or generate a unique request ID for correlation.
    
    This function first checks if a request ID already exists
    (set by middleware), and generates one if not found.
    
    Args:
        request: Django HTTP request
        
    Returns:
        Unique request ID
    """
    # Check if request ID was set by middleware
    request_id = getattr(request, 'request_id', None)
    if request_id:
        return request_id
    
    # Check headers for request ID
    request_id = request.META.get('HTTP_X_REQUEST_ID')
    if request_id:
        return request_id
    
    # Generate a new request ID
    request_id = str(uuid.uuid4())
    
    # Store it on the request for future use
    setattr(request, 'request_id', request_id)
    
    return request_id


def get_session_id(request: HttpRequest) -> Optional[str]:
    """
    Get the session ID from the request.
    
    Args:
        request: Django HTTP request
        
    Returns:
        Session ID or None if not found
    """
    if hasattr(request, 'session') and request.session.session_key:
        return request.session.session_key
    return None


def extract_request_info(request: HttpRequest) -> Dict[str, Any]:
    """
    Extract comprehensive request information for audit logging.
    
    This function extracts all relevant information from a Django
    HTTP request that might be useful for audit logging and security.
    
    Args:
        request: Django HTTP request
        
    Returns:
        Dictionary with request information
    """
    return {
        'ip_address': get_client_ip(request),
        'user_agent': get_user_agent(request),
        'request_id': get_request_id(request),
        'session_id': get_session_id(request),
        'method': request.method,
        'path': request.path,
        'timestamp': timezone.now().isoformat(),
        'is_secure': request.is_secure(),
        'host': request.get_host(),
        'referer': request.META.get('HTTP_REFERER'),
        'accept_language': request.META.get('HTTP_ACCEPT_LANGUAGE'),
        'content_type': request.META.get('CONTENT_TYPE'),
    }


def get_device_info(request: HttpRequest) -> Dict[str, Any]:
    """
    Extract device information from the request.
    
    This function attempts to parse the user agent string
    to extract device and browser information.
    
    Args:
        request: Django HTTP request
        
    Returns:
        Dictionary with device information
    """
    user_agent = get_user_agent(request) or ''
    
    # Basic device type detection
    device_type = 'desktop'
    if any(mobile in user_agent.lower() for mobile in ['mobile', 'android', 'iphone', 'ipad']):
        device_type = 'mobile'
    elif 'tablet' in user_agent.lower() or 'ipad' in user_agent.lower():
        device_type = 'tablet'
    
    # Basic browser detection
    browser = 'unknown'
    if 'chrome' in user_agent.lower():
        browser = 'chrome'
    elif 'firefox' in user_agent.lower():
        browser = 'firefox'
    elif 'safari' in user_agent.lower() and 'chrome' not in user_agent.lower():
        browser = 'safari'
    elif 'edge' in user_agent.lower():
        browser = 'edge'
    elif 'opera' in user_agent.lower():
        browser = 'opera'
    
    # Basic OS detection
    operating_system = 'unknown'
    if 'windows' in user_agent.lower():
        operating_system = 'windows'
    elif 'mac os' in user_agent.lower() or 'macos' in user_agent.lower():
        operating_system = 'macos'
    elif 'linux' in user_agent.lower():
        operating_system = 'linux'
    elif 'android' in user_agent.lower():
        operating_system = 'android'
    elif 'ios' in user_agent.lower() or 'iphone' in user_agent.lower() or 'ipad' in user_agent.lower():
        operating_system = 'ios'
    
    return {
        'device_type': device_type,
        'browser': browser,
        'operating_system': operating_system,
        'user_agent': user_agent,
    }


def create_device_fingerprint(request: HttpRequest) -> str:
    """
    Create a device fingerprint for session tracking.
    
    This function creates a semi-unique fingerprint based on
    request headers and other characteristics.
    
    Args:
        request: Django HTTP request
        
    Returns:
        Device fingerprint string
    """
    import hashlib
    
    # Collect fingerprinting data
    fingerprint_data = [
        get_user_agent(request) or '',
        request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        request.META.get('HTTP_ACCEPT_ENCODING', ''),
        request.META.get('HTTP_ACCEPT', ''),
        str(request.is_secure()),
    ]
    
    # Create hash of the fingerprint data
    fingerprint_string = '|'.join(fingerprint_data)
    fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    return fingerprint_hash[:32]  # Use first 32 characters


def is_request_from_trusted_source(request: HttpRequest) -> bool:
    """
    Check if the request is from a trusted source.
    
    This function checks various indicators to determine if
    the request is coming from a trusted source.
    
    Args:
        request: Django HTTP request
        
    Returns:
        True if request is from trusted source
    """
    # Check for internal network IPs
    client_ip = get_client_ip(request)
    if client_ip:
        # Check for localhost
        if client_ip in ['127.0.0.1', '::1']:
            return True
        
        # Check for private network ranges
        import ipaddress
        try:
            ip = ipaddress.ip_address(client_ip)
            if ip.is_private:
                return True
        except ValueError:
            pass
    
    # Check for trusted user agents (API clients, etc.)
    user_agent = get_user_agent(request) or ''
    trusted_agents = [
        'health-check',
        'monitoring',
        'load-balancer',
    ]
    
    if any(agent in user_agent.lower() for agent in trusted_agents):
        return True
    
    return False


def get_geolocation_info(request: HttpRequest) -> Dict[str, Any]:
    """
    Get geolocation information from request headers.
    
    This function extracts geolocation information that might
    be provided by CDNs or proxy services.
    
    Args:
        request: Django HTTP request
        
    Returns:
        Dictionary with geolocation information
    """
    return {
        'country': request.META.get('HTTP_CF_IPCOUNTRY'),  # Cloudflare
        'region': request.META.get('HTTP_CF_REGION'),      # Cloudflare
        'city': request.META.get('HTTP_CF_CITY'),          # Cloudflare
        'timezone': request.META.get('HTTP_CF_TIMEZONE'),  # Cloudflare
        'latitude': request.META.get('HTTP_X_LATITUDE'),   # Custom header
        'longitude': request.META.get('HTTP_X_LONGITUDE'), # Custom header
    }


def sanitize_request_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize request data for logging by removing sensitive information.
    
    Args:
        data: Request data dictionary
        
    Returns:
        Sanitized data dictionary
    """
    sensitive_fields = {
        'password',
        'password_confirm',
        'current_password',
        'new_password',
        'token',
        'secret',
        'key',
        'authorization',
        'cookie',
        'session',
    }
    
    sanitized = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_fields):
            sanitized[key] = '[REDACTED]'
        else:
            sanitized[key] = value
    
    return sanitized