"""
Request helper utilities for enterprise authentication system.

This module provides utility functions for extracting information
from HTTP requests such as client IP addresses and user agents.
"""

from typing import Optional
from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> Optional[str]:
    """
    Get the client IP address from the request.
    
    Handles various proxy headers and forwarded IP scenarios.
    
    Args:
        request: Django HTTP request object
        
    Returns:
        Client IP address or None if not available
    """
    # Check for forwarded IP headers (in order of preference)
    forwarded_headers = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
    ]
    
    for header in forwarded_headers:
        ip = request.META.get(header)
        if ip:
            # X-Forwarded-For can contain multiple IPs, take the first one
            ip = ip.split(',')[0].strip()
            if ip and ip != 'unknown':
                return ip
    
    # Fall back to REMOTE_ADDR
    return request.META.get('REMOTE_ADDR')


def get_user_agent(request: HttpRequest) -> Optional[str]:
    """
    Get the user agent string from the request.
    
    Args:
        request: Django HTTP request object
        
    Returns:
        User agent string or None if not available
    """
    return request.META.get('HTTP_USER_AGENT')


def get_request_metadata(request: HttpRequest) -> dict:
    """
    Get comprehensive request metadata for logging and security analysis.
    
    Args:
        request: Django HTTP request object
        
    Returns:
        Dictionary containing request metadata
    """
    return {
        'ip_address': get_client_ip(request),
        'user_agent': get_user_agent(request),
        'method': request.method,
        'path': request.path,
        'query_string': request.META.get('QUERY_STRING', ''),
        'content_type': request.META.get('CONTENT_TYPE', ''),
        'content_length': request.META.get('CONTENT_LENGTH', ''),
        'host': request.META.get('HTTP_HOST', ''),
        'referer': request.META.get('HTTP_REFERER', ''),
        'accept': request.META.get('HTTP_ACCEPT', ''),
        'accept_language': request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        'accept_encoding': request.META.get('HTTP_ACCEPT_ENCODING', ''),
        'connection': request.META.get('HTTP_CONNECTION', ''),
        'x_requested_with': request.META.get('HTTP_X_REQUESTED_WITH', ''),
    }


def is_ajax_request(request: HttpRequest) -> bool:
    """
    Check if the request is an AJAX request.
    
    Args:
        request: Django HTTP request object
        
    Returns:
        True if request is AJAX, False otherwise
    """
    return (
        request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest' or
        request.META.get('CONTENT_TYPE', '').startswith('application/json')
    )


def get_device_info(request: HttpRequest) -> dict:
    """
    Extract device information from the request for device fingerprinting.
    
    Args:
        request: Django HTTP request object
        
    Returns:
        Dictionary containing device information
    """
    user_agent = get_user_agent(request) or ''
    
    # Basic device type detection
    device_type = 'desktop'
    if any(mobile in user_agent.lower() for mobile in ['mobile', 'android', 'iphone', 'ipad']):
        device_type = 'mobile'
    elif 'tablet' in user_agent.lower():
        device_type = 'tablet'
    
    # Basic browser detection
    browser = 'unknown'
    if 'chrome' in user_agent.lower():
        browser = 'chrome'
    elif 'firefox' in user_agent.lower():
        browser = 'firefox'
    elif 'safari' in user_agent.lower():
        browser = 'safari'
    elif 'edge' in user_agent.lower():
        browser = 'edge'
    elif 'opera' in user_agent.lower():
        browser = 'opera'
    
    # Basic OS detection
    operating_system = 'unknown'
    if 'windows' in user_agent.lower():
        operating_system = 'windows'
    elif 'mac' in user_agent.lower():
        operating_system = 'macos'
    elif 'linux' in user_agent.lower():
        operating_system = 'linux'
    elif 'android' in user_agent.lower():
        operating_system = 'android'
    elif 'ios' in user_agent.lower():
        operating_system = 'ios'
    
    return {
        'device_type': device_type,
        'browser': browser,
        'operating_system': operating_system,
        'user_agent': user_agent,
        'ip_address': get_client_ip(request),
        'accept_language': request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        'screen_resolution': request.META.get('HTTP_X_SCREEN_RESOLUTION', ''),
        'timezone': request.META.get('HTTP_X_TIMEZONE', ''),
    }