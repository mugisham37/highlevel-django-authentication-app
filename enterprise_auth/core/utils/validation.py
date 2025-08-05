"""
Validation utilities for request data and input validation.
"""

import json
import uuid
from typing import Any, Dict, Optional

from django.http import JsonResponse, HttpRequest
from django.core.exceptions import ValidationError


def validate_json_request(request: HttpRequest) -> Dict[str, Any]:
    """
    Validate and parse JSON request data.
    
    Args:
        request: Django HTTP request
        
    Returns:
        Dict: Parsed JSON data or JsonResponse with error
    """
    if request.content_type != 'application/json':
        return JsonResponse({
            'error': {
                'code': 'INVALID_CONTENT_TYPE',
                'message': 'Content-Type must be application/json'
            }
        }, status=400)
    
    try:
        data = json.loads(request.body)
        return data
    except json.JSONDecodeError as e:
        return JsonResponse({
            'error': {
                'code': 'INVALID_JSON',
                'message': f'Invalid JSON data: {str(e)}'
            }
        }, status=400)
    except UnicodeDecodeError:
        return JsonResponse({
            'error': {
                'code': 'INVALID_ENCODING',
                'message': 'Request body must be UTF-8 encoded'
            }
        }, status=400)


def validate_uuid(uuid_string: str) -> bool:
    """
    Validate UUID string format.
    
    Args:
        uuid_string: String to validate as UUID
        
    Returns:
        bool: True if valid UUID, False otherwise
    """
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False


def validate_email(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        bool: True if valid email, False otherwise
    """
    import re
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_required_fields(data: Dict[str, Any], required_fields: list) -> Optional[JsonResponse]:
    """
    Validate that required fields are present in data.
    
    Args:
        data: Dictionary to validate
        required_fields: List of required field names
        
    Returns:
        JsonResponse: Error response if validation fails, None if valid
    """
    missing_fields = [field for field in required_fields if field not in data or data[field] is None]
    
    if missing_fields:
        return JsonResponse({
            'error': {
                'code': 'MISSING_FIELDS',
                'message': f'Missing required fields: {", ".join(missing_fields)}',
                'details': {
                    'missing_fields': missing_fields,
                    'required_fields': required_fields
                }
            }
        }, status=400)
    
    return None


def validate_field_types(data: Dict[str, Any], field_types: Dict[str, type]) -> Optional[JsonResponse]:
    """
    Validate field types in data dictionary.
    
    Args:
        data: Dictionary to validate
        field_types: Dictionary mapping field names to expected types
        
    Returns:
        JsonResponse: Error response if validation fails, None if valid
    """
    type_errors = []
    
    for field, expected_type in field_types.items():
        if field in data and not isinstance(data[field], expected_type):
            type_errors.append({
                'field': field,
                'expected_type': expected_type.__name__,
                'actual_type': type(data[field]).__name__
            })
    
    if type_errors:
        return JsonResponse({
            'error': {
                'code': 'INVALID_FIELD_TYPES',
                'message': 'Invalid field types',
                'details': {
                    'type_errors': type_errors
                }
            }
        }, status=400)
    
    return None


def validate_string_length(value: str, min_length: int = 0, max_length: int = None) -> bool:
    """
    Validate string length constraints.
    
    Args:
        value: String to validate
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not isinstance(value, str):
        return False
    
    if len(value) < min_length:
        return False
    
    if max_length is not None and len(value) > max_length:
        return False
    
    return True


def validate_choice(value: Any, choices: list) -> bool:
    """
    Validate that value is in allowed choices.
    
    Args:
        value: Value to validate
        choices: List of allowed choices
        
    Returns:
        bool: True if valid choice, False otherwise
    """
    return value in choices


def sanitize_string(value: str, max_length: int = None) -> str:
    """
    Sanitize string input by stripping whitespace and limiting length.
    
    Args:
        value: String to sanitize
        max_length: Maximum allowed length
        
    Returns:
        str: Sanitized string
    """
    if not isinstance(value, str):
        return str(value)
    
    # Strip whitespace
    sanitized = value.strip()
    
    # Limit length if specified
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized


def validate_pagination_params(request: HttpRequest) -> Dict[str, int]:
    """
    Validate and extract pagination parameters from request.
    
    Args:
        request: Django HTTP request
        
    Returns:
        Dict: Dictionary with 'page' and 'page_size' keys
    """
    try:
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 20))
        
        # Validate ranges
        page = max(1, page)
        page_size = max(1, min(page_size, 100))  # Limit to 100 items per page
        
        return {
            'page': page,
            'page_size': page_size
        }
    except (ValueError, TypeError):
        return {
            'page': 1,
            'page_size': 20
        }


def validate_date_range(start_date: str, end_date: str) -> Optional[JsonResponse]:
    """
    Validate date range parameters.
    
    Args:
        start_date: Start date string (ISO format)
        end_date: End date string (ISO format)
        
    Returns:
        JsonResponse: Error response if validation fails, None if valid
    """
    from datetime import datetime
    
    try:
        start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        
        if start >= end:
            return JsonResponse({
                'error': {
                    'code': 'INVALID_DATE_RANGE',
                    'message': 'Start date must be before end date'
                }
            }, status=400)
        
        return None
        
    except (ValueError, AttributeError):
        return JsonResponse({
            'error': {
                'code': 'INVALID_DATE_FORMAT',
                'message': 'Invalid date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)'
            }
        }, status=400)