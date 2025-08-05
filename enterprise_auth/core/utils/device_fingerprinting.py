"""
Device fingerprinting utilities for session tracking.

This module provides comprehensive device fingerprinting capabilities
for binding sessions to specific devices and detecting device changes.
"""

import hashlib
import json
import re
from typing import Dict, Any, Optional, Tuple
from user_agents import parse as parse_user_agent
from django.http import HttpRequest


class DeviceFingerprinter:
    """
    Advanced device fingerprinting for session security.
    
    Generates unique device fingerprints based on multiple characteristics
    including user agent, screen resolution, timezone, and other browser features.
    """
    
    def __init__(self):
        self.weight_factors = {
            'user_agent': 0.3,
            'screen_resolution': 0.2,
            'timezone_offset': 0.15,
            'language': 0.1,
            'platform': 0.15,
            'browser_features': 0.1,
        }
    
    def generate_fingerprint(self, request: HttpRequest, additional_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a unique device fingerprint from request data.
        
        Args:
            request: Django HTTP request object
            additional_data: Additional fingerprinting data from client
            
        Returns:
            str: Unique device fingerprint hash
        """
        fingerprint_data = self._extract_fingerprint_data(request, additional_data or {})
        
        # Create a stable hash from the fingerprint data
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        return fingerprint_hash
    
    def _extract_fingerprint_data(self, request: HttpRequest, additional_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract fingerprinting data from request and additional client data.
        
        Args:
            request: Django HTTP request object
            additional_data: Additional data from client-side fingerprinting
            
        Returns:
            Dict containing fingerprint components
        """
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse_user_agent(user_agent_string)
        
        fingerprint_data = {
            # User agent components
            'browser_family': user_agent.browser.family,
            'browser_version': f"{user_agent.browser.version[0]}.{user_agent.browser.version[1]}" if len(user_agent.browser.version) >= 2 else str(user_agent.browser.version[0]) if user_agent.browser.version else '',
            'os_family': user_agent.os.family,
            'os_version': f"{user_agent.os.version[0]}.{user_agent.os.version[1]}" if len(user_agent.os.version) >= 2 else str(user_agent.os.version[0]) if user_agent.os.version else '',
            'device_family': user_agent.device.family,
            
            # HTTP headers
            'accept_language': request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
            'accept_encoding': request.META.get('HTTP_ACCEPT_ENCODING', ''),
            'accept': request.META.get('HTTP_ACCEPT', ''),
            
            # Client-provided data
            'screen_resolution': additional_data.get('screen_resolution', ''),
            'screen_color_depth': additional_data.get('screen_color_depth', ''),
            'timezone_offset': additional_data.get('timezone_offset', ''),
            'timezone': additional_data.get('timezone', ''),
            'language': additional_data.get('language', ''),
            'platform': additional_data.get('platform', ''),
            'cookie_enabled': additional_data.get('cookie_enabled', True),
            'local_storage': additional_data.get('local_storage', True),
            'session_storage': additional_data.get('session_storage', True),
            'webgl_vendor': additional_data.get('webgl_vendor', ''),
            'webgl_renderer': additional_data.get('webgl_renderer', ''),
            'canvas_fingerprint': additional_data.get('canvas_fingerprint', ''),
            'audio_fingerprint': additional_data.get('audio_fingerprint', ''),
            'fonts': additional_data.get('fonts', []),
            'plugins': additional_data.get('plugins', []),
        }
        
        # Normalize and clean the data
        return self._normalize_fingerprint_data(fingerprint_data)
    
    def _normalize_fingerprint_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize fingerprint data for consistent hashing.
        
        Args:
            data: Raw fingerprint data
            
        Returns:
            Normalized fingerprint data
        """
        normalized = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                # Normalize strings
                normalized[key] = value.lower().strip()
            elif isinstance(value, list):
                # Sort lists for consistency
                normalized[key] = sorted([str(item).lower().strip() for item in value])
            else:
                normalized[key] = value
        
        return normalized
    
    def extract_device_info(self, request: HttpRequest, additional_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Extract comprehensive device information for storage.
        
        Args:
            request: Django HTTP request object
            additional_data: Additional data from client-side detection
            
        Returns:
            Dict containing device information
        """
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse_user_agent(user_agent_string)
        additional_data = additional_data or {}
        
        # Determine device type
        device_type = self._determine_device_type(user_agent, additional_data)
        
        # Extract browser information
        browser_info = self._extract_browser_info(user_agent)
        
        # Extract OS information
        os_info = self._extract_os_info(user_agent)
        
        device_info = {
            'device_type': device_type,
            'browser': browser_info,
            'operating_system': os_info,
            'screen_resolution': additional_data.get('screen_resolution', ''),
            'timezone_offset': self._parse_timezone_offset(additional_data.get('timezone_offset')),
            'language': self._extract_primary_language(request.META.get('HTTP_ACCEPT_LANGUAGE', '')),
            'user_agent': user_agent_string,
            'device_characteristics': {
                'screen_color_depth': additional_data.get('screen_color_depth'),
                'timezone': additional_data.get('timezone'),
                'platform': additional_data.get('platform'),
                'cookie_enabled': additional_data.get('cookie_enabled'),
                'local_storage': additional_data.get('local_storage'),
                'session_storage': additional_data.get('session_storage'),
                'webgl_vendor': additional_data.get('webgl_vendor'),
                'webgl_renderer': additional_data.get('webgl_renderer'),
                'canvas_fingerprint': additional_data.get('canvas_fingerprint'),
                'audio_fingerprint': additional_data.get('audio_fingerprint'),
                'fonts_count': len(additional_data.get('fonts', [])),
                'plugins_count': len(additional_data.get('plugins', [])),
            }
        }
        
        return device_info
    
    def _determine_device_type(self, user_agent, additional_data: Dict[str, Any]) -> str:
        """
        Determine device type from user agent and additional data.
        
        Args:
            user_agent: Parsed user agent object
            additional_data: Additional client data
            
        Returns:
            Device type string
        """
        # Check for mobile devices
        if user_agent.is_mobile:
            return 'mobile'
        
        # Check for tablets
        if user_agent.is_tablet:
            return 'tablet'
        
        # Check for TV devices (user_agent library doesn't have is_tv)
        # We'll check the user agent string for TV indicators
        user_agent_string = additional_data.get('user_agent', '')
        if any(tv_indicator in user_agent_string.lower() for tv_indicator in ['smart-tv', 'smarttv', 'tv', 'roku', 'appletv']):
            return 'tv'
        
        # Check screen resolution for device type hints
        screen_resolution = additional_data.get('screen_resolution', '')
        if screen_resolution:
            try:
                width, height = map(int, screen_resolution.split('x'))
                
                # Typical mobile resolutions
                if max(width, height) <= 896 and min(width, height) <= 414:
                    return 'mobile'
                
                # Typical tablet resolutions
                elif max(width, height) <= 1366 and min(width, height) <= 1024:
                    return 'tablet'
                
                # Large screens (desktop/TV)
                elif max(width, height) >= 1920:
                    return 'desktop'
                
            except (ValueError, AttributeError):
                pass
        
        # Default to desktop for PC user agents
        if user_agent.is_pc:
            return 'desktop'
        
        return 'unknown'
    
    def _extract_browser_info(self, user_agent) -> str:
        """
        Extract formatted browser information.
        
        Args:
            user_agent: Parsed user agent object
            
        Returns:
            Formatted browser string
        """
        browser_name = user_agent.browser.family
        browser_version = '.'.join(str(v) for v in user_agent.browser.version[:2] if v is not None)
        
        if browser_version:
            return f"{browser_name} {browser_version}"
        return browser_name
    
    def _extract_os_info(self, user_agent) -> str:
        """
        Extract formatted operating system information.
        
        Args:
            user_agent: Parsed user agent object
            
        Returns:
            Formatted OS string
        """
        os_name = user_agent.os.family
        os_version = '.'.join(str(v) for v in user_agent.os.version[:2] if v is not None)
        
        if os_version:
            return f"{os_name} {os_version}"
        return os_name
    
    def _parse_timezone_offset(self, timezone_offset: Any) -> Optional[int]:
        """
        Parse timezone offset from client data.
        
        Args:
            timezone_offset: Timezone offset value
            
        Returns:
            Timezone offset in minutes or None
        """
        if timezone_offset is None:
            return None
        
        try:
            return int(timezone_offset)
        except (ValueError, TypeError):
            return None
    
    def _extract_primary_language(self, accept_language: str) -> str:
        """
        Extract primary language from Accept-Language header.
        
        Args:
            accept_language: Accept-Language header value
            
        Returns:
            Primary language code
        """
        if not accept_language:
            return ''
        
        # Parse Accept-Language header (e.g., "en-US,en;q=0.9,es;q=0.8")
        languages = []
        for lang_part in accept_language.split(','):
            lang_part = lang_part.strip()
            if ';' in lang_part:
                lang, quality = lang_part.split(';', 1)
                try:
                    q_value = float(quality.split('=')[1])
                except (IndexError, ValueError):
                    q_value = 1.0
            else:
                lang = lang_part
                q_value = 1.0
            
            languages.append((lang.strip(), q_value))
        
        # Sort by quality value and return the highest
        if languages:
            languages.sort(key=lambda x: x[1], reverse=True)
            return languages[0][0]
        
        return ''
    
    def calculate_fingerprint_similarity(self, fingerprint1: str, fingerprint2: str, 
                                       data1: Dict[str, Any], data2: Dict[str, Any]) -> float:
        """
        Calculate similarity between two device fingerprints.
        
        Args:
            fingerprint1: First fingerprint hash
            fingerprint2: Second fingerprint hash
            data1: First fingerprint data
            data2: Second fingerprint data
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        if fingerprint1 == fingerprint2:
            return 1.0
        
        # Calculate weighted similarity based on components
        total_weight = 0.0
        weighted_similarity = 0.0
        
        for component, weight in self.weight_factors.items():
            if component in data1 and component in data2:
                component_similarity = self._calculate_component_similarity(
                    data1[component], data2[component]
                )
                weighted_similarity += component_similarity * weight
                total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        return weighted_similarity / total_weight
    
    def _calculate_component_similarity(self, value1: Any, value2: Any) -> float:
        """
        Calculate similarity between two fingerprint components.
        
        Args:
            value1: First component value
            value2: Second component value
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        if value1 == value2:
            return 1.0
        
        if isinstance(value1, str) and isinstance(value2, str):
            # Use Levenshtein distance for strings
            return self._string_similarity(value1, value2)
        
        if isinstance(value1, list) and isinstance(value2, list):
            # Calculate Jaccard similarity for lists
            set1, set2 = set(value1), set(value2)
            intersection = len(set1.intersection(set2))
            union = len(set1.union(set2))
            return intersection / union if union > 0 else 0.0
        
        return 0.0
    
    def _string_similarity(self, s1: str, s2: str) -> float:
        """
        Calculate string similarity using Levenshtein distance.
        
        Args:
            s1: First string
            s2: Second string
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        if not s1 and not s2:
            return 1.0
        
        if not s1 or not s2:
            return 0.0
        
        # Simple Levenshtein distance implementation
        len1, len2 = len(s1), len(s2)
        
        if len1 < len2:
            s1, s2 = s2, s1
            len1, len2 = len2, len1
        
        if len2 == 0:
            return 0.0
        
        previous_row = list(range(len2 + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        distance = previous_row[-1]
        max_len = max(len1, len2)
        
        return 1.0 - (distance / max_len)


def generate_device_fingerprint(request: HttpRequest, additional_data: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Convenience function to generate device fingerprint and extract device info.
    
    Args:
        request: Django HTTP request object
        additional_data: Additional fingerprinting data from client
        
    Returns:
        Tuple of (fingerprint_hash, device_info_dict)
    """
    fingerprinter = DeviceFingerprinter()
    
    fingerprint = fingerprinter.generate_fingerprint(request, additional_data)
    device_info = fingerprinter.extract_device_info(request, additional_data)
    
    return fingerprint, device_info