"""
Geographic location enrichment utilities for session tracking.

This module provides IP geolocation capabilities for enriching session data
with geographic information including country, region, city, and coordinates.
"""

import logging
import requests
from typing import Dict, Any, Optional, Tuple
from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest
import ipaddress


logger = logging.getLogger(__name__)


class GeolocationService:
    """
    Service for enriching IP addresses with geographic location data.
    
    Supports multiple geolocation providers with fallback mechanisms
    and caching for performance optimization.
    """
    
    def __init__(self):
        self.cache_timeout = getattr(settings, 'GEOLOCATION_CACHE_TIMEOUT', 86400)  # 24 hours
        self.providers = self._get_configured_providers()
    
    def _get_configured_providers(self) -> list:
        """Get configured geolocation providers from settings."""
        providers = []
        
        # MaxMind GeoIP2 (if configured)
        if hasattr(settings, 'GEOIP_PATH'):
            providers.append('maxmind')
        
        # IP-API (free tier)
        providers.append('ipapi')
        
        # IPInfo (if API key configured)
        if getattr(settings, 'IPINFO_API_KEY', None):
            providers.append('ipinfo')
        
        # IPStack (if API key configured)
        if getattr(settings, 'IPSTACK_API_KEY', None):
            providers.append('ipstack')
        
        return providers
    
    def get_location_data(self, ip_address: str) -> Dict[str, Any]:
        """
        Get comprehensive location data for an IP address.
        
        Args:
            ip_address: IP address to geolocate
            
        Returns:
            Dict containing location data
        """
        # Check if IP is private/local
        if self._is_private_ip(ip_address):
            return self._get_default_location_data()
        
        # Check cache first
        cache_key = f"geolocation:{ip_address}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data
        
        # Try each provider until we get data
        location_data = None
        for provider in self.providers:
            try:
                location_data = self._get_location_from_provider(ip_address, provider)
                if location_data and location_data.get('country'):
                    break
            except Exception as e:
                logger.warning(f"Geolocation provider {provider} failed for IP {ip_address}: {e}")
                continue
        
        # Use default data if all providers failed
        if not location_data:
            location_data = self._get_default_location_data()
        
        # Cache the result
        cache.set(cache_key, location_data, self.cache_timeout)
        
        return location_data
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is private/local.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is private/local
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return True  # Invalid IP, treat as private
    
    def _get_location_from_provider(self, ip_address: str, provider: str) -> Optional[Dict[str, Any]]:
        """
        Get location data from a specific provider.
        
        Args:
            ip_address: IP address to geolocate
            provider: Provider name
            
        Returns:
            Location data dict or None
        """
        if provider == 'maxmind':
            return self._get_maxmind_location(ip_address)
        elif provider == 'ipapi':
            return self._get_ipapi_location(ip_address)
        elif provider == 'ipinfo':
            return self._get_ipinfo_location(ip_address)
        elif provider == 'ipstack':
            return self._get_ipstack_location(ip_address)
        
        return None
    
    def _get_maxmind_location(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get location data from MaxMind GeoIP2.
        
        Args:
            ip_address: IP address to geolocate
            
        Returns:
            Location data dict or None
        """
        try:
            from django.contrib.gis.geoip2 import GeoIP2
            
            g = GeoIP2()
            city_data = g.city(ip_address)
            country_data = g.country(ip_address)
            
            return {
                'country': country_data.get('country_name', ''),
                'country_code': country_data.get('country_code', ''),
                'region': city_data.get('region', ''),
                'city': city_data.get('city', ''),
                'latitude': city_data.get('latitude'),
                'longitude': city_data.get('longitude'),
                'timezone': city_data.get('time_zone', ''),
                'isp': '',  # MaxMind doesn't provide ISP in free version
                'provider': 'maxmind'
            }
        except Exception as e:
            logger.warning(f"MaxMind geolocation failed for {ip_address}: {e}")
            return None
    
    def _get_ipapi_location(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get location data from IP-API.
        
        Args:
            ip_address: IP address to geolocate
            
        Returns:
            Location data dict or None
        """
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'timezone': data.get('timezone', ''),
                    'isp': data.get('isp', ''),
                    'provider': 'ipapi'
                }
            
            return None
        except Exception as e:
            logger.warning(f"IP-API geolocation failed for {ip_address}: {e}")
            return None
    
    def _get_ipinfo_location(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get location data from IPInfo.
        
        Args:
            ip_address: IP address to geolocate
            
        Returns:
            Location data dict or None
        """
        try:
            api_key = getattr(settings, 'IPINFO_API_KEY')
            url = f"https://ipinfo.io/{ip_address}/json"
            
            headers = {}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
            
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse location coordinates
            latitude, longitude = None, None
            if 'loc' in data:
                try:
                    lat_str, lon_str = data['loc'].split(',')
                    latitude = float(lat_str)
                    longitude = float(lon_str)
                except (ValueError, AttributeError):
                    pass
            
            return {
                'country': data.get('country', ''),
                'country_code': data.get('country', ''),
                'region': data.get('region', ''),
                'city': data.get('city', ''),
                'latitude': latitude,
                'longitude': longitude,
                'timezone': data.get('timezone', ''),
                'isp': data.get('org', ''),
                'provider': 'ipinfo'
            }
        except Exception as e:
            logger.warning(f"IPInfo geolocation failed for {ip_address}: {e}")
            return None
    
    def _get_ipstack_location(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get location data from IPStack.
        
        Args:
            ip_address: IP address to geolocate
            
        Returns:
            Location data dict or None
        """
        try:
            api_key = getattr(settings, 'IPSTACK_API_KEY')
            url = f"http://api.ipstack.com/{ip_address}"
            
            params = {'access_key': api_key}
            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            
            if not data.get('error'):
                return {
                    'country': data.get('country_name', ''),
                    'country_code': data.get('country_code', ''),
                    'region': data.get('region_name', ''),
                    'city': data.get('city', ''),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'timezone': data.get('time_zone', {}).get('id', ''),
                    'isp': data.get('connection', {}).get('isp', ''),
                    'provider': 'ipstack'
                }
            
            return None
        except Exception as e:
            logger.warning(f"IPStack geolocation failed for {ip_address}: {e}")
            return None
    
    def _get_default_location_data(self) -> Dict[str, Any]:
        """
        Get default location data for private/unknown IPs.
        
        Returns:
            Default location data dict
        """
        return {
            'country': '',
            'country_code': '',
            'region': '',
            'city': '',
            'latitude': None,
            'longitude': None,
            'timezone': '',
            'isp': '',
            'provider': 'default'
        }
    
    def get_distance_between_locations(self, loc1: Dict[str, Any], loc2: Dict[str, Any]) -> Optional[float]:
        """
        Calculate distance between two locations in kilometers.
        
        Args:
            loc1: First location with latitude/longitude
            loc2: Second location with latitude/longitude
            
        Returns:
            Distance in kilometers or None if coordinates missing
        """
        if not all([
            loc1.get('latitude'), loc1.get('longitude'),
            loc2.get('latitude'), loc2.get('longitude')
        ]):
            return None
        
        from math import radians, sin, cos, sqrt, atan2
        
        # Convert to radians
        lat1 = radians(loc1['latitude'])
        lon1 = radians(loc1['longitude'])
        lat2 = radians(loc2['latitude'])
        lon2 = radians(loc2['longitude'])
        
        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        # Earth's radius in kilometers
        earth_radius = 6371
        distance = earth_radius * c
        
        return distance
    
    def is_location_anomaly(self, user_id: int, current_location: Dict[str, Any], 
                           time_threshold_hours: int = 24) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if current location is anomalous for the user.
        
        Args:
            user_id: User ID to check against
            current_location: Current location data
            time_threshold_hours: Hours to look back for comparison
            
        Returns:
            Tuple of (is_anomaly, anomaly_details)
        """
        from django.utils import timezone
        from datetime import timedelta
        from ..models.session import UserSession
        
        # Get recent sessions for comparison
        since = timezone.now() - timedelta(hours=time_threshold_hours)
        recent_sessions = UserSession.objects.filter(
            user_id=user_id,
            created_at__gte=since,
            latitude__isnull=False,
            longitude__isnull=False
        ).order_by('-created_at')[:10]  # Last 10 sessions with location
        
        if not recent_sessions:
            # No recent sessions to compare against
            return False, {}
        
        anomaly_details = {
            'new_country': False,
            'impossible_travel': False,
            'distance_km': None,
            'time_diff_hours': None,
            'max_speed_kmh': None
        }
        
        # Check for new country
        recent_countries = set(session.country for session in recent_sessions if session.country)
        if current_location.get('country') and current_location['country'] not in recent_countries:
            anomaly_details['new_country'] = True
        
        # Check for impossible travel (compare with most recent session)
        latest_session = recent_sessions[0]
        if latest_session.latitude and latest_session.longitude:
            latest_location = {
                'latitude': latest_session.latitude,
                'longitude': latest_session.longitude
            }
            
            distance = self.get_distance_between_locations(current_location, latest_location)
            if distance:
                time_diff = timezone.now() - latest_session.created_at
                time_diff_hours = time_diff.total_seconds() / 3600
                
                # Calculate required speed
                if time_diff_hours > 0:
                    required_speed = distance / time_diff_hours
                    
                    anomaly_details['distance_km'] = distance
                    anomaly_details['time_diff_hours'] = time_diff_hours
                    anomaly_details['max_speed_kmh'] = required_speed
                    
                    # Flag as impossible if speed > 1000 km/h (including flights)
                    if required_speed > 1000:
                        anomaly_details['impossible_travel'] = True
        
        # Determine if this is an anomaly
        is_anomaly = anomaly_details['new_country'] or anomaly_details['impossible_travel']
        
        return is_anomaly, anomaly_details


def get_client_ip(request: HttpRequest) -> str:
    """
    Extract client IP address from request, handling proxies and load balancers.
    
    Args:
        request: Django HTTP request object
        
    Returns:
        Client IP address string
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
        ip_list = request.META.get(header)
        if ip_list:
            # Take the first IP from comma-separated list
            ip = ip_list.split(',')[0].strip()
            if ip and _is_valid_ip(ip):
                return ip
    
    # Fall back to REMOTE_ADDR
    remote_addr = request.META.get('REMOTE_ADDR', '')
    if _is_valid_ip(remote_addr):
        return remote_addr
    
    return '127.0.0.1'  # Default fallback


def _is_valid_ip(ip: str) -> bool:
    """
    Check if string is a valid IP address.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def enrich_session_with_location(session_data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
    """
    Enrich session data with geographic location information.
    
    Args:
        session_data: Existing session data dict
        ip_address: IP address to geolocate
        
    Returns:
        Session data enriched with location information
    """
    geolocation_service = GeolocationService()
    location_data = geolocation_service.get_location_data(ip_address)
    
    # Merge location data into session data
    session_data.update({
        'country': location_data.get('country', ''),
        'region': location_data.get('region', ''),
        'city': location_data.get('city', ''),
        'latitude': location_data.get('latitude'),
        'longitude': location_data.get('longitude'),
        'isp': location_data.get('isp', ''),
    })
    
    return session_data