#!/usr/bin/env python3
"""
GeoIP lookup module for IP address location
Uses free GeoIP services as fallback
"""

import os
import json
import logging
import requests
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Cache for IP lookups
_ip_cache = {}


def get_ip_location(ip_address: str) -> Dict[str, any]:
    """
    Get location information for an IP address
    Returns dict with country, city, isp, etc.
    """
    # Skip local/private IPs
    if ip_address in ['127.0.0.1', 'localhost', '::1'] or ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.'):
        return {
            'country': 'Local',
            'city': 'Local Network',
            'isp': 'Private Network',
            'country_code': 'LOCAL',
            'latitude': None,
            'longitude': None
        }
    
    # Check cache first
    if ip_address in _ip_cache:
        return _ip_cache[ip_address]
    
    location_info = {
        'country': 'Unknown',
        'city': 'Unknown',
        'isp': 'Unknown',
        'country_code': 'XX',
        'latitude': None,
        'longitude': None
    }
    
    # Try multiple free GeoIP services
    services = [
        _lookup_ipapi,
        _lookup_ipapi_co,
        _lookup_geojs
    ]
    
    for service in services:
        try:
            result = service(ip_address)
            if result and result.get('country') != 'Unknown':
                location_info = result
                break
        except Exception as e:
            logger.debug(f"GeoIP lookup failed with {service.__name__}: {e}")
            continue
    
    # Cache the result
    _ip_cache[ip_address] = location_info
    return location_info


def _lookup_ipapi(ip: str) -> Optional[Dict]:
    """Lookup using ip-api.com (free, no API key needed)"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'country_code': data.get('countryCode', 'XX'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'region': data.get('regionName', ''),
                    'timezone': data.get('timezone', '')
                }
    except:
        pass
    return None


def _lookup_ipapi_co(ip: str) -> Optional[Dict]:
    """Lookup using ipapi.co (free tier)"""
    try:
        response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if not data.get('error'):
                return {
                    'country': data.get('country_name', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'country_code': data.get('country_code', 'XX'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'region': data.get('region', ''),
                    'timezone': data.get('timezone', '')
                }
    except:
        pass
    return None


def _lookup_geojs(ip: str) -> Optional[Dict]:
    """Lookup using geojs.io (free, no API key)"""
    try:
        response = requests.get(f'https://get.geojs.io/v1/ip/geo/{ip}.json', timeout=3)
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('organization', 'Unknown'),
                'country_code': data.get('country_code', 'XX'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'region': data.get('region', ''),
                'timezone': data.get('timezone', '')
            }
    except:
        pass
    return None


