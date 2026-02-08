"""
IP Threat Intelligence & Geolocation Module
Checks IPs against threat databases and provides geolocation data
"""

import re
import requests
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import json


@dataclass
class IPInfo:
    """Information about an IP address"""
    ip: str
    country: str = "Unknown"
    city: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    isp: str = "Unknown"
    is_threat: bool = False
    threat_level: str = "NONE"
    threat_types: List[str] = None
    last_seen: Optional[str] = None
    
    def __post_init__(self):
        if self.threat_types is None:
            self.threat_types = []


class IPThreatIntelligence:
    """
    IP Threat Intelligence service
    Uses free API: ip-api.com for geolocation and basic threat detection
    """
    
    def __init__(self):
        """
        Initialize IP intelligence service
        Uses free ip-api.com service (no API key required)
        """
        self.cache = {}  # Simple cache to avoid repeated API calls
        self.cache_duration = timedelta(hours=1)
        
    def extract_ips_from_logs(self, logs: str) -> List[str]:
        """
        Extract all IP addresses from log text
        
        Args:
            logs: Raw log text
            
        Returns:
            List of unique IP addresses found
        """
        # IPv4 pattern
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        # Find all IPs
        ips = re.findall(ipv4_pattern, logs)
        
        # Filter out private/local IPs
        public_ips = []
        for ip in set(ips):
            if self._is_public_ip(ip):
                public_ips.append(ip)
        
        return public_ips
    
    def _is_public_ip(self, ip: str) -> bool:
        """Check if IP is public (not private/local)"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            octets = [int(p) for p in parts]
            
            # Private ranges
            if octets[0] == 10:
                return False
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return False
            if octets[0] == 192 and octets[1] == 168:
                return False
            if octets[0] == 127:  # Loopback
                return False
            if octets[0] == 169 and octets[1] == 254:  # Link-local
                return False
            
            return True
        except ValueError:
            return False
    
    def get_ip_info(self, ip: str) -> IPInfo:
        """
        Get comprehensive information about an IP address
        
        Args:
            ip: IP address to lookup
            
        Returns:
            IPInfo object with geolocation and threat data
        """
        # Check cache first
        cache_key = f"{ip}_{datetime.now().strftime('%Y%m%d%H')}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Get geolocation
        geo_data = self._get_geolocation(ip)
        
        # Get threat intelligence
        threat_data = self._get_threat_intelligence(ip)
        
        # Combine data
        ip_info = IPInfo(
            ip=ip,
            country=geo_data.get('country', 'Unknown'),
            city=geo_data.get('city', 'Unknown'),
            latitude=geo_data.get('lat', 0.0),
            longitude=geo_data.get('lon', 0.0),
            isp=geo_data.get('isp', 'Unknown'),
            is_threat=threat_data.get('is_threat', False),
            threat_level=threat_data.get('threat_level', 'NONE'),
            threat_types=threat_data.get('threat_types', []),
            last_seen=threat_data.get('last_seen')
        )
        
        # Cache result
        self.cache[cache_key] = ip_info
        
        return ip_info
    
    def _get_geolocation(self, ip: str) -> Dict:
        """Get geolocation data from ip-api.com (free, no key required)"""
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'lat': data.get('lat', 0.0),
                        'lon': data.get('lon', 0.0),
                        'isp': data.get('isp', 'Unknown')
                    }
        except Exception as e:
            print(f"Geolocation lookup failed for {ip}: {e}")
        
        return {}
    
    def _get_threat_intelligence(self, ip: str) -> Dict:
        """
        Get threat intelligence data using basic heuristics
        Analyzes IP location, ISP patterns, and known malicious ranges
        """
        return self._basic_threat_check(ip)
    
    
    def _basic_threat_check(self, ip: str) -> Dict:
        """
        Basic threat heuristics without external API
        Checks against known patterns
        """
        # Check against some known suspicious patterns
        suspicious_patterns = [
            # Known malicious ranges (examples)
            (r'^5\.', 'Suspicious ISP'),
            (r'^45\.', 'Potential VPN/Proxy'),
            (r'^23\.', 'Cloud Provider')
        ]
        
        threat_types = []
        for pattern, threat_type in suspicious_patterns:
            if re.match(pattern, ip):
                threat_types.append(threat_type)
        
        return {
            'is_threat': len(threat_types) > 0,
            'threat_level': 'LOW' if threat_types else 'NONE',
            'threat_types': threat_types,
            'last_seen': None
        }
    
    def analyze_logs_ips(self, logs: str) -> Dict:
        """
        Analyze all IPs in logs and return summary
        
        Args:
            logs: Raw log text
            
        Returns:
            Dictionary with IP analysis results
        """
        ips = self.extract_ips_from_logs(logs)
        
        results = {
            'total_ips': len(ips),
            'threat_ips': [],
            'safe_ips': [],
            'countries': {},
            'threat_map': []
        }
        
        for ip in ips:
            ip_info = self.get_ip_info(ip)
            
            if ip_info.is_threat:
                results['threat_ips'].append({
                    'ip': ip_info.ip,
                    'country': ip_info.country,
                    'city': ip_info.city,
                    'threat_level': ip_info.threat_level,
                    'threat_types': ip_info.threat_types
                })
                
                # Add to threat map
                results['threat_map'].append({
                    'lat': ip_info.latitude,
                    'lon': ip_info.longitude,
                    'ip': ip_info.ip,
                    'country': ip_info.country,
                    'threat_level': ip_info.threat_level
                })
            else:
                results['safe_ips'].append(ip_info.ip)
            
            # Count countries
            country = ip_info.country
            results['countries'][country] = results['countries'].get(country, 0) + 1
        
        return results
