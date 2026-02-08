"""
Log Pattern Learning Module
Learns normal patterns and detects anomalies based on historical data
"""

import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from collections import Counter, defaultdict
import hashlib


class PatternLearner:
    """
    Learns normal log patterns and identifies anomalies
    """
    
    def __init__(self, baseline_file: str = "data/pattern_baseline.json"):
        """
        Initialize pattern learner
        
        Args:
            baseline_file: File to store learned patterns
        """
        self.baseline_file = Path(baseline_file)
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.baseline = self._load_baseline()
        self.current_session_patterns = defaultdict(list)
    
    def _load_baseline(self) -> Dict:
        """Load existing baseline patterns"""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Failed to load baseline: {e}")
        
        # Default baseline structure
        return {
            'version': '1.0',
            'last_updated': datetime.now().isoformat(),
            'total_logs_analyzed': 0,
            'patterns': {
                'user_activity': {},
                'ip_addresses': {},
                'timestamps': {},
                'log_types': {},
                'resources': {},
                'custom_patterns': {}
            },
            'thresholds': {
                'rare_event_threshold': 0.05,  # 5% occurrence rate
                'anomaly_confidence': 0.70
            }
        }
    
    def _save_baseline(self):
        """Save baseline patterns to file"""
        try:
            self.baseline['last_updated'] = datetime.now().isoformat()
            with open(self.baseline_file, 'w') as f:
                json.dump(self.baseline, f, indent=2)
        except Exception as e:
            print(f"Failed to save baseline: {e}")
    
    def learn_from_logs(self, logs: str, is_clean: bool = False):
        """
        Learn patterns from log data
        
        Args:
            logs: Raw log text
            is_clean: If True, these logs are known to be threat-free
        """
        if not is_clean:
            print("Warning: Learning from potentially unsafe logs. Use is_clean=True for verified safe logs.")
        
        lines = logs.strip().split('\n')
        self.baseline['total_logs_analyzed'] += len(lines)
        
        for line in lines:
            if not line.strip():
                continue
            
            # Extract and learn patterns
            self._learn_users(line)
            self._learn_ips(line)
            self._learn_log_types(line)
            self._learn_resources(line)
            self._learn_time_patterns(line)
        
        self._save_baseline()
    
    def _learn_users(self, line: str):
        """Learn normal user patterns"""
        # Extract usernames
        user_patterns = [
            r'user[:\s]+(\w+)',
            r'User\s+(\w+)',
            r'from\s+user\s+(\w+)'
        ]
        
        for pattern in user_patterns:
            matches = re.findall(pattern, line, re.IGNORECASE)
            for user in matches:
                users = self.baseline['patterns']['user_activity']
                users[user] = users.get(user, 0) + 1
    
    def _learn_ips(self, line: str):
        """Learn normal IP patterns"""
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, line)
        
        for ip in ips:
            ip_data = self.baseline['patterns']['ip_addresses']
            ip_data[ip] = ip_data.get(ip, 0) + 1
    
    def _learn_log_types(self, line: str):
        """Learn normal log level distribution"""
        log_levels = ['INFO', 'WARNING', 'ERROR', 'CRITICAL', 'DEBUG', 'ALERT']
        
        for level in log_levels:
            if level in line.upper():
                log_types = self.baseline['patterns']['log_types']
                log_types[level] = log_types.get(level, 0) + 1
                break
    
    def _learn_resources(self, line: str):
        """Learn normal resource access patterns"""
        resource_patterns = [
            r'/([\w/]+)',  # File paths
            r'accessing\s+([\w]+)',
            r'resource[:\s]+([\w]+)'
        ]
        
        for pattern in resource_patterns:
            matches = re.findall(pattern, line, re.IGNORECASE)
            for resource in matches:
                if len(resource) > 3:  # Filter out very short matches
                    resources = self.baseline['patterns']['resources']
                    resources[resource] = resources.get(resource, 0) + 1
    
    def _learn_time_patterns(self, line: str):
        """Learn normal time-based patterns"""
        timestamp_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
        matches = re.findall(timestamp_pattern, line)
        
        for timestamp_str in matches:
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                hour = dt.hour
                day_of_week = dt.strftime('%A')
                
                timestamps = self.baseline['patterns']['timestamps']
                
                # Track hourly patterns
                hourly = timestamps.get('hourly', {})
                hourly[str(hour)] = hourly.get(str(hour), 0) + 1
                timestamps['hourly'] = hourly
                
                # Track daily patterns
                daily = timestamps.get('daily', {})
                daily[day_of_week] = daily.get(day_of_week, 0) + 1
                timestamps['daily'] = daily
            except ValueError:
                pass
    
    def detect_anomalies(self, logs: str) -> List[Dict[str, Any]]:
        """
        Detect anomalies based on learned patterns
        
        Args:
            logs: Raw log text to analyze
            
        Returns:
            List of detected anomalies
        """
        if self.baseline['total_logs_analyzed'] < 100:
            return [{
                'type': 'Insufficient Baseline',
                'description': 'Not enough historical data for pattern-based detection',
                'confidence': 0.0,
                'recommendation': 'Collect more baseline data from normal operations'
            }]
        
        anomalies = []
        lines = logs.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            # Check for rare users
            user_anomalies = self._check_rare_users(line, line_num)
            anomalies.extend(user_anomalies)
            
            # Check for new/unknown IPs
            ip_anomalies = self._check_unusual_ips(line, line_num)
            anomalies.extend(ip_anomalies)
            
            # Check for unusual time patterns
            time_anomalies = self._check_time_anomalies(line, line_num)
            anomalies.extend(time_anomalies)
            
            # Check for unusual resources
            resource_anomalies = self._check_unusual_resources(line, line_num)
            anomalies.extend(resource_anomalies)
        
        return anomalies
    
    def _check_rare_users(self, line: str, line_num: int) -> List[Dict]:
        """Check for rarely seen users"""
        anomalies = []
        user_patterns = [r'user[:\s]+(\w+)', r'User\s+(\w+)']
        
        total_user_events = sum(self.baseline['patterns']['user_activity'].values())
        if total_user_events == 0:
            return []
        
        for pattern in user_patterns:
            matches = re.findall(pattern, line, re.IGNORECASE)
            for user in matches:
                user_count = self.baseline['patterns']['user_activity'].get(user, 0)
                frequency = user_count / total_user_events
                
                threshold = self.baseline['thresholds']['rare_event_threshold']
                
                if frequency < threshold and user_count > 0:
                    anomalies.append({
                        'type': 'Unusual User Activity',
                        'description': f'Rarely seen user "{user}" (seen {user_count} times, {frequency:.1%} of activity)',
                        'line': line_num,
                        'confidence': 1 - frequency,
                        'recommendation': 'Verify this is a legitimate user account'
                    })
                elif user_count == 0:
                    anomalies.append({
                        'type': 'Unknown User',
                        'description': f'Never before seen user "{user}"',
                        'line': line_num,
                        'confidence': 0.85,
                        'recommendation': 'Investigate new user account activity'
                    })
        
        return anomalies
    
    def _check_unusual_ips(self, line: str, line_num: int) -> List[Dict]:
        """Check for new or rare IP addresses"""
        anomalies = []
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, line)
        
        total_ip_events = sum(self.baseline['patterns']['ip_addresses'].values())
        if total_ip_events == 0:
            return []
        
        for ip in ips:
            # Skip private IPs
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                continue
            
            ip_count = self.baseline['patterns']['ip_addresses'].get(ip, 0)
            
            if ip_count == 0:
                anomalies.append({
                    'type': 'New IP Address',
                    'description': f'Never before seen IP: {ip}',
                    'line': line_num,
                    'confidence': 0.75,
                    'recommendation': 'Check IP reputation and geolocation'
                })
        
        return anomalies
    
    def _check_time_anomalies(self, line: str, line_num: int) -> List[Dict]:
        """Check for unusual time-based activity"""
        anomalies = []
        timestamp_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
        matches = re.findall(timestamp_pattern, line)
        
        hourly_data = self.baseline['patterns']['timestamps'].get('hourly', {})
        if not hourly_data:
            return []
        
        total_events = sum(int(v) for v in hourly_data.values())
        
        for timestamp_str in matches:
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                hour = str(dt.hour)
                
                hour_count = int(hourly_data.get(hour, 0))
                frequency = hour_count / total_events if total_events > 0 else 0
                
                # Flag very low activity hours
                if frequency < 0.02 and hour_count > 0:  # Less than 2% of activity
                    anomalies.append({
                        'type': 'Unusual Time Activity',
                        'description': f'Activity at unusual hour {dt.hour}:00 ({frequency:.1%} of normal activity)',
                        'line': line_num,
                        'confidence': 0.65,
                        'recommendation': 'Verify this activity is authorized for this time period'
                    })
            except ValueError:
                pass
        
        return anomalies
    
    def _check_unusual_resources(self, line: str, line_num: int) -> List[Dict]:
        """Check for access to rarely accessed resources"""
        anomalies = []
        resource_patterns = [r'/([\w/]+)', r'accessing\s+([\w]+)']
        
        total_resource_events = sum(self.baseline['patterns']['resources'].values())
        if total_resource_events == 0:
            return []
        
        for pattern in resource_patterns:
            matches = re.findall(pattern, line, re.IGNORECASE)
            for resource in matches:
                if len(resource) < 4:
                    continue
                
                resource_count = self.baseline['patterns']['resources'].get(resource, 0)
                
                if resource_count == 0 and ('admin' in resource.lower() or 'config' in resource.lower()):
                    anomalies.append({
                        'type': 'Unusual Resource Access',
                        'description': f'Access to sensitive resource not seen before: {resource}',
                        'line': line_num,
                        'confidence': 0.80,
                        'recommendation': 'Verify authorization for this resource access'
                    })
        
        return anomalies
    
    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get summary of learned baseline"""
        return {
            'version': self.baseline['version'],
            'last_updated': self.baseline['last_updated'],
            'total_logs_analyzed': self.baseline['total_logs_analyzed'],
            'unique_users': len(self.baseline['patterns']['user_activity']),
            'unique_ips': len(self.baseline['patterns']['ip_addresses']),
            'unique_resources': len(self.baseline['patterns']['resources']),
            'log_type_distribution': self.baseline['patterns']['log_types']
        }
