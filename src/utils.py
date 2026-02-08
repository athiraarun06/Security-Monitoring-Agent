"""
Utility functions for Security Monitoring Agent
Helper functions for log parsing, formatting, and data processing
"""

import re
from typing import Dict, List, Any, Optional
from datetime import datetime


def parse_log_entry(log_line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single log entry into structured format
    
    Args:
        log_line: Single line from log file
        
    Returns:
        Dictionary with parsed log components or None if invalid
    """
    # Common log format: YYYY-MM-DD HH:MM:SS LEVEL Message
    pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.*)'
    match = re.match(pattern, log_line.strip())
    
    if match:
        timestamp, level, message = match.groups()
        return {
            'timestamp': timestamp,
            'level': level.upper(),
            'message': message,
            'raw': log_line.strip()
        }
    return None


def format_log_for_display(logs: List[Dict[str, Any]]) -> str:
    """
    Format parsed logs for display
    
    Args:
        logs: List of parsed log dictionaries
        
    Returns:
        Formatted string representation
    """
    formatted = []
    for log in logs:
        formatted.append(
            f"[{log['timestamp']}] {log['level']}: {log['message']}"
        )
    return "\n".join(formatted)


def extract_ips(text: str) -> List[str]:
    """
    Extract all IP addresses from text
    
    Args:
        text: Text containing IP addresses
        
    Returns:
        List of unique IP addresses
    """
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    return list(set(ips))


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private/internal
    
    Args:
        ip: IP address string
        
    Returns:
        True if private IP, False otherwise
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        first = int(parts[0])
        second = int(parts[1])
        
        # Check private ranges
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:  # Localhost
            return True
            
        return False
    except ValueError:
        return False


def truncate_text(text: str, max_length: int = 100) -> str:
    """
    Truncate text to maximum length with ellipsis
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."


def calculate_percentage(part: float, whole: float) -> float:
    """
    Calculate percentage safely
    
    Args:
        part: Numerator
        whole: Denominator
        
    Returns:
        Percentage (0-100)
    """
    if whole == 0:
        return 0.0
    return round((part / whole) * 100, 2)


def format_bytes(bytes_count: int) -> str:
    """
    Format byte count to human-readable format
    
    Args:
        bytes_count: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def get_timestamp() -> str:
    """
    Get current timestamp in standard format
    
    Returns:
        ISO format timestamp string
    """
    return datetime.now().isoformat()


def sanitize_filename(filename: str) -> str:
    """
    Remove unsafe characters from filename
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove unsafe characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    safe = safe.strip('. ')
    return safe or 'unnamed'
