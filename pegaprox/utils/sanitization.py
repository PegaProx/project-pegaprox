# -*- coding: utf-8 -*-
"""
PegaProx Input Sanitization - Layer 2
"""

import re
import html

# NS: split from monolith - these were scattered all over the place before


def sanitize_string(value: str, max_length: int = 1000, allow_html: bool = False) -> str:
    """sanitize string input, escape html by default"""
    if not isinstance(value, str):
        value = str(value) if value is not None else ''
    
    # Truncate to max length
    value = value[:max_length]
    
    # Strip null bytes and other control characters (0x0b = vertical tab, 0x0c = form feed)
    # MK: the regex looks scary but its just ASCII C0 control chars minus \t \n \r
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    
    # Escape HTML if not allowed
    if not allow_html:
        value = html.escape(value)
    
    return value.strip()


def sanitize_identifier(value: str, max_length: int = 64) -> str:
    """sanitize identifier - alphanumeric, underscore, hyphen, dot only"""
    if not isinstance(value, str):
        value = str(value) if value is not None else ''
    
    # Only allow safe characters
    value = re.sub(r'[^a-zA-Z0-9_\-\.]', '', value)
    
    return value[:max_length]


def sanitize_int(value, default: int = 0, min_val: int = None, max_val: int = None) -> int:
    """Sanitize an integer input"""
    try:
        result = int(value)
        if min_val is not None and result < min_val:
            result = min_val
        if max_val is not None and result > max_val:
            result = max_val
        return result
    except (ValueError, TypeError):
        return default


def sanitize_bool(value, default: bool = False) -> bool:
    """Sanitize a boolean input"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('true', '1', 'yes', 'on')
    if isinstance(value, int):
        return value != 0
    return default


def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False
    # Simple regex - not perfect but catches most issues
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_hostname(hostname: str) -> bool:
    """Validate hostname/IP format"""
    if not hostname or not isinstance(hostname, str):
        return False
    # Allow IP addresses and hostnames
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(ip_pattern, hostname) or re.match(hostname_pattern, hostname))


