"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.
"""
"""Security utilities for Label Studio.

This module provides functions for secure logging and data handling to prevent
common security vulnerabilities like log injection and sensitive data exposure.
"""
import re
from typing import Any, Optional


# Fields that are considered sensitive and should be masked in logs
SENSITIVE_FIELDS = frozenset({
    'password',
    'token',
    'api_key',
    'apikey',
    'secret',
    'credential',
    'auth',
    'authorization',
    'access_token',
    'refresh_token',
    'private_key',
    'secret_key',
})


def is_sensitive_field(field_name: str) -> bool:
    """Check if a field name indicates sensitive data.

    Args:
        field_name: The name of the field to check.

    Returns:
        True if the field name suggests it contains sensitive data.
    """
    field_lower = field_name.lower()
    return any(sensitive in field_lower for sensitive in SENSITIVE_FIELDS)


def mask_sensitive_value(value: str, visible_chars: int = 4) -> str:
    """Mask a sensitive value, keeping only a few characters visible.

    Args:
        value: The sensitive value to mask.
        visible_chars: Number of characters to keep visible at the end.

    Returns:
        The masked value with asterisks replacing hidden characters.
    """
    if not value or len(value) <= visible_chars:
        return '****'
    return '*' * (len(value) - visible_chars) + value[-visible_chars:]


def sanitize_for_logging(value: Any, max_length: int = 1000) -> str:
    """Sanitize a value for safe inclusion in log messages.

    This function prevents log injection attacks by:
    - Removing or escaping newline characters
    - Removing or escaping carriage returns
    - Truncating overly long values
    - Converting non-string values to safe string representations

    Args:
        value: The value to sanitize.
        max_length: Maximum length of the returned string.

    Returns:
        A sanitized string safe for logging.
    """
    if value is None:
        return 'None'

    # Convert to string if necessary
    str_value = str(value)

    # Remove or escape characters that could be used for log injection
    # Replace newlines and carriage returns with escaped versions
    str_value = str_value.replace('\r\n', '\\r\\n')
    str_value = str_value.replace('\n', '\\n')
    str_value = str_value.replace('\r', '\\r')

    # Remove ANSI escape sequences that could manipulate terminal output
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    str_value = ansi_escape.sub('', str_value)

    # Truncate if too long
    if len(str_value) > max_length:
        str_value = str_value[:max_length] + '...[truncated]'

    return str_value


def sanitize_log_input(value: Any) -> str:
    """Alias for sanitize_for_logging for backward compatibility.

    Args:
        value: The value to sanitize.

    Returns:
        A sanitized string safe for logging.
    """
    return sanitize_for_logging(value)


def get_safe_exception_message(exc: Exception, include_type: bool = True) -> str:
    """Get a safe error message from an exception without exposing internals.

    This function provides a generic error message that doesn't expose
    stack traces or internal implementation details to end users.

    Args:
        exc: The exception to get a message from.
        include_type: Whether to include the exception type name.

    Returns:
        A safe error message suitable for returning to users.
    """
    # Map of known exception types to user-friendly messages
    safe_messages = {
        'ConnectionError': 'Unable to connect to the external service.',
        'TimeoutError': 'The operation timed out.',
        'PermissionError': 'Permission denied.',
        'FileNotFoundError': 'The requested file was not found.',
        'ValidationError': 'The provided data is invalid.',
        'AuthenticationError': 'Authentication failed.',
    }

    exc_type = type(exc).__name__

    # Check if we have a safe message for this exception type
    if exc_type in safe_messages:
        return safe_messages[exc_type]

    # For other exceptions, return a generic message
    if include_type:
        return f'An error occurred ({exc_type}). Please try again or contact support.'
    return 'An error occurred. Please try again or contact support.'


def create_generic_error_response(detail: Optional[str] = None) -> dict:
    """Create a generic error response dictionary.

    Args:
        detail: Optional detail message. If not provided, a generic message is used.

    Returns:
        A dictionary suitable for use in API error responses.
    """
    return {
        'detail': detail or 'An internal error occurred. Please contact support if the issue persists.',
    }
