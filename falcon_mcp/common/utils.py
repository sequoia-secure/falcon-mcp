"""
Common utility functions for Falcon MCP Server

This module provides common utility functions for the Falcon MCP server.
"""

import re
import unicodedata
from typing import Any, Optional

from .errors import _format_error_response, is_success_response
from .logging import get_logger

logger = get_logger(__name__)


def unwrap_field_default(value: Any) -> Any:
    """Resolve a Pydantic FieldInfo object to its actual default value."""
    return value.default if hasattr(value, "default") else value


def filter_none_values(data: dict[str, Any]) -> dict[str, Any]:
    """Remove None values from a dictionary.

    Args:
        data: Dictionary to filter

    Returns:
        Dict[str, Any]: Filtered dictionary
    """
    return {k: v for k, v in data.items() if v is not None}


def prepare_api_parameters(params: dict[str, Any]) -> dict[str, Any]:
    """Prepare parameters for Falcon API requests.

    Args:
        params: Raw parameters

    Returns:
        Dict[str, Any]: Prepared parameters
    """
    # Remove None values
    filtered = filter_none_values(params)

    return filtered


def extract_resources(
    response: dict[str, Any],
    default: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Extract resources from an API response.

    Args:
        response: API response dictionary
        default: Default value if no resources are found

    Returns:
        List[Dict[str, Any]]: Extracted resources
    """
    if not is_success_response(response):
        return default if default is not None else []

    resources = response.get("body", {}).get("resources", [])
    return resources if resources else (default if default is not None else [])


def extract_first_resource(
    response: dict[str, Any],
    operation: str,
    not_found_error: str = "Resource not found",
) -> dict[str, Any]:
    """Extract the first resource from an API response.

    Args:
        response: API response dictionary
        operation: The API operation that was performed
        not_found_error: Error message if no resources are found

    Returns:
        Dict[str, Any]: First resource or error response
    """
    resources = extract_resources(response)

    if not resources:
        return _format_error_response(not_found_error, operation=operation)

    return resources[0]


def sanitize_input(input_str: str) -> str:
    """Sanitize input string.

    Args:
        input_str: Input string to sanitize

    Returns:
        Sanitized string with dangerous characters removed
    """
    if not isinstance(input_str, str):
        return str(input_str)

    # Remove backslashes, quotes, and control characters that could be used for injection
    sanitized = re.sub(r'[\\"\'\n\r\t]', "", input_str)

    # Additional safety: limit length to prevent excessively long inputs
    return sanitized[:255]


# Characters that stop a value inside a single-quoted FQL literal from matching
# as plain data:
#   ' " \      close or escape the literal, exposing the rest as query grammar
#   * ?        glob inside the literal (see FQL_BASE_OPERATORS: 'partial*')
#   control    non-printables with no legitimate place in a literal
# FQL defines no escape sequence for string values, so a value containing one of
# these cannot be embedded safely in a composed filter.
_FQL_UNSAFE_LITERAL_CHARS = re.compile(r"['\"\\*?]|[\x00-\x1f\x7f]")


def is_safe_fql_literal(value: str) -> bool:
    """Report whether a value can be safely interpolated into a quoted FQL literal.

    Callers that build an FQL filter by interpolation (e.g. ``name:'{value}'``)
    must reject values this rejects. Two separate hazards are covered: a quote or
    backslash ends the literal early and lets the remaining text be parsed as
    query grammar, and a glob character widens the match from inside the literal.
    Either one changes which records the filter selects.

    Args:
        value: Value destined for interpolation into an FQL string literal

    Returns:
        bool: True if the value is safe to interpolate into a filter
    """
    if not isinstance(value, str):
        value = str(value)

    if _FQL_UNSAFE_LITERAL_CHARS.search(value):
        return False

    # A homoglyph such as U+FF07 FULLWIDTH APOSTROPHE is not itself a quote but
    # folds into one under NFKC, so reject anything that becomes unsafe if a
    # downstream consumer normalizes before parsing.
    return not _FQL_UNSAFE_LITERAL_CHARS.search(unicodedata.normalize("NFKC", value))


def generate_md_table(data: list[tuple]) -> str:
    """Generate a Markdown table from a list of tuples.

    This function creates a compact Markdown table with the provided data.
    It's designed to minimize token usage while maintaining readability.
    The first tuple contains headers, remaining tuples contain data rows.

    Args:
        data: List of tuples where the first tuple contains the headers
              and the remaining tuples contain the table data

    Returns:
        str: Formatted Markdown table as a string

    Raises:
        TypeError: If the first row (headers) contains non-string values
        TypeError: If there are not at least 2 items (header and a value row)
        ValueError: If the header row is empty
    """
    # Basic validation
    if not data or len(data) < 2:
        raise TypeError("Need at least 2 items. The header and a value row")

    # Extract and validate headers
    headers = data[0]
    if len(headers) == 0:
        raise ValueError("Header row cannot be empty")

    # Validate header types and clean them
    clean_headers = []
    for header in headers:
        if not isinstance(header, str):
            raise TypeError(f"Header values must be strings, got {type(header).__name__}")
        clean_headers.append(header.strip())

    # Build table structure
    lines = [
        "|" + "|".join(clean_headers) + "|",
        "|" + "|".join(["-"] * len(clean_headers)) + "|"
    ]

    # Process data rows
    for row in data[1:]:
        # Convert values to strings with consistent formatting
        row_values = []
        for value in row[:len(clean_headers)]:  # Truncate to header count
            if value is None:
                row_values.append("")
            elif isinstance(value, bool):
                row_values.append(str(value).lower())
            elif isinstance(value, (int, float)):
                row_values.append(str(value))
            else:
                # Handle multi-line strings by collapsing to single line
                text = str(value)
                clean_text = " ".join(line.strip() for line in text.split('\n') if line.strip())
                row_values.append(clean_text)

        # Pad row to match header count
        while len(row_values) < len(clean_headers):
            row_values.append("")

        lines.append("|" + "|".join(row_values) + "|")

    return "\n".join(lines)
