"""
Helper Utilities for WebAudit.

Common functions used across modules.
"""

from __future__ import annotations

import re
import time
import functools
from typing import Any, Callable
from urllib.parse import urljoin, urlparse, urlunparse

from utils.logger import get_logger

logger = get_logger("helpers")


def normalize_url(url: str) -> str:
    """Normalize a URL by removing trailing slashes and fragments."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        parsed.params,
        parsed.query,
        "",  # Remove fragment
    ))
    return normalized


def build_url(base: str, path: str) -> str:
    """Build a full URL from base and path."""
    if not base.endswith("/"):
        base += "/"
    return urljoin(base, path.lstrip("/"))


def is_same_domain(url: str, base_url: str) -> bool:
    """Check if a URL belongs to the same domain as the base URL."""
    return urlparse(url).netloc == urlparse(base_url).netloc


def is_valid_url(url: str) -> bool:
    """Check if a URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def extract_domain(url: str) -> str:
    """Extract the domain from a URL."""
    return urlparse(url).netloc


def timing_decorator(func: Callable) -> Callable:
    """Decorator to measure function execution time."""
    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs) -> Any:
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        logger.debug(f"{func.__name__} completed in {elapsed:.1f}ms")
        return result

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs) -> Any:
        start = time.perf_counter()
        result = await func(*args, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        logger.debug(f"{func.__name__} completed in {elapsed:.1f}ms")
        return result

    import asyncio
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    return sync_wrapper


def truncate(text: str, max_length: int = 200) -> str:
    """Truncate text to a maximum length."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def sanitize_filename(name: str) -> str:
    """Sanitize a string to be used as a filename."""
    return re.sub(r'[<>:"/\\|?*]', "_", name).strip()


def bytes_to_human(size_bytes: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def ms_to_human(ms: float) -> str:
    """Convert milliseconds to human-readable format."""
    if ms < 1000:
        return f"{ms:.0f}ms"
    elif ms < 60000:
        return f"{ms / 1000:.1f}s"
    else:
        return f"{ms / 60000:.1f}min"


def extract_emails(text: str) -> list[str]:
    """Extract email addresses from text."""
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text)))


def extract_urls_from_text(text: str) -> list[str]:
    """Extract URLs from text."""
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return list(set(re.findall(pattern, text)))


def calculate_contrast_ratio(color1: tuple[int, int, int], color2: tuple[int, int, int]) -> float:
    """
    Calculate WCAG contrast ratio between two RGB colors.

    Returns a value between 1 and 21.
    """
    def relative_luminance(rgb: tuple[int, int, int]) -> float:
        srgb = [c / 255.0 for c in rgb]
        linear = []
        for c in srgb:
            if c <= 0.03928:
                linear.append(c / 12.92)
            else:
                linear.append(((c + 0.055) / 1.055) ** 2.4)
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    l1 = relative_luminance(color1)
    l2 = relative_luminance(color2)

    lighter = max(l1, l2)
    darker = min(l1, l2)

    return (lighter + 0.05) / (darker + 0.05)


def parse_color(color_str: str) -> tuple[int, int, int] | None:
    """Parse a CSS color string to RGB tuple."""
    color_str = color_str.strip().lower()

    # Hex color
    hex_match = re.match(r'^#([0-9a-f]{3,8})$', color_str)
    if hex_match:
        hex_val = hex_match.group(1)
        if len(hex_val) == 3:
            return tuple(int(c * 2, 16) for c in hex_val)  # type: ignore
        elif len(hex_val) >= 6:
            return (int(hex_val[0:2], 16), int(hex_val[2:4], 16), int(hex_val[4:6], 16))

    # rgb() / rgba()
    rgb_match = re.match(r'rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)', color_str)
    if rgb_match:
        return (int(rgb_match.group(1)), int(rgb_match.group(2)), int(rgb_match.group(3)))

    return None
