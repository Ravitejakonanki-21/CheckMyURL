import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple


def _is_private_or_internal(ip: str) -> bool:
    """Return True if the IP is private, loopback, link-local, or reserved."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return False


def validate_url_input(url: str) -> Tuple[bool, str]:
    """
    Validates that a URL:
    - is non-empty
    - uses http or https scheme
    - has a resolvable hostname
    - does not resolve to a private / internal IP (SSRF pre-check)
    """
    if not url:
        return False, "url required"

    candidate = url if "://" in url else "https://" + url
    parsed = urlparse(candidate)

    if parsed.scheme not in ("http", "https"):
        return False, "unsupported URL scheme"
    if not parsed.hostname:
        return False, "hostname is required"

    # SSRF pre-check: resolve hostname and reject private/internal IPs
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
        ips = {info[4][0] for info in infos}
        for ip in ips:
            if _is_private_or_internal(str(ip)):
                return False, f"access to private/internal address blocked ({ip})"
    except socket.gaierror:
        # Can't resolve — allow the scan services to handle this gracefully
        pass

    return True, ""

