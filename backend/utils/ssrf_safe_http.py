import ipaddress
import socket
from typing import Optional, Dict, Any

from urllib.parse import urlparse, urljoin

import requests


class SSRFBlockedError(Exception):
    pass


_METADATA_IPS = {
    "169.254.169.254",
    "169.254.169.250",
}

_BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
}


def _is_private_or_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def _resolve_host(hostname: str) -> list[str]:
    infos = socket.getaddrinfo(hostname, None)
    return list({info[4][0] for info in infos})


def _validate_target(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError("Unsupported URL scheme")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("Missing hostname")

    if hostname in _BLOCKED_HOSTNAMES:
        raise SSRFBlockedError("Blocked metadata hostname")

    ips = _resolve_host(hostname)
    for ip in ips:
        if ip in _METADATA_IPS or _is_private_or_internal(ip):
            raise SSRFBlockedError(f"Access to private/metadata IP {ip} blocked")


def safe_request(
    method: str,
    url: str,
    *,
    timeout: float = 5.0,
    max_redirects: int = 3,
    headers: Optional[Dict[str, str]] = None,
    **kwargs: Any,
) -> requests.Response:
    """
    SSRF-safe HTTP request wrapper.
    - Validates DNS resolution before each request.
    - Blocks private, loopback, link-local and metadata IP ranges.
    - Performs manual redirect handling with re-validation.
    """
    session = requests.Session()
    session.max_redirects = max_redirects
    current_url = url

    for _ in range(max_redirects + 1):
        _validate_target(current_url)
        resp = session.request(
            method=method.upper(),
            url=current_url,
            timeout=timeout,
            headers=headers,
            allow_redirects=False,
            **kwargs,
        )
        if 300 <= resp.status_code < 400 and "location" in resp.headers:
            location = resp.headers["location"]
            current_url = urljoin(current_url, location)
            continue
        return resp

    raise SSRFBlockedError("Too many redirects")

