import requests

try:
    # Optional config integration
    from services.config import config
    DEFAULT_TIMEOUT = float(getattr(config, "REQUEST_TIMEOUT", 8.0))
except Exception:
    DEFAULT_TIMEOUT = 8.0

ESSENTIAL_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-resource-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "access-control-allow-origin",
    "x-xss-protection",
    "set-cookie",
    "cache-control",
    "expires",
    "pragma",
    "vary",
    "server",
    "date",
    "alt-svc",
    "accept-ch",
    "p3p",
]

def parse_security_headers(headers_dict):
    def header_val(header):
        return headers_dict.get(header, None)

    # Parse for all relevant security fields
    return {
        # Core Security Headers
        "Strict-Transport-Security": header_val("strict-transport-security"),
        "Content-Security-Policy": header_val("content-security-policy"),
        "Content-Security-Policy-Report-Only": header_val("content-security-policy-report-only"),
        "X-Content-Type-Options": header_val("x-content-type-options"),
        "X-Frame-Options": header_val("x-frame-options"),
        "Referrer-Policy": header_val("referrer-policy"),
        "Permissions-Policy": header_val("permissions-policy"),
        # CORS/Advanced Headers
        "Cross-Origin-Resource-Policy": header_val("cross-origin-resource-policy"),
        "Cross-Origin-Opener-Policy": header_val("cross-origin-opener-policy"),
        "Cross-Origin-Embedder-Policy": header_val("cross-origin-embedder-policy"),
        "Access-Control-Allow-Origin": header_val("access-control-allow-origin"),
        # Extra Security Indicators
        "X-XSS-Protection": header_val("x-xss-protection"),
        # Useful Metadata
        "Set-Cookie": header_val("set-cookie"),
        "Cache-Control": header_val("cache-control"),
        "Expires": header_val("expires"),
        "Pragma": header_val("pragma"),
        "Vary": header_val("vary"),
        "Server": header_val("server"),
        "Date": header_val("date"),
        # Transport/Protocol Info
        "Alt-Svc": header_val("alt-svc"),
        # Privacy
        "Accept-CH": header_val("accept-ch"),
        "P3P": header_val("p3p"),
    }

def check_headers(url: str, timeout: float | None = None):
    out = {
        "final_url": None,
        "status": None,
        "redirects": 0,
        "redirect_chain": [],  # Track entire redirect path
        "https_redirect": None,
        "security_headers": {},  # Expanded to full dict
        "all_headers": {},
        "errors": []
    }
    try:
        # Resolve timeout
        if timeout is None:
            timeout = DEFAULT_TIMEOUT

        # Ensure scheme, prefer https by default
        test_url = url if "://" in url else "https://" + url
        r = requests.get(test_url, timeout=timeout, allow_redirects=True)
        out["final_url"] = r.url
        out["status"] = r.status_code
        out["redirects"] = len(r.history)
        out["redirect_chain"] = [h.url for h in r.history] + [r.url]

        # Detect http -> https redirect
        if r.history:
            first = r.history[0].request.url
            out["https_redirect"] = first.startswith("http://") and r.url.startswith("https://")
        else:
            out["https_redirect"] = None

        # Lowercase the headers dictionary for case-insensitivity
        h = {k.lower(): v for k, v in r.headers.items()}
        out["security_headers"] = parse_security_headers(h)
        out["all_headers"] = h  # For completeness, include every header for full transparency

    except Exception as e:
        out["errors"].append(f"headers_error: {e}")
    return out
