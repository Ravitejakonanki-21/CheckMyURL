import requests

try:
    # Optional config integration
    from services.config import config
    DEFAULT_TIMEOUT = float(getattr(config, "REQUEST_TIMEOUT", 8.0))
except Exception:
    DEFAULT_TIMEOUT = 8.0


def check_headers(url: str, timeout: float | None = None):
    out = {
        "final_url": None,
        "status": None,
        "redirects": 0,
        "https_redirect": None,
        "security_headers": {
            "strict_transport_security": False,
            "content_security_policy": False,
            "x_content_type_options": False,
            "x_frame_options": False,
            "referrer_policy": False,
        },
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

        # Detect http -> https redirect
        if r.history:
            first = r.history[0].request.url
            out["https_redirect"] = first.startswith("http://") and r.url.startswith("https://")
        else:
            out["https_redirect"] = None

        h = {k.lower(): v for k, v in r.headers.items()}
        out["security_headers"]["strict_transport_security"] = "strict-transport-security" in h
        out["security_headers"]["content_security_policy"] = "content-security-policy" in h
        out["security_headers"]["x_content_type_options"] = h.get("x-content-type-options", "").lower() == "nosniff"
        out["security_headers"]["x_frame_options"] = "x-frame-options" in h
        out["security_headers"]["referrer_policy"] = "referrer-policy" in h

    except Exception as e:
        out["errors"].append(f"headers_error: {e}")
    return out
