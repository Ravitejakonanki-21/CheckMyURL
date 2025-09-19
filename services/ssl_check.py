import ssl, socket
from datetime import datetime

def check_ssl(hostname: str, port: int = 443, timeout: float = 5.0):
    out = {
        "https_ok": False,
        "expires_on": None,
        "expired": None,
        "issuer_cn": None,
        "subject_cn": None,
        "self_signed_hint": None,
        "errors": []
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        out["https_ok"] = True

        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            out["expires_on"] = exp.isoformat() + "Z"
            out["expired"] = exp < datetime.utcnow()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        out["subject_cn"] = subject.get("commonName")
        out["issuer_cn"] = issuer.get("commonName")
        out["self_signed_hint"] = (out["subject_cn"] == out["issuer_cn"])
    except ssl.SSLCertVerificationError as e:
        out["errors"].append(f"cert_verify_error: {e}")
    except Exception as e:
        out["errors"].append(f"other_error: {e}")
    return out
