import whois
from datetime import datetime
import tldextract

def check_whois(url: str):
    out = {
        "domain": None,
        "registrar": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "age_days": None,
        "errors": []
    }
    try:
        # Normalize to registrable domain
        ext = tldextract.extract(url)
        domain = ".".join(part for part in [ext.domain, ext.suffix] if part)
        out["domain"] = domain or url

        w = whois.whois(domain)

        def to_dt(v):
            if isinstance(v, list):
                v = v[0]
            return v if isinstance(v, datetime) else None

        c = to_dt(w.creation_date)
        u = to_dt(w.updated_date)
        e = to_dt(w.expiration_date)

        out["registrar"] = getattr(w, "registrar", None)
        out["creation_date"] = c.isoformat() + "Z" if c else None
        out["updated_date"] = u.isoformat() + "Z" if u else None
        out["expiration_date"] = e.isoformat() + "Z" if e else None

        if c:
            out["age_days"] = (datetime.utcnow() - c).days
    except Exception as ex:
        out["errors"].append(f"whois_error: {ex}")
    return out
