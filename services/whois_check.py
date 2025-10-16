import whois
from datetime import datetime
import tldextract

def check_whois(url: str):
    """
    Performs WHOIS lookup and risk assessment for the given URL.

    Args:
        url (str): The URL or domain to analyze.

    Returns:
        dict: WHOIS information and risk scoring with classification.
    """
    out = {
        "domain": None,
        "registrar": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "age_days": None,
        "privacy_protected": False,
        "registrant": None,
        "admin_email": None,
        "tech_email": None,
        "name_servers": [],
        "country": None,
        "statuses": [],
        "risk_score": 0,
        "classification": "Unknown",
        "risk_factors": [],
        "errors": []
    }

    def to_dt(v):
        # Convert input to a single datetime object or None
        if isinstance(v, list):
            valid_dates = [d for d in v if isinstance(d, datetime)]
            if valid_dates:
                return min(valid_dates)  # Take the earliest date if multiple
            else:
                return None
        return v if isinstance(v, datetime) else None

    try:
        # Extract the registrable domain from the URL
        ext = tldextract.extract(url)
        domain = ".".join(part for part in [ext.domain, ext.suffix] if part)
        out["domain"] = domain or url

        # Perform WHOIS lookup
        w = whois.whois(domain)

        # Extract important dates
        c = to_dt(w.creation_date)
        u = to_dt(w.updated_date)
        e = to_dt(w.expiration_date)

        # Populate date fields as ISO 8601 strings
        out["registrar"] = getattr(w, "registrar", None)
        out["creation_date"] = c.isoformat() + "Z" if c else None
        out["updated_date"] = u.isoformat() + "Z" if u else None
        out["expiration_date"] = e.isoformat() + "Z" if e else None

        # Domain age and risk scoring based on age
        if c:
            age_days = (datetime.utcnow() - c).days
            out["age_days"] = age_days
            if age_days < 30:
                out["risk_score"] += 40
                out["risk_factors"].append("Very new domain (< 30 days)")
            elif age_days < 90:
                out["risk_score"] += 25
                out["risk_factors"].append("Recently registered domain (< 90 days)")
            elif age_days < 365:
                out["risk_score"] += 10
                out["risk_factors"].append("Young domain (< 1 year)")

        # Privacy protection check in registrant string
        registrant = str(w.registrant) if getattr(w, "registrant", None) else ""
        out["privacy_protected"] = ('privacy' in registrant.lower()) or ('protected' in registrant.lower())
        if out["privacy_protected"]:
            out["risk_score"] += 15
            out["risk_factors"].append("WHOIS privacy protection enabled")

        # Contact info
        out["registrant"] = registrant
        out["admin_email"] = getattr(w, "admin_email", None)
        out["tech_email"] = getattr(w, "tech_email", None)

        # Registrar reputation check
        suspicious_registrars = [
            "namecheap", "tucows", "publicdomainregistry", "web.com"
        ]
        registrar_lower = (out["registrar"] or "").lower()
        if any(sus_reg in registrar_lower for sus_reg in suspicious_registrars):
            out["risk_score"] += 20
            out["risk_factors"].append("Registrar commonly used by malicious actors")

        # Registration period check
        if c and e:
            validity_period = (e - c).days
            if validity_period < 365:
                out["risk_score"] += 10
                out["risk_factors"].append("Short registration period (< 1 year)")

        # Name servers
        name_servers = getattr(w, "name_servers", None)
        if name_servers:
            if isinstance(name_servers, str):
                name_servers = [name_servers]
            out["name_servers"] = name_servers

        # Country and risk on high risk countries
        out["country"] = getattr(w, "country", None)
        high_risk_countries = ['CN', 'RU', 'PK', 'NG', 'RO']
        if out["country"] and out["country"].upper() in high_risk_countries:
            out["risk_score"] += 15
            out["risk_factors"].append(f"Registered in high-risk country: {out['country']}")

        # Domain statuses and suspicious status risk
        statuses = getattr(w, "status", [])
        if isinstance(statuses, str):
            statuses = [statuses]
        out["statuses"] = statuses

        suspicious_statuses = ['pendingDelete', 'clientHold', 'serverHold']
        for status in statuses:
            if any(sus in status.lower() for sus in suspicious_statuses):
                out["risk_score"] += 20
                out["risk_factors"].append(f"Suspicious domain status: {status}")

        # Classification based on accumulated risk score
        if out["risk_score"] >= 60:
            out["classification"] = "High Risk"
        elif out["risk_score"] >= 30:
            out["classification"] = "Suspicious"
        else:
            out["classification"] = "Low Risk"

    except Exception as ex:
        out["errors"].append(f"whois_error: {ex}")

    return out
