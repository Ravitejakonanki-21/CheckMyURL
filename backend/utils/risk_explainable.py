from typing import Dict, Any, List, Tuple

from services.risk_engine import compute_risk


def _score_ssl(ssl: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    if not ssl.get("https_ok"):
        score += 40
        reasons.append("SSL: no HTTPS")
    if ssl.get("expired"):
        score += 40
        reasons.append("SSL: certificate expired")
    if ssl.get("mismatched_hostname"):
        score += 30
        reasons.append("SSL: hostname mismatch")
    return min(score, 100), reasons


def _score_domain_age(whois: Dict[str, Any]) -> Tuple[int, List[str]]:
    age_days = whois.get("age_days")
    score = 0
    reasons: List[str] = []
    if isinstance(age_days, int):
        if age_days < 30:
            score = 90
            reasons.append("Domain age < 30 days")
        elif age_days < 180:
            score = 60
            reasons.append("Domain age < 6 months")
        elif age_days < 365:
            score = 40
            reasons.append("Domain age < 1 year")
    else:
        score = 30
        reasons.append("Domain age unknown")
    return score, reasons


def _score_keywords(keyword: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    if keyword.get("has_suspicious_words"):
        score += 60
        reasons.append("Contains phishing-related keywords")
    if keyword.get("has_brand_words_in_host"):
        score += 80
        reasons.append("Brand impersonation in hostname")
    return min(score, 100), reasons


def _score_headers(headers: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    missing = headers.get("missing_security_headers", [])
    if "Strict-Transport-Security" in missing:
        score += 20
        reasons.append("HSTS missing")
    if "Content-Security-Policy" in missing:
        score += 20
        reasons.append("CSP missing")
    if "X-Frame-Options" in missing:
        score += 10
        reasons.append("X-Frame-Options missing")
    return min(score, 100), reasons


def build_explainable_risk(
    results: Dict[str, Any], ml_output: Dict[str, Any] | None
) -> Dict[str, Any]:
    """
    Composite, explainable scoring model that combines:
    - SSL findings
    - WHOIS domain age
    - Keyword heuristics
    - HTTP security headers
    - ML probability
    """
    ssl_score, ssl_reasons = _score_ssl(results.get("ssl", {}))
    age_score, age_reasons = _score_domain_age(results.get("whois", {}))
    kw_score, kw_reasons = _score_keywords(results.get("keyword", {}))
    hdr_score, hdr_reasons = _score_headers(results.get("headers", {}))

    ml_prob = (ml_output or {}).get("probability", 0.0)
    ml_score = int(round(ml_prob * 100))
    ml_reasons = (ml_output or {}).get("reasons", [])

    weights = {
        "ssl": 0.2,
        "domain_age": 0.25,
        "keywords": 0.2,
        "headers": 0.15,
        "ml": 0.2,
    }

    total = int(
        round(
            weights["ssl"] * ssl_score
            + weights["domain_age"] * age_score
            + weights["keywords"] * kw_score
            + weights["headers"] * hdr_score
            + weights["ml"] * ml_score
        )
    )

    if total >= 90:
        severity = "CRITICAL"
    elif total >= 70:
        severity = "HIGH"
    elif total >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    reasons = ssl_reasons + age_reasons + kw_reasons + hdr_reasons + ml_reasons

    # Also expose the original heuristic engine as an additional view
    heuristic_score, heuristic_label, heuristic_reasons = compute_risk(results)

    return {
        "total_score": total,
        "severity_level": severity,
        "component_scores": {
            "ssl": ssl_score,
            "domain_age": age_score,
            "keywords": kw_score,
            "headers": hdr_score,
            "ml_probability": ml_score,
            "heuristic": heuristic_score,
        },
        "reasoning": reasons + heuristic_reasons,
        "heuristic": {
            "score": heuristic_score,
            "label": heuristic_label,
            "reasons": heuristic_reasons,
        },
    }

