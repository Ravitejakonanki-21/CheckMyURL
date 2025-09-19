def compute_risk(results: dict) -> tuple[int, str]:
    score = 0
    reasons = []

    ssl = results.get("ssl", {})
    whois = results.get("whois", {})
    idn = results.get("idn", {})
    rules = results.get("rules", {})

    # SSL
    if not ssl.get("https_ok"):
        score += 30; reasons.append("no_https")
    if ssl.get("expired"):
        score += 30; reasons.append("expired_cert")

    # WHOIS
    age_days = whois.get("age_days")
    if isinstance(age_days, int):
        if age_days < 30:
            score += 30; reasons.append("very_new_domain")
        elif age_days < 180:
            score += 15; reasons.append("new_domain")

    # IDN / Unicode
    if idn.get("is_idn"):
        score += 10; reasons.append("idn_domain")
    if idn.get("mixed_confusable_scripts"):
        score += 25; reasons.append("mixed_scripts")

    # Content rules
    if rules.get("has_suspicious_words"):
        score += 15; reasons.append("phishy_words")
    if rules.get("has_brand_words_in_host"):
        score += 20; reasons.append("brand_in_host")

    # Clamp 0..100
    score = max(0, min(100, score))

    if score >= 70:
        label = "High Risk"
    elif score >= 40:
        label = "Medium Risk"
    else:
        label = "Low Risk"

    return score, label, reasons
