import ipaddress
import json
import os
import re
from functools import lru_cache
from urllib.parse import parse_qs, urlparse

import joblib
import numpy as np

MODEL_FILENAME = "phishing_rf_production.pkl"
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", MODEL_FILENAME)
COLS_PATH  = os.path.join(os.path.dirname(__file__), "feature_cols.json")
RANDOM_TOKEN_RE = re.compile(r"[A-Za-z0-9]{15,}")

LEGITIMATE_DOMAINS = {
    "google.com", "www.google.com", "google.co.uk", "google.ca", "google.com.au",
    "microsoft.com", "www.microsoft.com", "office.com", "outlook.com", "live.com",
    "apple.com", "www.apple.com", "icloud.com", "appleid.apple.com",
    "amazon.com", "www.amazon.com", "amazon.co.uk", "amazon.ca",
    "facebook.com", "www.facebook.com", "fb.com",
    "twitter.com", "www.twitter.com", "x.com",
    "linkedin.com", "www.linkedin.com",
    "github.com", "www.github.com",
    "paypal.com", "www.paypal.com",
    "netflix.com", "www.netflix.com",
    "youtube.com", "www.youtube.com",
    "instagram.com", "www.instagram.com",
    "reddit.com", "www.reddit.com",
    "wikipedia.org", "www.wikipedia.org",
    "stackoverflow.com", "www.stackoverflow.com",
}


class ModelNotAvailableError(RuntimeError):
    pass


# ── Load feature columns saved during training ────────────────────────────────
def _load_feature_cols():
    if not os.path.exists(COLS_PATH):
        return []
    with open(COLS_PATH) as f:
        return json.load(f)

FEATURE_COLS = _load_feature_cols()


@lru_cache(maxsize=1)
def _load_model():
    if not os.path.exists(MODEL_PATH):
        raise ModelNotAvailableError(
            f"Model not found at {MODEL_PATH}. "
            "Train in Colab and place .pkl in services/"
        )
    model = joblib.load(MODEL_PATH)
    print(f"[ml_scoring] Model loaded OK — {len(model.feature_names_in_)} features")
    return model


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if "://" not in url:
        return "https://" + url
    return url


def _extract_feature_values(url: str, results: dict) -> dict:
    normalized_url = _normalize_url(url)
    parsed   = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    query    = parsed.query or ""

    host_parts  = [p for p in hostname.split(".") if p]
    base_domain = host_parts[-2] if len(host_parts) >= 2 else (host_parts[-1] if host_parts else "")
    subdomain   = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""

    rules_info = results.get("rules") or {}
    whois_info = results.get("whois") or {}
    ssl_info   = results.get("ssl")   or {}

    features = {}

    # ── URL structure features ────────────────────────────────────────────────
    features["NumDots"]            = float(hostname.count(".") + path.count("."))
    features["SubdomainLevel"]     = float(max(len(host_parts) - 2, 0))
    features["PathLevel"]          = float(len([s for s in path.split("/") if s]))
    features["UrlLength"]          = float(len(normalized_url))
    features["NumDash"]            = float(normalized_url.count("-"))
    features["NumDashInHostname"]  = float(hostname.count("-"))
    features["AtSymbol"]           = float("@" in normalized_url)
    features["TildeSymbol"]        = float("~" in normalized_url)
    features["NumUnderscore"]      = float(normalized_url.count("_"))
    features["NumPercent"]         = float(normalized_url.count("%"))
    features["NumQueryComponents"] = float(len(parse_qs(query, keep_blank_values=True)))
    features["NumAmpersand"]       = float(normalized_url.count("&"))
    features["NumHash"]            = float(normalized_url.count("#"))
    features["NumNumericChars"]    = float(sum(c.isdigit() for c in normalized_url))
    features["NoHttps"]            = 0.0 if ssl_info.get("https_ok") else 1.0
    features["RandomString"]       = float(bool(RANDOM_TOKEN_RE.search(path + query)))

    try:
        ipaddress.ip_address(hostname)
        features["IpAddress"] = 1.0
    except ValueError:
        features["IpAddress"] = 0.0

    features["DomainInSubdomains"] = float(bool(subdomain and base_domain and base_domain in subdomain))
    features["DomainInPaths"]      = float(bool(base_domain and base_domain in path))
    features["HttpsInHostname"]    = float("https" in hostname.lower())
    features["HostnameLength"]     = float(len(hostname))
    features["PathLength"]         = float(len(path))
    features["QueryLength"]        = float(len(query))
    features["DoubleSlashInPath"]  = float("//" in path)
    features["NumSensitiveWords"]  = float(len(rules_info.get("matched_suspicious") or []))
    features["EmbeddedBrandName"]  = float(bool(rules_info.get("has_brand_words_in_host")))

    # ── WHOIS domain mismatch ─────────────────────────────────────────────────
    whois_domain = (whois_info.get("domain") or "").lower()
    features["FrequentDomainNameMismatch"] = float(
        bool(hostname and whois_domain and not hostname.endswith(whois_domain))
    )

    # ── Page-level features (from rules service or default 0) ─────────────────
    features["PctExtHyperlinks"]    = float(rules_info.get("pct_ext_hyperlinks") or 0)
    features["PctExtResourceUrls"]  = float(rules_info.get("pct_ext_resource_urls") or 0)
    features["ExtFavicon"]          = float(rules_info.get("ext_favicon") or 0)
    features["InsecureForms"]       = float(rules_info.get("has_external_form") or 0)
    features["RelativeFormAction"]  = float(rules_info.get("relative_form_action") or 0)
    features["ExtFormAction"]       = float(rules_info.get("ext_form_action") or 0)
    features["AbnormalFormAction"]  = float(rules_info.get("abnormal_form_action") or 0)
    features["PctNullSelfRedirectHyperlinks"] = float(rules_info.get("pct_null_self_redirect") or 0)
    features["FakeLinkInStatusBar"] = float(rules_info.get("fake_status_bar") or 0)
    features["RightClickDisabled"]  = float(rules_info.get("right_click_disabled") or 0)
    features["PopUpWindow"]         = float(rules_info.get("has_popup") or 0)
    features["SubmitInfoToEmail"]   = float(rules_info.get("mailto_form") or 0)
    features["IframeOrFrame"]       = float(rules_info.get("has_iframe") or 0)
    features["MissingTitle"]        = 0.0 if rules_info.get("has_title") else 1.0
    features["ImagesOnlyInForm"]    = float(rules_info.get("images_only_in_form") or 0)

    # ── RT columns ────────────────────────────────────────────────────────────
    features["SubdomainLevelRT"]    = features["SubdomainLevel"]
    features["UrlLengthRT"]         = features["UrlLength"]
    features["PctExtResourceUrlsRT"]= float(rules_info.get("pct_ext_resource_urls_rt") or 0)
    features["AbnormalExtFormActionR"]             = features["AbnormalFormAction"]
    features["ExtMetaScriptLinkRT"]                = float(rules_info.get("ext_meta_script") or 0)
    features["PctExtNullSelfRedirectHyperlinksRT"] = float(rules_info.get("pct_null_self_redirect_rt") or 0)

    return features


def score_url_with_model(url: str, results: dict) -> dict:
    model    = _load_model()
    features = _extract_feature_values(url, results)

    # Use saved column order from training — guarantees exact match
    col_order = FEATURE_COLS if FEATURE_COLS else list(model.feature_names_in_)
    ordered   = np.array(
        [[features.get(col, 0.0) for col in col_order]],
        dtype=float
    )

    proba = float(model.predict_proba(ordered)[0][1])
    score = int(round(proba * 100))

    # Whitelist check
    parsed     = urlparse(_normalize_url(url))
    hostname   = (parsed.hostname or "").lower()
    is_whitelisted = (
        hostname in LEGITIMATE_DOMAINS or
        any(hostname.endswith(f".{d}") for d in LEGITIMATE_DOMAINS)
    )

    original_score = score
    if is_whitelisted and score > 20:
        score = max(5, min(20, score // 3))
        whitelist_adjusted = True
    else:
        whitelist_adjusted = False

    label = (
        "High Risk"   if score >= 70 else
        "Medium Risk" if score >= 40 else
        "Low Risk"
    )

    # Build reasons
    reasons = []
    whois = results.get("whois") or {}
    ssl   = results.get("ssl")   or {}
    rules = results.get("rules") or {}

    if whitelist_adjusted:
        reasons.append(
            f"Domain is whitelisted as legitimate "
            f"(original ML score: {original_score}, adjusted to: {score})"
        )
    if proba >= 0.70:
        reasons.append("ML model predicts high probability of phishing")
    elif proba >= 0.40:
        reasons.append("ML model predicts moderate risk")
    else:
        reasons.append("ML model predicts low risk")

    age = whois.get("age_days")
    if age is not None and int(age) < 180:
        reasons.append(f"Domain only {age} days old")

    if not ssl.get("https_ok"):
        reasons.append("No valid HTTPS connection")

    suspicious = rules.get("matched_suspicious") or []
    if suspicious:
        reasons.append(f"Suspicious keywords: {', '.join(suspicious[:5])}")

    if rules.get("has_iframe"):
        reasons.append("Hidden iframes detected")
    if rules.get("has_external_form"):
        reasons.append("Form submits to external domain")

    return {
        "score":             score,
        "label":             label,
        "probability":       round(proba, 4),
        "reasons":           reasons,
        "original_ml_score": original_score if whitelist_adjusted else None,
        "whitelisted":       is_whitelisted,
        "feature_count":     len(col_order),
    }