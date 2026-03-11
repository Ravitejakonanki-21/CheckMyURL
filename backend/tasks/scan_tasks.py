from bson import ObjectId

from services.ssl_check import check_ssl
from services.whois_check import check_whois
from services.unicode_idn import check_unicode_domain
from services.keyword_check import check_url_for_keywords
from services.content_rules import check_keywords
from services.ascii_unicode_check import validate_ascii_unicode
from services.headers_check import check_headers
from services.ml_scoring import score_url_with_model, ModelNotAvailableError
from services.simple_cache import cache
from services.utils import timed_call

from models.mongo_client import get_collection
from models.scan_model import update_scan_state, save_scan_results
from utils.risk_explainable import build_explainable_risk
from .celery_app import celery_app


_scans = get_collection("scans")


def enqueue_scan_task(scan_id: str) -> str:
    result = run_deep_scan.delay(scan_id)
    return result.id


@celery_app.task(bind=True, name="run_deep_scan")
def run_deep_scan(self, scan_id: str):
    doc = _scans.find_one({"_id": ObjectId(scan_id)})
    if not doc:
        return {"error": "scan_not_found"}

    url = doc["url"]
    cache_key = url.lower()
    cached = cache.get(cache_key)
    if cached:
        save_scan_results(ObjectId(scan_id), cached["risk"], cached["raw_results"])
        update_scan_state(ObjectId(scan_id), "SCANNED")
        return {"status": "from_cache"}

    from urllib.parse import urlparse
    parsed = urlparse(url if "://" in url else "https://" + url)
    hostname = parsed.hostname or url

    ssl_info, t_ssl, e_ssl = timed_call(check_ssl, hostname)
    whois_info, t_whois, e_whois = timed_call(check_whois, hostname)
    idn_info, t_idn, e_idn = timed_call(check_unicode_domain, hostname, url)
    ascii_unicode_info, t_ascii, e_ascii = timed_call(validate_ascii_unicode, url)
    keyword_info, t_kw, e_kw = timed_call(check_url_for_keywords, url)
    rules_info, t_rules, e_rules = timed_call(check_keywords, url)
    headers_info, t_hd, e_hd = timed_call(check_headers, url)

    base_results = {
        "ssl": ssl_info,
        "whois": whois_info,
        "idn": idn_info,
        "ascii_unicode": ascii_unicode_info,
        "keyword": keyword_info,
        "rules": rules_info,
        "headers": headers_info,
        "timings": {
            "ssl_ms": int(t_ssl * 1000),
            "whois_ms": int(t_whois * 1000),
            "idn_ms": int(t_idn * 1000),
            "ascii_unicode_ms": int(t_ascii * 1000),
            "keyword_ms": int(t_kw * 1000),
            "rules_ms": int(t_rules * 1000),
            "headers_ms": int(t_hd * 1000),
        },
        "errors": {
            "ssl": e_ssl,
            "whois": e_whois,
            "idn": e_idn,
            "ascii_unicode": e_ascii,
            "keyword": e_kw,
            "rules": e_rules,
            "headers": e_hd,
        },
    }

    ml_output = None
    try:
        ml_output = score_url_with_model(url, base_results)
    except ModelNotAvailableError:
        ml_output = None
    except Exception:
        ml_output = None

    risk = build_explainable_risk(base_results, ml_output)
    raw_results = {**base_results, "ml": ml_output}

    save_scan_results(ObjectId(scan_id), risk, raw_results)
    update_scan_state(ObjectId(scan_id), "SCANNED")
    cache.set(cache_key, {"risk": risk, "raw_results": raw_results})

    return {"status": "ok", "scan_id": scan_id}


