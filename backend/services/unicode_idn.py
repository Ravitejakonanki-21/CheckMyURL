import idna
import unicodedata

CONFUSABLE_SCRIPTS = {
    "Latin", "Cyrillic", "Greek"
}

def script_of(ch: str) -> str:
    # Heuristic script inference using Unicode names
    name = unicodedata.name(ch, "")
    if not name:
        return "Unknown"
    for s in ["LATIN", "CYRILLIC", "GREEK", "HEBREW", "ARABIC", "DEVANAGARI", "HIRAGANA", "KATAKANA", "HANGUL", "CJK"]:
        if s in name:
            return s.title()
    return "Other"

def check_unicode_domain(hostname: str):
    out = {
        "punycode": None,
        "is_idn": False,
        "scripts": [],
        "mixed_confusable_scripts": False,
        "has_rtl": False,
        "errors": []
    }
    try:
        # Encode punycode (ACE) to see if IDN is used
        ace = idna.encode(hostname).decode("ascii")
        out["punycode"] = ace
        out["is_idn"] = any(label.startswith("xn--") for label in ace.split("."))

        # Script analysis on the U-label (original Unicode form)
        scripts = set()
        has_rtl = False
        for ch in hostname:
            if ch == ".":
                continue
            cat = unicodedata.category(ch)
            if cat.startswith("C"):
                # control/unassigned, ignore
                continue
            scripts.add(script_of(ch))
            bidic = unicodedata.bidirectional(ch)
            if bidic in ("R", "AL", "RLE", "RLO"):
                has_rtl = True

        out["scripts"] = sorted(scripts)
        out["has_rtl"] = has_rtl

        # Flag mixed Latin/Cyrillic/Greek (common phishing trick)
        confusable_present = [s for s in scripts if s in CONFUSABLE_SCRIPTS]
        out["mixed_confusable_scripts"] = len(confusable_present) > 1

    except Exception as e:
        out["errors"].append(f"idn_error: {e}")
    return out
