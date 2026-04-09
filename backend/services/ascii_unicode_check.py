import unicodedata
import re

# -------- 1. NON-ASCII CHECK --------
def has_non_ascii(url: str):
    return any(ord(c) > 127 for c in url)


# -------- 2. HOMOGLYPH SETS --------
HOMOGLYPHS = {
    "a": ["а", "ɑ", "ά", "à", "á", "â", "ä", "ã", "å"],
    "e": ["е", "є", "ẻ", "é", "è", "ê", "ë"],
    "o": ["ο", "о", "ỏ", "ó", "ò", "ô", "ö", "õ"],
    "p": ["р"],
    "c": ["с", "ϲ"],
    "y": ["у", "ү"],
    "x": ["х"],
    "g": ["ɡ"],
    "l": ["ⅼ", "ӏ"]
}


def detect_homoglyphs(url):
    suspicious = []
    for normal, variants in HOMOGLYPHS.items():
        for v in variants:
            if v in url:
                suspicious.append((normal, v))
    return suspicious


# -------- 3. MIXED SCRIPTS --------
def detect_mixed_scripts(url):
    scripts = set()

    for char in url:
        if char.isalnum():
            try:
                name = unicodedata.name(char)
                if "CYRILLIC" in name:
                    scripts.add("Cyrillic")
                elif "GREEK" in name:
                    scripts.add("Greek")
                elif "LATIN" in name:
                    scripts.add("Latin")
            except:
                pass

    return len(scripts) > 1, scripts


# -------- 4. ZERO-WIDTH CHARACTERS --------
ZERO_WIDTH = [
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"
]

def has_zero_width(url):
    return any(z in url for z in ZERO_WIDTH)


# -------- 5. ACCENTED CHARACTER CHECK --------
ACCENTED_PATTERN = r"[áàâäãåÁÀÂÄÃÅéèêëÉÈÊËíìîïÍÌÎÏóòôöõÓÒÔÖÕúùûüÚÙÛÜñÑ]"

def has_accented(url):
    return bool(re.search(ACCENTED_PATTERN, url))


# -------- 6. PUNYCODE DETECTION --------
def is_punycode(url):
    return "xn--" in url


# -------- 7. FULL VALIDATOR --------
def validate_ascii_unicode(url: str):
    report = {
        "non_ascii": has_non_ascii(url),
        "homoglyphs": detect_homoglyphs(url),
        "has_zero_width": has_zero_width(url),
        "accented_characters": has_accented(url),
        "punycode_domain": is_punycode(url),
    }

    mixed, scripts = detect_mixed_scripts(url)
    report["mixed_scripts"] = mixed
    report["scripts_found"] = list(scripts)

    return report

