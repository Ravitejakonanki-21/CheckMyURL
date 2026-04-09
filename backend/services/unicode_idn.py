import idna
import unicodedata
import re
import math
from urllib.parse import unquote, urlparse

CONFUSABLE_SCRIPTS = {
    "Latin", "Cyrillic", "Greek"
}

# Homograph characters that look similar to ASCII (only non-ASCII characters)
# Expanded list based on common homograph attacks
HOMOGRAPH_MAP = {
    # Cyrillic lowercase
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'м': 'm', 'н': 'n', 'т': 't', 'в': 'v', 'к': 'k', 'з': 'z',
    # Cyrillic uppercase
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
    # Greek uppercase
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    # Full-width digits
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
    '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
    # Full-width Latin
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f',
    'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l',
    'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
    'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x',
    'ｙ': 'y', 'ｚ': 'z',
    # Latin lookalikes (various Unicode characters that look like Latin)
    'ⅼ': 'l',  # Small Roman Numeral One (looks like lowercase L)
    'Ⅰ': 'I',  # Roman Numeral One (looks like uppercase I)
    '１': '1',  # Full-width digit one
    'Ｌ': 'L'   # Full-width Latin L
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

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0.0
    entropy = 0.0
    text = text.lower()
    for char in set(text):
        p = text.count(char) / len(text)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def check_character_set_validation(text: str) -> dict:
    """Check if all characters are standard ASCII (0-127 range)"""
    all_ascii = all(ord(c) < 128 for c in text)
    non_ascii_chars = [c for c in text if ord(c) >= 128]
    return {
        "all_ascii": all_ascii,
        "non_ascii_count": len(non_ascii_chars),
        "non_ascii_chars": non_ascii_chars[:10]  # Limit to first 10
    }

def check_unicode_detection(text: str) -> dict:
    """Detect non-ASCII (Unicode, Cyrillic, Arabic, etc.) characters"""
    unicode_chars = []
    for ch in text:
        if ord(ch) >= 128:
            unicode_chars.append({
                "char": ch,
                "code": ord(ch),
                "name": unicodedata.name(ch, "UNKNOWN"),
                "script": script_of(ch)
            })
    return {
        "found": len(unicode_chars) > 0,
        "count": len(unicode_chars),
        "characters": unicode_chars[:10]  # Limit to first 10
    }

def check_punycode(hostname: str) -> dict:
    """Detect encoded Unicode domains using xn-- prefix"""
    try:
        ace = idna.encode(hostname).decode("ascii")
        has_punycode = any(label.startswith("xn--") for label in ace.split("."))
        punycode_labels = [label for label in ace.split(".") if label.startswith("xn--")]
        return {
            "found": has_punycode,
            "punycode": ace,
            "labels": punycode_labels
        }
    except:
        return {
            "found": False,
            "punycode": None,
            "labels": []
        }

def check_homographs(text: str) -> dict:
    """Flags visually deceptive characters like а for a or е for e (only non-ASCII)
    Uses both direct mapping and Unicode name analysis for comprehensive detection"""
    homographs = []
    for i, ch in enumerate(text):
        # Skip dots and common separators
        if ch in ['.', '/', ':', '-', '_', '@']:
            continue
            
        # Method 1: Check direct mapping
        if ord(ch) >= 128 and ch in HOMOGRAPH_MAP:
            homographs.append({
                "position": i,
                "char": ch,
                "looks_like": HOMOGRAPH_MAP[ch],
                "unicode_name": unicodedata.name(ch, "UNKNOWN"),
                "detection_method": "direct_mapping"
            })
        # Method 2: Check Unicode name for suspicious scripts
        elif ord(ch) >= 128:
            try:
                name = unicodedata.name(ch, "")
                if any(word in name for word in ["CYRILLIC", "GREEK", "ARABIC", "FULLWIDTH", "HALFWIDTH"]):
                    # Try to find what ASCII character it might look like
                    looks_like = None
                    for ascii_char, unicode_chars in [
                        ('a', ['CYRILLIC SMALL LETTER A', 'GREEK SMALL LETTER ALPHA']),
                        ('e', ['CYRILLIC SMALL LETTER IE', 'GREEK SMALL LETTER EPSILON']),
                        ('o', ['CYRILLIC SMALL LETTER O', 'GREEK SMALL LETTER OMICRON']),
                        ('p', ['CYRILLIC SMALL LETTER PE', 'GREEK SMALL LETTER RHO']),
                        ('c', ['CYRILLIC SMALL LETTER ES', 'GREEK SMALL LETTER SIGMA']),
                        ('x', ['CYRILLIC SMALL LETTER HA', 'GREEK SMALL LETTER CHI']),
                    ]:
                        if any(term in name for term in unicode_chars):
                            looks_like = ascii_char
                            break
                    
                    if looks_like:
                        homographs.append({
                            "position": i,
                            "char": ch,
                            "looks_like": looks_like,
                            "unicode_name": name,
                            "detection_method": "unicode_name_analysis"
                        })
            except (ValueError, TypeError):
                pass
    
    return {
        "found": len(homographs) > 0,
        "count": len(homographs),
        "patterns": homographs[:10]  # Limit to first 10
    }

def check_encoded_characters(url: str) -> dict:
    """Checks for percent-encoded strings (%20, %2E, etc.)"""
    encoded_pattern = re.compile(r'%[0-9A-Fa-f]{2}')
    matches = encoded_pattern.findall(url)
    decoded_parts = []
    for match in matches[:10]:  # Limit to first 10
        try:
            decoded = unquote(match)
            decoded_parts.append({
                "encoded": match,
                "decoded": decoded
            })
        except:
            pass
    return {
        "found": len(matches) > 0,
        "count": len(matches),
        "encoded_strings": matches[:10],
        "decoded": decoded_parts
    }

def check_invisible_characters(text: str) -> dict:
    """Detects hidden or zero-width characters
    Comprehensive detection of invisible Unicode characters"""
    invisible_chars = []
    # Common zero-width and invisible characters
    zero_width_chars = [
        '\u200B',  # Zero Width Space
        '\u200C',  # Zero Width Non-Joiner
        '\u200D',  # Zero Width Joiner
        '\uFEFF',  # Zero Width No-Break Space (BOM)
        '\u2060',  # Word Joiner
        '\u180E',  # Mongolian Vowel Separator
        '\u200E',  # Left-to-Right Mark
        '\u200F',  # Right-to-Left Mark
        '\u202A',  # Left-to-Right Embedding
        '\u202B',  # Right-to-Left Embedding
        '\u202C',  # Pop Directional Formatting
        '\u202D',  # Left-to-Right Override
        '\u202E',  # Right-to-Left Override
    ]
    
    for i, ch in enumerate(text):
        # Check direct list
        if ch in zero_width_chars:
            try:
                invisible_chars.append({
                    "position": i,
                    "char": repr(ch),
                    "unicode_name": unicodedata.name(ch, "UNKNOWN"),
                    "category": unicodedata.category(ch),
                    "detection_method": "direct_list"
                })
            except (ValueError, TypeError):
                pass
        else:
            # Check Unicode category for invisible characters
            cat = unicodedata.category(ch)
            # Cf = Format characters, Mn = Non-spacing marks (can be invisible)
            if cat in ['Cf', 'Mn']:
                try:
                    name = unicodedata.name(ch, "")
                    # Only flag if it's truly invisible/zero-width
                    if 'ZERO WIDTH' in name or 'INVISIBLE' in name or cat == 'Cf':
                        invisible_chars.append({
                            "position": i,
                            "char": repr(ch),
                            "unicode_name": name,
                            "category": cat,
                            "detection_method": "category_analysis"
                        })
                except (ValueError, TypeError):
                    pass
    
    return {
        "found": len(invisible_chars) > 0,
        "count": len(invisible_chars),
        "characters": invisible_chars[:10]  # Limit to first 10
    }

def check_entropy(text: str) -> dict:
    """Calculates randomness of strings to detect obfuscation
    High entropy indicates random/obfuscated content (common in phishing URLs)"""
    if not text:
        return {"entropy": 0.0, "level": "None"}
    
    # Remove common separators for more accurate entropy calculation
    clean_text = ''.join(c for c in text if c.isalnum())
    if not clean_text:
        return {"entropy": 0.0, "level": "None"}
    
    entropy = calculate_entropy(clean_text)
    
    # Entropy levels based on Shannon entropy:
    # 0-2: Low (predictable, structured)
    # 2-4: Moderate (normal text)
    # 4-6: High (random-looking, suspicious)
    # 6+: Very High (highly obfuscated, likely malicious)
    if entropy < 2:
        level = "Low"
    elif entropy < 3.0:
        level = "Moderate"
    elif entropy < 4.0:
        level = "High"
    else:
        level = "Very High"
    
    return {
        "entropy": round(entropy, 2),
        "level": level,
        "interpretation": "Normal text" if entropy < 3.0 else "Possible obfuscation" if entropy < 4.0 else "High obfuscation detected"
    }

# Suspicious keywords that indicate phishing/malicious intent
# Comprehensive list based on common phishing patterns
PHISHING_KEYWORDS = [
    # Direct phishing terms
    "phish", "scam", "fake", "fraud", "steal", "hack", "malware",
    "virus", "trojan", "spyware", "stealer", "credential",
    # Common phishing URL patterns
    "password-steal", "account-hack", "verify-now", "urgent-update",
    "secure-login", "update-account", "verify-account", "confirm-account",
    "account-suspended", "account-locked", "unauthorized-access",
    # Suspicious action words
    "click-here", "verify-now", "update-now", "confirm-now",
    "reactivate", "validate", "authenticate", "authorize"
]

def check_url_legibility(url: str) -> dict:
    """Evaluates readability and predictability of URL text"""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    
    # Check for random-looking strings
    random_pattern = re.compile(r'[a-zA-Z0-9]{15,}')
    random_strings = random_pattern.findall(hostname + path)
    
    # Check structure
    has_subdomain = len(hostname.split('.')) > 2
    path_depth = len([p for p in path.split('/') if p])
    
    # Check for phishing-related keywords in hostname
    hostname_lower = hostname.lower()
    found_phishing_keywords = [kw for kw in PHISHING_KEYWORDS if kw in hostname_lower]
    
    # Overall assessment
    issues = []
    if random_strings:
        issues.append(f"Found {len(random_strings)} random-looking strings")
    if path_depth > 5:
        issues.append("Deep path structure")
    if len(hostname) > 50:
        issues.append("Very long hostname")
    if found_phishing_keywords:
        issues.append(f"Suspicious keywords detected: {', '.join(found_phishing_keywords)}")
    
    readability = "Readable and structured"
    if found_phishing_keywords:
        readability = f"High risk: Contains phishing-related keywords ({', '.join(found_phishing_keywords)})"
    elif issues:
        readability = f"Some concerns: {', '.join(issues)}"
    
    return {
        "readability": readability,
        "random_strings_count": len(random_strings),
        "path_depth": path_depth,
        "hostname_length": len(hostname),
        "has_subdomain": has_subdomain,
        "phishing_keywords_found": found_phishing_keywords,
        "has_phishing_keywords": len(found_phishing_keywords) > 0
    }

def check_unicode_domain(hostname: str, full_url: str = None):
    out = {
        "punycode": None,
        "is_idn": False,
        "scripts": [],
        "mixed_confusable_scripts": False,
        "has_rtl": False,
        "errors": [],
        # New detailed checks
        "character_set_validation": {},
        "unicode_detection": {},
        "punycode_check": {},
        "homograph_detection": {},
        "encoded_characters": {},
        "invisible_characters": {},
        "entropy_check": {},
        "url_legibility": {}
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

        # Perform detailed ASCII checks
        out["character_set_validation"] = check_character_set_validation(hostname)
        out["unicode_detection"] = check_unicode_detection(hostname)
        out["punycode_check"] = check_punycode(hostname)
        out["homograph_detection"] = check_homographs(hostname)
        
        # For full URL checks
        if full_url:
            out["encoded_characters"] = check_encoded_characters(full_url)
            out["url_legibility"] = check_url_legibility(full_url)
        else:
            out["encoded_characters"] = {"found": False, "note": "Full URL not provided"}
            out["url_legibility"] = check_url_legibility(hostname)
        out["invisible_characters"] = check_invisible_characters(hostname)
        out["entropy_check"] = check_entropy(hostname)
        
        # Calculate ASCII score based on all checks
        scores = []
        
        # Character Set Validation (weight: 20%)
        if out["character_set_validation"].get("all_ascii"):
            scores.append(100 * 0.20)
        else:
            scores.append(0 * 0.20)
        
        # Unicode Detection (weight: 20%)
        if not out["unicode_detection"].get("found"):
            scores.append(100 * 0.20)
        else:
            scores.append(0 * 0.20)
        
        # Punycode Check (weight: 15%)
        if not out["punycode_check"].get("found"):
            scores.append(100 * 0.15)
        else:
            scores.append(0 * 0.15)
        
        # Homograph Detection (weight: 20%)
        if not out["homograph_detection"].get("found"):
            scores.append(100 * 0.20)
        else:
            scores.append(0 * 0.20)
        
        # Encoded Characters (weight: 10%) - some encoding is normal
        if not out["encoded_characters"].get("found"):
            scores.append(100 * 0.10)
        else:
            # Penalize but not as much since some encoding is normal
            encoded_count = out["encoded_characters"].get("count", 0)
            if encoded_count <= 2:
                scores.append(75 * 0.10)  # Minor penalty
            elif encoded_count <= 5:
                scores.append(50 * 0.10)  # Medium penalty
            else:
                scores.append(25 * 0.10)  # High penalty
        
        # Invisible Characters (weight: 10%)
        if not out["invisible_characters"].get("found"):
            scores.append(100 * 0.10)
        else:
            scores.append(0 * 0.10)
        
        # Entropy Check (weight: 5%)
        entropy_level = out["entropy_check"].get("level", "Moderate")
        if entropy_level == "Low":
            scores.append(100 * 0.05)
        elif entropy_level == "Moderate":
            scores.append(100 * 0.05)
        elif entropy_level == "High":
            scores.append(50 * 0.05)
        else:  # Very High
            scores.append(25 * 0.05)
        
        # URL Legibility (weight: 10%)
        readability = out["url_legibility"].get("readability", "")
        has_phishing_keywords = out["url_legibility"].get("has_phishing_keywords", False)
        
        if has_phishing_keywords:
            # Severe penalty for phishing keywords in hostname
            scores.append(0 * 0.10)
        elif "Readable and structured" in readability:
            scores.append(100 * 0.10)
        elif "Some concerns" in readability:
            scores.append(50 * 0.10)
        else:
            scores.append(25 * 0.10)
        
        # Additional penalty for phishing keywords (reduce overall score)
        if has_phishing_keywords:
            # Apply severe penalty: reduce total score by 50 points
            # URLs with phishing keywords should score very low
            phishing_penalty = 50
        else:
            phishing_penalty = 0
        
        # Calculate total score
        total_score = int(sum(scores))
        
        # Apply phishing keyword penalty
        total_score = max(0, total_score - phishing_penalty)
        
        # Cap at 100
        total_score = min(100, total_score)
        out["ascii_score"] = total_score

    except Exception as e:
        out["errors"].append(f"idn_error: {e}")
        out["ascii_score"] = 0
    return out
