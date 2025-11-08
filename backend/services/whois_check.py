import whoisit
from datetime import datetime
import tldextract
import re

# Global bootstrap flag to avoid re-bootstrapping
_bootstrapped = False

def ensure_bootstrap():
    global _bootstrapped
    if not _bootstrapped:
        if not whoisit.is_bootstrapped():
            whoisit.bootstrap()
        _bootstrapped = True

def parse_vcard(vcard_array, roles, out):
    if len(vcard_array) > 1:
        vcard_properties = vcard_array[1]
        for prop in vcard_properties:
            if isinstance(prop, list) and len(prop) >= 4:
                if prop[0] == 'email':
                    email = prop[3]
                    if 'administrative' in roles or 'admin' in roles:
                        out["admin_email"] = email
                    elif 'technical' in roles or 'tech' in roles:
                        out["tech_email"] = email
                    elif 'abuse' in roles or 'registrar' in roles:
                        if 'abuse' in email.lower():
                            out["registrar_abuse_email"] = email
                elif prop[0] == 'tel':
                    phone = prop[3]
                    if 'abuse' in roles or ('registrar' in roles and not out["registrar_abuse_phone"]):
                        out["registrar_abuse_phone"] = phone
                elif prop[0] == 'adr':
                    if len(prop[3]) >= 7:
                        country = prop[3][6]
                        if country and ('registrant' in roles or 'administrative' in roles or 'admin' in roles):
                            out["country"] = country
                            out["registrant_country"] = country

def extract_entity_info(entity, roles, out):
    if isinstance(entity, dict):
        fn = entity.get('fn')
        name = entity.get('name')
        handle = entity.get('handle')
        if 'registrar' in roles:
            if not out["registrar"]:
                for field in [fn, name, handle]:
                    if field:
                        out["registrar"] = field
                        break
            # IANA ID from publicIds
            if not out["registrar_iana_id"]:
                public_ids = entity.get('publicIds', [])
                for pub_id in public_ids:
                    if isinstance(pub_id, dict) and pub_id.get('type') == 'iana':
                        out["registrar_iana_id"] = pub_id.get('identifier')
                        break
            if not out["registrar_abuse_email"] or not out["registrar_abuse_phone"]:
                parse_vcard(entity.get('vcardArray', []), roles, out)
        if 'registrant' in roles:
            if not out["registrant"]:
                regname = fn or name
                if regname:
                    out["registrant"] = regname
            if not out["registrant_organization"]:
                orgname = fn or name
                if orgname:
                    out["registrant_organization"] = orgname
            if not out["registrant_country"]:
                parse_vcard(entity.get('vcardArray', []), roles, out)
        if any(role in roles for role in ['technical', 'admin', 'administrative']):
            parse_vcard(entity.get('vcardArray', []), roles, out)
        if 'abuse' in roles:
            parse_vcard(entity.get('vcardArray', []), roles, out)

def regex_extract(pattern, text):
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else None

def fallback_whois_lookup(domain):
    try:
        import whois
        import subprocess
        import json

        # Try python-whois first
        try:
            whois_data = whois.whois(domain)
            result = {}

            # Extract registrar info
            if whois_data.registrar:
                result['registrar'] = str(whois_data.registrar)

            # Extract dates
            if whois_data.creation_date:
                if isinstance(whois_data.creation_date, list):
                    result['creation_date'] = whois_data.creation_date[0]
                else:
                    result['creation_date'] = whois_data.creation_date

            if whois_data.updated_date:
                if isinstance(whois_data.updated_date, list):
                    result['updated_date'] = whois_data.updated_date[0]
                else:
                    result['updated_date'] = whois_data.updated_date

            if whois_data.expiration_date:
                if isinstance(whois_data.expiration_date, list):
                    result['expiration_date'] = whois_data.expiration_date[0]
                else:
                    result['expiration_date'] = whois_data.expiration_date

            # Extract name servers
            if whois_data.name_servers:
                result['name_servers'] = [str(ns).lower() for ns in whois_data.name_servers]

            # Extract status
            if whois_data.status:
                if isinstance(whois_data.status, list):
                    result['status'] = [str(s) for s in whois_data.status]
                else:
                    result['status'] = [str(whois_data.status)]

            # Extract registrant info
            if whois_data.org:
                result['registrant_org'] = str(whois_data.org)
            if whois_data.country:
                result['country'] = str(whois_data.country)

            # Extract registry id, abuse, iana if present using raw text if available
            raw_str = whois_data.text if hasattr(whois_data, 'text') else None
            if raw_str:
                # Extract commonly missed fields with regex
                regid = regex_extract(r"Registry Domain ID:\s*(.+)", raw_str)
                if regid: result['registry_domain_id'] = regid

                ianaid = regex_extract(r"Registrar IANA ID:\s*(.+)", raw_str)
                if ianaid: result['registrar_iana_id'] = ianaid

                abuse_email = regex_extract(r"Registrar Abuse Contact Email:\s*(.+)", raw_str)
                if abuse_email: result['registrar_abuse_email'] = abuse_email

                abuse_phone = regex_extract(r"Registrar Abuse Contact Phone:\s*(.+)", raw_str)
                if abuse_phone: result['registrar_abuse_phone'] = abuse_phone

            return result
        except Exception as e:
            print(f"Python-whois fallback failed: {e}")

        # Extra: fallback with raw whois shell (if needed)
        try:
            output = subprocess.check_output(['whois', domain], universal_newlines=True, timeout=10)
            # Use regex_extract from above to fill fields
            result = {}
            regid = regex_extract(r"Registry Domain ID:\s*(.+)", output)
            if regid: result['registry_domain_id'] = regid
            registrar = regex_extract(r"Registrar:\s*(.+)", output)
            if registrar: result['registrar'] = registrar
            ianaid = regex_extract(r"Registrar IANA ID:\s*(.+)", output)
            if ianaid: result['registrar_iana_id'] = ianaid
            abuse_email = regex_extract(r"Registrar Abuse Contact Email:\s*(.+)", output)
            if abuse_email: result['registrar_abuse_email'] = abuse_email
            abuse_phone = regex_extract(r"Registrar Abuse Contact Phone:\s*(.+)", output)
            if abuse_phone: result['registrar_abuse_phone'] = abuse_phone
            return result
        except Exception as e:
            print(f"Shell whois fallback failed: {e}")
            return None
    except ImportError:
        print("python-whois not available for fallback")
        return None

def check_whois(url: str):
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
        "errors": [],
        "registrant_organization": None,
        "registrant_country": None,
        "registry_domain_id": None,
        "registrar_iana_id": None,
        "registrar_abuse_email": None,
        "registrar_abuse_phone": None,
        "dnssec": None
    }

    try:
        ext = tldextract.extract(url)
        domain = ".".join(part for part in [ext.domain, ext.suffix] if part)
        out["domain"] = domain or url

        # Try RDAP first
        ensure_bootstrap()
        result = whoisit.domain(domain)
        if result and isinstance(result, dict):
            out["domain"] = result.get('name', domain)
            out["registry_domain_id"] = result.get('handle') or result.get('registry_domain_id')
            out["dnssec"] = result.get('secureDNS', {}).get('delegationSigned', 'unsigned')
            if out["dnssec"] is True:
                out["dnssec"] = "signed"
            elif out["dnssec"] is False:
                out["dnssec"] = "unsigned"

            registration_date = result.get('registration_date')
            if registration_date:
                out["creation_date"] = registration_date.isoformat().replace('+00:00', 'Z')
                age_days = (datetime.now(registration_date.tzinfo) - registration_date).days
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

            last_changed_date = result.get('last_changed_date')
            if last_changed_date:
                out["updated_date"] = last_changed_date.isoformat().replace('+00:00', 'Z')

            expiration_date = result.get('expiration_date')
            if expiration_date:
                out["expiration_date"] = expiration_date.isoformat().replace('+00:00', 'Z')
                days_until_expiry = (expiration_date - datetime.now(expiration_date.tzinfo)).days
                if days_until_expiry < 30:
                    out["risk_score"] += 20
                    out["risk_factors"].append("Domain expiring within 30 days")

            nameservers = result.get('nameservers', [])
            if nameservers:
                out["name_servers"] = nameservers

            status = result.get('status', [])
            if status:
                out["statuses"] = status
                suspicious_statuses = ['client hold', 'server hold', 'pending delete']
                for status_item in status:
                    if any(sus_status in status_item.lower() for sus_status in suspicious_statuses):
                        out["risk_score"] += 30
                        out["risk_factors"].append(f"Suspicious domain status: {status_item}")

            entities = result.get('entities', [])
            if entities:
                for entity in entities:
                    if isinstance(entity, dict):
                        roles = entity.get('roles', [])
                        extract_entity_info(entity, roles, out)

            # Check if we're missing critical fields and try fallback
            missing_critical_fields = not out["registrar"] or not out["creation_date"] or not out["registrar_iana_id"] or not out["registrar_abuse_email"] or not out["registrar_abuse_phone"]
            if missing_critical_fields:
                fallback_data = fallback_whois_lookup(domain)
                if fallback_data:
                    if not out["registrar"] and fallback_data.get('registrar'):
                        out["registrar"] = fallback_data['registrar']
                    if not out["creation_date"] and fallback_data.get('creation_date'):
                        if isinstance(fallback_data['creation_date'], datetime):
                            out["creation_date"] = fallback_data['creation_date'].isoformat().replace('+00:00', 'Z')
                        else:
                            out["creation_date"] = str(fallback_data['creation_date'])
                    if not out["updated_date"] and fallback_data.get('updated_date'):
                        if isinstance(fallback_data['updated_date'], datetime):
                            out["updated_date"] = fallback_data['updated_date'].isoformat().replace('+00:00', 'Z')
                        else:
                            out["updated_date"] = str(fallback_data['updated_date'])
                    if not out["expiration_date"] and fallback_data.get('expiration_date'):
                        if isinstance(fallback_data['expiration_date'], datetime):
                            out["expiration_date"] = fallback_data['expiration_date'].isoformat().replace('+00:00', 'Z')
                        else:
                            out["expiration_date"] = str(fallback_data['expiration_date'])
                    if not out["name_servers"] and fallback_data.get('name_servers'):
                        out["name_servers"] = fallback_data['name_servers']
                    if not out["statuses"] and fallback_data.get('status'):
                        out["statuses"] = fallback_data['status']
                    if not out["registrant_organization"] and fallback_data.get('registrant_org'):
                        out["registrant_organization"] = fallback_data['registrant_org']
                    if not out["country"] and fallback_data.get('country'):
                        out["country"] = fallback_data['country']
                        out["registrant_country"] = fallback_data['country']
                    if not out["registry_domain_id"] and fallback_data.get('registry_domain_id'):
                        out["registry_domain_id"] = fallback_data['registry_domain_id']
                    if not out["registrar_iana_id"] and fallback_data.get('registrar_iana_id'):
                        out["registrar_iana_id"] = fallback_data['registrar_iana_id']
                    if not out["registrar_abuse_email"] and fallback_data.get('registrar_abuse_email'):
                        out["registrar_abuse_email"] = fallback_data['registrar_abuse_email']
                    if not out["registrar_abuse_phone"] and fallback_data.get('registrar_abuse_phone'):
                        out["registrar_abuse_phone"] = fallback_data['registrar_abuse_phone']

            # Privacy detection
            if out.get("registrant"):
                privacy_keywords = ['privacy', 'protected', 'redacted', 'withheld', 'contact privacy', 'whois privacy', 'domain privacy']
                out["privacy_protected"] = any(keyword in out["registrant"].lower() for keyword in privacy_keywords)
            elif out.get("registrant_organization"):
                privacy_keywords = ['privacy', 'protected', 'redacted', 'withheld', 'contact privacy', 'whois privacy', 'domain privacy']
                out["privacy_protected"] = any(keyword in out["registrant_organization"].lower() for keyword in privacy_keywords)

            if out["privacy_protected"]:
                out["risk_score"] += 15
                out["risk_factors"].append("WHOIS privacy protection enabled")
            if not out["registrar"]:
                out["risk_score"] += 10
                out["risk_factors"].append("Registrar information not available")
            if not out["creation_date"]:
                out["risk_score"] += 20
                out["risk_factors"].append("Domain creation date not available")
            if out["dnssec"] == "unsigned":
                out["risk_score"] += 5
                out["risk_factors"].append("DNSSEC not enabled")

            if out["risk_score"] >= 60:
                out["classification"] = "High Risk"
            elif out["risk_score"] >= 30:
                out["classification"] = "Suspicious"
            else:
                out["classification"] = "Low Risk"
        else:
            # If RDAP fails completely, try fallback
            fallback_data = fallback_whois_lookup(domain)
            if fallback_data:
                if fallback_data.get('registrar'):
                    out["registrar"] = fallback_data['registrar']
                if fallback_data.get('creation_date'):
                    if isinstance(fallback_data['creation_date'], datetime):
                        out["creation_date"] = fallback_data['creation_date'].isoformat().replace('+00:00', 'Z')
                    else:
                        out["creation_date"] = str(fallback_data['creation_date'])
                if fallback_data.get('updated_date'):
                    if isinstance(fallback_data['updated_date'], datetime):
                        out["updated_date"] = fallback_data['updated_date'].isoformat().replace('+00:00', 'Z')
                    else:
                        out["updated_date"] = str(fallback_data['updated_date'])
                if fallback_data.get('expiration_date'):
                    if isinstance(fallback_data['expiration_date'], datetime):
                        out["expiration_date"] = fallback_data['expiration_date'].isoformat().replace('+00:00', 'Z')
                    else:
                        out["expiration_date"] = str(fallback_data['expiration_date'])
                if fallback_data.get('name_servers'):
                    out["name_servers"] = fallback_data['name_servers']
                if fallback_data.get('status'):
                    out["statuses"] = fallback_data['status']
                if fallback_data.get('registrant_org'):
                    out["registrant_organization"] = fallback_data['registrant_org']
                if fallback_data.get('country'):
                    out["country"] = fallback_data['country']
                    out["registrant_country"] = fallback_data['country']
                if fallback_data.get('registry_domain_id'):
                    out["registry_domain_id"] = fallback_data['registry_domain_id']
                if fallback_data.get('registrar_iana_id'):
                    out["registrar_iana_id"] = fallback_data['registrar_iana_id']
                if fallback_data.get('registrar_abuse_email'):
                    out["registrar_abuse_email"] = fallback_data['registrar_abuse_email']
                if fallback_data.get('registrar_abuse_phone'):
                    out["registrar_abuse_phone"] = fallback_data['registrar_abuse_phone']

                # Calculate age if we have creation date
                if out["creation_date"]:
                    try:
                        if isinstance(fallback_data['creation_date'], datetime):
                            creation_dt = fallback_data['creation_date']
                        else:
                            creation_dt = datetime.fromisoformat(out["creation_date"].replace('Z', '+00:00'))
                        age_days = (datetime.now(creation_dt.tzinfo) - creation_dt).days
                        out["age_days"] = age_days
                    except:
                        pass
            else:
                out["errors"].append("WHOIS lookup failed - no data available from RDAP or fallback")

    except Exception as ex:
        import traceback
        out["errors"].append(f"whois_lookup_error: {str(ex)}")
        try:
            fallback_data = fallback_whois_lookup(domain)
            if fallback_data:
                if fallback_data.get('registrar'):
                    out["registrar"] = fallback_data['registrar']
                if fallback_data.get('creation_date'):
                    out["creation_date"] = str(fallback_data['creation_date'])
                if fallback_data.get('registrar_iana_id'):
                    out["registrar_iana_id"] = fallback_data['registrar_iana_id']
                if fallback_data.get('registrar_abuse_email'):
                    out["registrar_abuse_email"] = fallback_data['registrar_abuse_email']
                if fallback_data.get('registrar_abuse_phone'):
                    out["registrar_abuse_phone"] = fallback_data['registrar_abuse_phone']
        except:
            pass

    return out
