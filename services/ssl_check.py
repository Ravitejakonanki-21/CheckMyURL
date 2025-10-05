import ssl
import socket
from datetime import datetime, timezone
import ipaddress
from urllib.parse import urlparse


def check_ssl(hostname: str, port: int = 443, timeout: float = 5.0):
    """
    Enhanced SSL certificate validation with comprehensive security checks
    """
    out = {
        "https_ok": False,
        "expires_on": None,
        "expired": None,
        "issuer_cn": None,
        "subject_cn": None,
        "self_signed_hint": None,
        "certificate_chain_valid": None,
        "tls_version": None,
        "cipher_suite": None,
        "certificate_valid_days": None,
        "san_domains": [],
        "certificate_transparency": None,
        "weak_signature": None,
        "hostname_match": None,
        "errors": []
    }
    
    try:
        # Validate hostname format
        hostname = _normalize_hostname(hostname)
        if not hostname:
            out["errors"].append("invalid_hostname: Invalid hostname format")
            return out
            
        # Create enhanced SSL context with security best practices
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        # Disable weak protocols (force TLS 1.2+)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Enhanced cipher configuration
        ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Successful connection
                out["https_ok"] = True
                
                # Get TLS version and cipher info
                out["tls_version"] = ssock.version()
                out["cipher_suite"] = ssock.cipher()[0] if ssock.cipher() else None
                
                # Get peer certificate
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                
                # Certificate chain validation
                cert_chain = ssock.getpeercert_chain()
                out["certificate_chain_valid"] = len(cert_chain) > 1 if cert_chain else False
                
        # Process certificate details
        _process_certificate_details(cert, cert_der, hostname, out)
        
    except ssl.SSLCertVerificationError as e:
        error_msg = str(e).lower()
        if "self signed" in error_msg:
            out["self_signed_hint"] = True
            out["errors"].append(f"self_signed_cert: {e}")
        elif "hostname" in error_msg:
            out["hostname_match"] = False
            out["errors"].append(f"hostname_mismatch: {e}")
        elif "expired" in error_msg:
            out["expired"] = True
            out["errors"].append(f"certificate_expired: {e}")
        else:
            out["errors"].append(f"cert_verify_error: {e}")
            
    except socket.timeout:
        out["errors"].append("connection_timeout: SSL handshake timed out")
        
    except socket.gaierror as e:
        out["errors"].append(f"dns_resolution_error: {e}")
        
    except ConnectionRefusedError:
        out["errors"].append(f"connection_refused: Port {port} is not accessible")
        
    except OSError as e:
        out["errors"].append(f"network_error: {e}")
        
    except Exception as e:
        out["errors"].append(f"other_error: {e}")
        
    return out


def _normalize_hostname(hostname: str) -> str:
    """Normalize and validate hostname"""
    if not hostname:
        return None
        
    # Handle URLs by extracting hostname
    if "://" in hostname:
        try:
            parsed = urlparse(hostname)
            hostname = parsed.hostname or parsed.netloc
        except:
            return None
    
    # Remove port if present
    hostname = hostname.split(':')[0]
    
    # Basic validation
    if not hostname or len(hostname) > 253:
        return None
        
    # Check if it's an IP address
    try:
        ipaddress.ip_address(hostname)
        return hostname  # Valid IP address
    except ValueError:
        pass  # Not an IP, continue with hostname validation
    
    # Basic hostname validation
    if hostname.startswith('.') or hostname.endswith('.') or '..' in hostname:
        return None
        
    return hostname.lower()


def _process_certificate_details(cert, cert_der, hostname, out):
    """Process and extract detailed certificate information"""
    if not cert:
        return
        
    try:
        # Extract subject and issuer information
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        
        out["subject_cn"] = subject.get("commonName")
        out["issuer_cn"] = issuer.get("commonName")
        
        # Enhanced self-signed detection
        out["self_signed_hint"] = _is_self_signed(subject, issuer)
        
        # Certificate expiration handling with timezone awareness
        not_after = cert.get("notAfter")
        not_before = cert.get("notBefore")
        
        if not_after:
            try:
                # Handle different date formats
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=timezone.utc)
                out["expires_on"] = exp.isoformat()
                
                now = datetime.now(timezone.utc)
                out["expired"] = exp < now
                
                # Calculate days until expiration
                days_until_expiry = (exp - now).days
                out["certificate_valid_days"] = days_until_expiry
                
            except ValueError as e:
                out["errors"].append(f"date_parsing_error: {e}")
        
        # Extract Subject Alternative Names (SAN)
        san_list = []
        for subject_alt_name in cert.get("subjectAltName", []):
            if subject_alt_name[0] == "DNS":
                san_list.append(subject_alt_name[1])
        out["san_domains"] = san_list
        
        # Hostname verification
        out["hostname_match"] = _verify_hostname_match(hostname, out["subject_cn"], san_list)
        
        # Check for weak signature algorithms (if certificate data available)
        if cert_der:
            signature_info = _check_signature_algorithm(cert_der)
            out["weak_signature"] = signature_info
            
    except Exception as e:
        out["errors"].append(f"cert_processing_error: {e}")


def _is_self_signed(subject, issuer):
    """Enhanced self-signed certificate detection"""
    if not subject or not issuer:
        return None
        
    # Compare common name
    subject_cn = subject.get("commonName", "").lower()
    issuer_cn = issuer.get("commonName", "").lower()
    
    # Compare organization
    subject_org = subject.get("organizationName", "").lower()
    issuer_org = issuer.get("organizationName", "").lower()
    
    # Self-signed if CN and org match
    return (subject_cn == issuer_cn and subject_org == issuer_org) if subject_cn else None


def _verify_hostname_match(hostname, subject_cn, san_domains):
    """Verify if hostname matches certificate CN or SAN"""
    if not hostname:
        return None
        
    hostname = hostname.lower()
    
    # Check against Common Name
    if subject_cn and _match_hostname_pattern(hostname, subject_cn.lower()):
        return True
        
    # Check against SAN domains
    for san_domain in san_domains:
        if _match_hostname_pattern(hostname, san_domain.lower()):
            return True
            
    return False


def _match_hostname_pattern(hostname, pattern):
    """Match hostname against certificate pattern (supports wildcards)"""
    if hostname == pattern:
        return True
        
    # Handle wildcard certificates (*.example.com)
    if pattern.startswith('*.'):
        pattern_domain = pattern[2:]
        # Match subdomain.example.com against *.example.com
        if '.' in hostname and hostname.split('.', 1)[1] == pattern_domain:
            return True
            
    return False


def _check_signature_algorithm(cert_der):
    """Check for weak signature algorithms"""
    try:
        # This would require additional parsing of DER certificate
        # For now, we'll return None and could be enhanced with cryptography library
        return None
    except:
        return None
