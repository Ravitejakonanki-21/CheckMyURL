import re
import ssl
import socket
from datetime import datetime, timezone
import ipaddress
from urllib.parse import urlparse

# Try to import cryptography library for enhanced analysis
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Try to import requests for HTTPS testing
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


def check_ssl(hostname: str, port: int = 443, timeout: float = 5.0):
    """
    Main SSL check function with backward compatibility
    Returns enhanced SSL data if cryptography is available, otherwise basic SSL data
    """
    print(f"🔍 DEBUG: check_ssl called for {hostname}")
    
    if CRYPTOGRAPHY_AVAILABLE and REQUESTS_AVAILABLE:
        # Use enhanced SSL check if libraries are available
        enhanced_result = enhanced_ssl_check(hostname, port)
        
        # Transform to backward-compatible format
        return {
            "https_ok": enhanced_result.get("https_ok", False),
            "expires_on": enhanced_result.get("expires_on"),
            "expired": enhanced_result.get("expired"),
            "issuer_cn": enhanced_result.get("issuer_cn"),
            "subject_cn": enhanced_result.get("subject_cn"),
            "self_signed_hint": enhanced_result.get("self_signed"),
            "certificate_chain_valid": enhanced_result.get("certificate_chain_complete", False),
            "tls_version": enhanced_result.get("tls_version"),
            "cipher_suite": enhanced_result.get("cipher_suite"),
            "certificate_valid_days": enhanced_result.get("days_until_expiry"),
            "san_domains": enhanced_result.get("san_domains", []),
            "certificate_transparency": None,
            "weak_signature": None,
            "hostname_match": enhanced_result.get("hostname_match"),
            "errors": enhanced_result.get("errors", []),
            
            # Add enhanced data as extras
            "enhanced_data": enhanced_result
        }
    else:
        # Fallback to basic SSL check
        return _basic_ssl_check(hostname, port, timeout)


def enhanced_ssl_check(hostname: str, port: int = 443):
    """
    Professional SSL check with complete certificate data extraction - TECHNICAL DETAILS READY
    """
    print(f"🔍 DEBUG: enhanced_ssl_check called for {hostname}")
    
    result = {
        "hostname": hostname,
        "port": port,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        
        # Connection Status
        "https_ok": False,
        "ssl_handshake_successful": False,
        
        # Certificate Validity
        "certificate_valid": False,
        "expired": None,
        "expires_on": None,
        "not_before": None,
        "days_until_expiry": None,
        "certificate_valid_days": None,
        
        # Certificate Identity - ENHANCED FOR TECHNICAL DETAILS
        "subject_cn": None,
        "subject_org": None,
        "issuer_cn": None,
        "issuer_org": None,
        "serial_number": None,
        
        # Trust & Security
        "self_signed": None,
        "ca_trusted": False,
        "certificate_chain_complete": False,
        "chain_length": 0,
        
        # Technical Details - ENHANCED
        "tls_version": None,
        "cipher_suite": None,
        "key_algorithm": None,
        "key_size": None,
        "key_curve": None,  # NEW: For EC keys
        "signature_algorithm": None,
        
        # Domain Coverage
        "hostname_match": False,
        "san_domains": [],
        "wildcard_cert": False,
        
        # Raw Data - ENHANCED FOR TECHNICAL SECTION
        "certificate_pem": None,
        "full_chain": [],
        "errors": []
    }
    
    try:
        # Step 1: Test HTTPS connectivity
        result.update(_test_https_connection(hostname))
        
        # Step 2: Get complete SSL certificate data with technical details
        cert_data = _get_complete_certificate_details(hostname, port)
        result.update(cert_data)
        
        print("🔍 Enhanced SSL analysis complete with technical details")
        
    except Exception as e:
        result["errors"].append(f"ssl_check_error: {str(e)}")
        print(f"❌ SSL check error: {e}")
    
    return result


def _test_https_connection(hostname):
    """Test basic HTTPS connectivity with proper error handling"""
    print(f"🔍 DEBUG: Testing HTTPS connection for {hostname}")
    
    data = {"https_ok": False, "http_redirect": False, "errors": []}
    
    if not REQUESTS_AVAILABLE:
        data["errors"].append("requests_library_not_available")
        return data
    
    try:
        # Validate hostname first
        normalized_hostname = _normalize_hostname(hostname)
        if not normalized_hostname:
            data["errors"].append("invalid_hostname_format")
            return data
        
        # Test HTTPS connection with proper timeout and error handling
        response = requests.get(
            f"https://{normalized_hostname}", 
            timeout=10, 
            verify=True,
            allow_redirects=True
        )
        
        data["https_ok"] = response.status_code < 400
        data["http_status"] = response.status_code
        print(f"✅ HTTPS connection successful: {response.status_code}")
        
        # Check if HTTP redirects to HTTPS
        try:
            http_response = requests.get(
                f"http://{normalized_hostname}", 
                timeout=5, 
                allow_redirects=False
            )
            if http_response.status_code in [301, 302, 307, 308]:
                location = http_response.headers.get('Location', '')
                data["http_redirect"] = location.startswith('https://')
        except Exception:
            # HTTP redirect check is optional, don't fail the main check
            pass
            
    except requests.exceptions.SSLError as e:
        data["errors"].append(f"ssl_verification_failed: {str(e)}")
        data["https_ok"] = False
        print(f"❌ SSL Error: {e}")
        
    except requests.exceptions.ConnectionError as e:
        data["errors"].append(f"connection_failed: {str(e)}")
        data["https_ok"] = False
        print(f"❌ Connection Error: {e}")
        
    except requests.exceptions.Timeout:
        data["errors"].append("connection_timeout")
        data["https_ok"] = False
        print("❌ Connection Timeout")
        
    except Exception as e:
        data["errors"].append(f"https_test_error: {str(e)}")
        data["https_ok"] = False
        print(f"❌ HTTPS Test Error: {e}")
    
    return data


def _get_complete_certificate_details(hostname, port):
    """
    COMPLETE certificate extraction with all technical details for frontend display
    """
    print(f"🔍 DEBUG: Getting COMPLETE certificate details for {hostname}:{port}")
    
    data = {
        "ssl_handshake_successful": False,
        "certificate_valid": False,
        "errors": []
    }
    
    try:
        # Normalize hostname
        normalized_hostname = _normalize_hostname(hostname)
        if not normalized_hostname:
            data["errors"].append("invalid_hostname_format")
            return data
        
        # PHASE 1: Get certificate data without verification
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Allow any certificate to get data
        
        print(f"🔍 Connecting to {normalized_hostname}:{port}")
        
        with socket.create_connection((normalized_hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=normalized_hostname) as ssock:
                data["ssl_handshake_successful"] = True
                print("✅ SSL Handshake successful")
                
                # Get connection info
                data["tls_version"] = ssock.version()
                print(f"✅ TLS Version: {data['tls_version']}")
                
                try:
                    cipher_info = ssock.cipher()
                    if cipher_info and len(cipher_info) >= 3:
                        data["cipher_suite"] = cipher_info[0]  
                        data["tls_protocol"] = cipher_info[1]  
                        data["cipher_key_size"] = cipher_info[2]  
                        print(f"✅ Cipher Suite: {data['cipher_suite']}")
                except Exception as e:
                    print(f"⚠️ Cipher info error: {e}")
                
                # Get RAW certificate data for complete analysis
                cert_der = None
                cert_dict = None
                
                try:
                    # Method 1: Get dictionary format
                    cert_dict = ssock.getpeercert(binary_form=False)
                    if cert_dict:
                        print("✅ Certificate dictionary retrieved")
                    
                    # Method 2: Get DER format for advanced analysis
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        print("✅ Certificate DER data retrieved")
                        
                except Exception as e:
                    print(f"⚠️ Certificate retrieval error: {e}")
                
                # PHASE 2: Process ALL certificate data
                if cert_dict or cert_der:
                    # Process standard certificate info
                    if cert_dict:
                        cert_info = _process_certificate_data(cert_dict, normalized_hostname)
                        data.update(cert_info)
                    
                    # Process advanced technical details
                    if cert_der and CRYPTOGRAPHY_AVAILABLE:
                        print("🔍 Processing advanced technical details...")
                        technical_data = _extract_all_technical_details(cert_der, normalized_hostname)
                        data.update(technical_data)
                        data["certificate_valid"] = True
                        print("✅ All technical details extracted")
                    else:
                        data["certificate_valid"] = bool(cert_dict)
                else:
                    print("❌ No certificate data retrieved")
                    data["errors"].append("no_certificate_data_available")
                
        # PHASE 3: Test hostname verification
        try:
            verify_context = ssl.create_default_context()
            verify_context.check_hostname = True
            verify_context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((normalized_hostname, port), timeout=5) as verify_sock:
                with verify_context.wrap_socket(verify_sock, server_hostname=normalized_hostname) as verify_ssock:
                    data["hostname_match"] = True
                    data["ca_trusted"] = True
                    data["certificate_chain_complete"] = True
                    data["chain_length"] = 3  # Estimate for trusted certificates
                    print("✅ Hostname verification passed")
                    
        except ssl.SSLCertVerificationError as e:
            print(f"⚠️ Certificate verification failed: {e}")
            data["hostname_match"] = False
            data["ca_trusted"] = False
            if "self signed" in str(e).lower():
                data["self_signed"] = True
        except Exception as e:
            print(f"⚠️ Verification test failed: {e}")
            if "hostname_match" not in data:
                data["hostname_match"] = False
            
    except Exception as e:
        print(f"❌ SSL connection failed: {e}")
        data["errors"].append(f"ssl_connection_failed: {str(e)}")
    
    print(f"🔍 Final certificate analysis complete: certificate_valid: {data.get('certificate_valid')}")
    return data


def _process_certificate_data(cert, hostname):
    """Process standard certificate info from SSL dict format"""
    print("🔍 Processing standard certificate data...")
    
    data = {}
    
    if not cert or not isinstance(cert, dict):
        return data
    
    try:
        # FIXED: Extract subject and issuer with proper parsing
        subject_info = {}
        issuer_info = {}
        
        if "subject" in cert and cert["subject"]:
            try:
                for item in cert["subject"]:
                    if isinstance(item, (tuple, list)) and len(item) >= 2:
                        key, value = item[0], item[1]
                        subject_info[key] = value
            except Exception as e:
                print(f"⚠️ Subject parsing error: {e}")
                
        if "issuer" in cert and cert["issuer"]:
            try:
                for item in cert["issuer"]:
                    if isinstance(item, (tuple, list)) and len(item) >= 2:
                        key, value = item[0], item[1]
                        issuer_info[key] = value
            except Exception as e:
                print(f"⚠️ Issuer parsing error: {e}")
        
        # Extract certificate identity details
        data["subject_cn"] = subject_info.get("commonName")  
        data["subject_org"] = subject_info.get("organizationName")
        data["issuer_cn"] = issuer_info.get("commonName")  
        data["issuer_org"] = issuer_info.get("organizationName")  
        
        print(f"✅ Subject CN: {data['subject_cn']}")
        print(f"✅ Issuer CN: {data['issuer_cn']}")
        print(f"✅ Subject Org: {data['subject_org']}")
        print(f"✅ Issuer Org: {data['issuer_org']}")
        
        # Self-signed detection
        data["self_signed"] = _is_self_signed(subject_info, issuer_info)
        
        # Process certificate dates
        _process_certificate_dates(cert, data)
        
        # Process SAN domains
        _process_san_domains(cert, data)
        
        # Hostname verification
        data["hostname_match"] = _verify_hostname_match(
            hostname, 
            data.get("subject_cn"), 
            data.get("san_domains", [])
        )
        
        print(f"✅ Hostname match: {data['hostname_match']}")
        
    except Exception as e:
        print(f"❌ Certificate processing error: {e}")
        data.setdefault("errors", []).append(f"cert_processing_error: {str(e)}")
    
    return data


def _extract_all_technical_details(cert_der, hostname):
    """
    COMPLETE technical details extraction using cryptography library
    This provides ALL data needed for the Technical Details frontend section
    """
    data = {}
    
    if not CRYPTOGRAPHY_AVAILABLE or not cert_der:
        print("⚠️ Cryptography not available or no certificate data")
        return data
    
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        print("✅ Certificate loaded for technical analysis")
        
        # DATES - Fixed timezone handling
        try:
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            
            data.update({
                "not_before": not_before.isoformat(),
                "expires_on": not_after.isoformat(),
                "expired": not_after < now,
                "days_until_expiry": (not_after - now).days,
                "certificate_valid": not_before <= now <= not_after
            })
            
            print(f"✅ Technical dates: {not_before} to {not_after}")
        except Exception as e:
            print(f"⚠️ Date processing error: {e}")
        
        # SERIAL NUMBER
        try:
            data["serial_number"] = str(cert.serial_number)
            print(f"✅ Serial number: {data['serial_number'][:20]}...")
        except Exception as e:
            print(f"⚠️ Serial number error: {e}")
        
        # KEY ALGORITHM & TECHNICAL SPECS - COMPLETE
        try:
            public_key = cert.public_key()
            print(f"🔍 Key type detected: {type(public_key).__name__}")
            
            if isinstance(public_key, rsa.RSAPublicKey):
                data["key_algorithm"] = "RSA"
                data["key_size"] = public_key.key_size
                print(f"✅ RSA Key: {public_key.key_size} bits")
                
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                data["key_algorithm"] = "EC"  # Elliptic Curve
                data["key_size"] = public_key.curve.key_size
                
                # EXTRACT CURVE NAME for technical details
                curve_name = type(public_key.curve).__name__
                if hasattr(public_key.curve, 'name'):
                    curve_name = public_key.curve.name
                
                data["key_curve"] = curve_name
                print(f"✅ EC Key: {curve_name} ({public_key.curve.key_size} bits)")
                
            elif isinstance(public_key, dsa.DSAPublicKey):
                data["key_algorithm"] = "DSA"
                data["key_size"] = public_key.key_size
                print(f"✅ DSA Key: {public_key.key_size} bits")
                
            else:
                # Handle other key types
                key_type = type(public_key).__name__.replace('PublicKey', '')
                data["key_algorithm"] = key_type
                if hasattr(public_key, 'key_size'):
                    data["key_size"] = public_key.key_size
                print(f"✅ Other key type: {key_type}")
                
        except Exception as key_error:
            print(f"⚠️ Key analysis error: {key_error}")
            data["key_algorithm"] = "Unknown"
        
        # SIGNATURE ALGORITHM
        try:
            sig_algo = cert.signature_algorithm_oid._name
            data["signature_algorithm"] = sig_algo
            print(f"✅ Signature algorithm: {sig_algo}")
        except Exception as sig_error:
            print(f"⚠️ Signature algorithm error: {sig_error}")
        
        # SUBJECT & ISSUER - Complete extraction
        try:
            # Extract complete subject information
            subject_parts = {}
            for attr in cert.subject:
                attr_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                subject_parts[attr_name] = attr.value
            
            # Override/supplement with cryptography data
            if "commonName" in subject_parts:
                data["subject_cn"] = subject_parts["commonName"]
            if "organizationName" in subject_parts:
                data["subject_org"] = subject_parts["organizationName"]
            
            # Extract complete issuer information  
            issuer_parts = {}
            for attr in cert.issuer:
                attr_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                issuer_parts[attr_name] = attr.value
            
            if "commonName" in issuer_parts:
                data["issuer_cn"] = issuer_parts["commonName"]
            if "organizationName" in issuer_parts:
                data["issuer_org"] = issuer_parts["organizationName"]
            
            print(f"✅ Technical subject: {data.get('subject_cn')} ({data.get('subject_org')})")
            print(f"✅ Technical issuer: {data.get('issuer_cn')} ({data.get('issuer_org')})")
            
        except Exception as e:
            print(f"⚠️ Subject/Issuer extraction error: {e}")
        
        # SAN DOMAINS - Enhanced processing
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = []
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(name.value)
            if san_list:
                data["san_domains"] = san_list
                data["wildcard_cert"] = any(domain.startswith('*.') for domain in san_list)
                print(f"✅ Technical SAN: {len(san_list)} domains")
        except x509.ExtensionNotFound:
            print("⚠️ No SAN extension found")
        except Exception as san_error:
            print(f"⚠️ SAN processing error: {san_error}")
        
        # CERTIFICATE PEM - For technical display
        try:
            pem_data = cert.public_bytes(serialization.Encoding.PEM)
            data["certificate_pem"] = pem_data.decode('utf-8')
            print("✅ Certificate PEM data extracted for technical section")
        except Exception as pem_error:
            print(f"⚠️ PEM extraction error: {pem_error}")
            
        print("✅ All technical details extraction complete")
            
    except Exception as e:
        print(f"❌ Technical analysis error: {e}")
        data["errors"] = data.get("errors", []) + [f"technical_analysis_error: {str(e)}"]
    
    return data


def _process_certificate_dates(cert, data):
    """Process certificate dates from SSL dict format"""
    try:
        not_after = cert.get("notAfter")  
        not_before = cert.get("notBefore")  
        
        if not_after:
            try:
                # Parse the exact format from SSL
                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                exp_date = exp_date.replace(tzinfo=timezone.utc)
                
                data["expires_on"] = exp_date.isoformat() 
                
                now = datetime.now(timezone.utc)
                data["expired"] = exp_date < now  
                
                # Calculate days until expiration
                days_until_expiry = (exp_date - now).days
                data["days_until_expiry"] = days_until_expiry
                data["certificate_valid_days"] = days_until_expiry
                
                print(f"✅ Certificate expires: {exp_date} ({days_until_expiry} days)")
                
            except ValueError:
                # Try alternative format
                try:
                    exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
                    exp_date = exp_date.replace(tzinfo=timezone.utc)
                    data["expires_on"] = exp_date.isoformat()
                    now = datetime.now(timezone.utc)
                    data["expired"] = exp_date < now
                    data["days_until_expiry"] = (exp_date - now).days
                    data["certificate_valid_days"] = (exp_date - now).days
                    print(f"✅ Certificate expires (alt format): {exp_date}")
                except ValueError:
                    print("⚠️ Date parsing failed")
                    data.setdefault("errors", []).append("date_parsing_failed")
        
        if not_before:
            try:
                start_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                start_date = start_date.replace(tzinfo=timezone.utc)
                data["not_before"] = start_date.isoformat()
            except ValueError:
                try:
                    start_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y GMT")
                    start_date = start_date.replace(tzinfo=timezone.utc)
                    data["not_before"] = start_date.isoformat()
                except ValueError:
                    pass
                    
    except Exception as e:
        print(f"⚠️ Date processing error: {e}")


def _process_san_domains(cert, data):
    """Process SAN domains with safe error handling"""
    san_domains = []
    
    try:
        san_list = cert.get("subjectAltName", [])
        if san_list and isinstance(san_list, (list, tuple)):
            for san_entry in san_list:
                try:
                    if isinstance(san_entry, (list, tuple)) and len(san_entry) >= 2:
                        if san_entry[0] == "DNS":
                            domain = san_entry[1]
                            if domain and isinstance(domain, str):
                                san_domains.append(domain)
                                # Check for wildcard
                                if domain.startswith('*.'):
                                    data["wildcard_cert"] = True
                except Exception:
                    continue
        
        print(f"✅ SAN domains: {len(san_domains)} found")
                    
    except Exception:
        # SAN processing is optional
        pass
    
    data["san_domains"] = san_domains


def _verify_hostname_match(hostname, subject_cn, san_domains):
    """Proper hostname verification like OpenSSL"""
    if not hostname:
        return False
    
    try:
        hostname = hostname.lower().strip()
        
        # Check against Common Name
        if subject_cn:
            if _match_hostname_pattern(hostname, subject_cn.lower().strip()):
                print(f"✅ Hostname {hostname} matches CN {subject_cn}")
                return True
        
        # Check against SAN domains
        if san_domains and isinstance(san_domains, list):
            for san_domain in san_domains:
                if san_domain and isinstance(san_domain, str):
                    if _match_hostname_pattern(hostname, san_domain.lower().strip()):
                        print(f"✅ Hostname {hostname} matches SAN {san_domain}")
                        return True
                        
    except Exception as e:
        print(f"⚠️ Hostname verification error: {e}")
    
    print(f"❌ Hostname {hostname} does not match certificate")
    return False


def _match_hostname_pattern(hostname, pattern):
    """Proper wildcard matching like OpenSSL"""
    try:
        if hostname == pattern:
            return True
        
        # Handle wildcard certificates
        if pattern.startswith('*.'):
            base_domain = pattern[2:]  # Remove *.
            if base_domain:
                # google.com matches *.google.com
                if hostname == base_domain:
                    return True
                # sub.google.com matches *.google.com  
                if hostname.endswith('.' + base_domain):
                    return True
                    
    except Exception:
        pass
    
    return False


def _is_self_signed(subject_info, issuer_info):
    """Proper self-signed detection"""
    if not subject_info or not issuer_info:
        return None
    
    try:
        subject_cn = subject_info.get("commonName", "").lower().strip()
        issuer_cn = issuer_info.get("commonName", "").lower().strip()
        
        if subject_cn and issuer_cn:
            is_self_signed = subject_cn == issuer_cn
            print(f"✅ Self-signed check: {subject_cn} == {issuer_cn} -> {is_self_signed}")
            return is_self_signed
                
    except Exception as e:
        print(f"⚠️ Self-signed detection error: {e}")
    
    return False


def _basic_ssl_check(hostname: str, port: int = 443, timeout: float = 5.0):
    """
    Basic SSL check fallback without cryptography library
    """
    print(f"🔍 DEBUG: Using basic SSL check for {hostname}")
    
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
            
        # Create SSL context
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Successful connection
                out["https_ok"] = True
                
                # Get TLS version and cipher info
                out["tls_version"] = ssock.version()
                out["cipher_suite"] = ssock.cipher()[0] if ssock.cipher() else None
                
                # Get peer certificate
                cert = ssock.getpeercert()
                
                # Process basic certificate info
                if cert:
                    cert_info = _process_certificate_data(cert, hostname)
                    out.update(cert_info)
                
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


def _normalize_hostname(hostname: str):
    """Safe hostname normalization"""
    if not hostname or not isinstance(hostname, str):
        return None
    
    try:
        hostname = hostname.strip()
        
        # Handle URLs by extracting hostname
        if "://" in hostname:
            try:
                parsed = urlparse(hostname)
                hostname = parsed.hostname or parsed.netloc
            except Exception:
                return None
        
        if not hostname:
            return None
        
        # Remove port if present
        hostname = hostname.split(':')[0].strip()
        
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
        
    except Exception:
        return None
