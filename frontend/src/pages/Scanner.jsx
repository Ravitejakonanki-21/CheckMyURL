import { useState } from "react";
import { explain } from "../utils/riskExplain";
import { useScan } from "../context/ScanContext";

// PDF deps: npm i jspdf jspdf-autotable (then restart dev server)
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

function Scanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [expandedRows, setExpandedRows] = useState({});
  const { recordScan } = useScan();

  // Toggle row expansion
  const toggleRowExpansion = (rowKey) => {
    setExpandedRows(prev => ({
      ...prev,
      [rowKey]: !prev[rowKey]
    }));
  };

  // Backend API integration function
  const analyzeUrl = async (inputUrl) => {
    try {
      const response = await fetch('http://127.0.0.1:5000/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: inputUrl })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return data;
    } catch (err) {
      console.error('API Error:', err);
      throw err;
    }
  };

  // SSL/TLS detailed analysis component
  const SSLDetails = ({ sslData }) => {
    const formatDate = (dateString) => {
      if (!dateString) return "Not available";
      try {
        return new Date(dateString).toLocaleDateString() + " " + new Date(dateString).toLocaleTimeString();
      } catch {
        return dateString;
      }
    };

    const getDaysUntilExpiry = (expiresOn) => {
      if (!expiresOn) return null;
      try {
        const expiry = new Date(expiresOn);
        const now = new Date();
        const diffTime = expiry - now;
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        return diffDays;
      } catch {
        return null;
      }
    };

    const daysUntilExpiry = getDaysUntilExpiry(sslData?.expires_on);

    const checks = [
      {
        name: "HTTPS Connection",
        description: "SSL/TLS connection established successfully",
        value: sslData?.https_ok,
        status: sslData?.https_ok ? 'good' : 'bad',
        details: sslData?.https_ok ? "Secure HTTPS connection established" : "Failed to establish HTTPS connection"
      },
      {
        name: "Certificate Validity",
        description: "Certificate is currently valid and not expired",
        value: sslData?.expired === false && sslData?.expires_on,
        status: sslData?.expired === false ? 'good' : sslData?.expired === true ? 'bad' : 'warning',
        details: sslData?.expired === false ? "Certificate is currently valid" : 
                sslData?.expired === true ? "Certificate has expired" : "Certificate validity unknown"
      },
      {
        name: "Certificate Expiration",
        description: "When the SSL certificate expires",
        value: sslData?.expires_on,
        status: daysUntilExpiry > 30 ? 'good' : daysUntilExpiry > 7 ? 'warning' : 'bad',
        details: sslData?.expires_on ? 
          `Expires: ${formatDate(sslData.expires_on)}${daysUntilExpiry !== null ? ` (${daysUntilExpiry} days remaining)` : ''}` :
          "Expiration date not available"
      },
      {
        name: "Certificate Authority",
        description: "Who issued the SSL certificate",
        value: sslData?.issuer_cn,
        status: sslData?.issuer_cn ? 'good' : 'warning',
        details: sslData?.issuer_cn ? `Issued by: ${sslData.issuer_cn}` : "Certificate authority information not available"
      },
      {
        name: "Subject Common Name",
        description: "The domain name the certificate is issued for",
        value: sslData?.subject_cn,
        status: sslData?.subject_cn ? 'good' : 'warning',
        details: sslData?.subject_cn ? `Certificate issued for: ${sslData.subject_cn}` : "Subject common name not available"
      },
      {
        name: "Self-Signed Check",
        description: "Whether the certificate is self-signed (less secure)",
        value: sslData?.self_signed_hint === false,
        status: sslData?.self_signed_hint === false ? 'good' : sslData?.self_signed_hint === true ? 'bad' : 'warning',
        details: sslData?.self_signed_hint === false ? "Certificate issued by trusted CA" :
                sslData?.self_signed_hint === true ? "Self-signed certificate (security risk)" :
                "Self-signed status unknown"
      },
      {
        name: "TLS Version",
        description: "The TLS protocol version being used",
        value: sslData?.tls_version,
        status: sslData?.tls_version === 'TLSv1.3' ? 'good' : 
                sslData?.tls_version === 'TLSv1.2' ? 'good' : 
                sslData?.tls_version ? 'warning' : 'bad',
        details: sslData?.tls_version ? `Using ${sslData.tls_version}` : "TLS version information not available"
      },
      {
        name: "Cipher Suite",
        description: "The encryption cipher being used",
        value: sslData?.cipher_suite,
        status: sslData?.cipher_suite ? 'good' : 'warning',
        details: sslData?.cipher_suite ? `Cipher: ${sslData.cipher_suite}` : "Cipher suite information not available"
      },
      {
        name: "Certificate Chain",
        description: "Whether the certificate chain is complete",
        value: sslData?.certificate_chain_valid,
        status: sslData?.certificate_chain_valid === true ? 'good' : 
                sslData?.certificate_chain_valid === false ? 'warning' : 'warning',
        details: sslData?.certificate_chain_valid === true ? "Complete certificate chain present" :
                sslData?.certificate_chain_valid === false ? "Incomplete certificate chain" :
                "Certificate chain status unknown"
      },
      {
        name: "Hostname Match",
        description: "Whether the certificate matches the hostname",
        value: sslData?.hostname_match,
        status: sslData?.hostname_match === true ? 'good' : 
                sslData?.hostname_match === false ? 'bad' : 'warning',
        details: sslData?.hostname_match === true ? "Certificate matches hostname" :
                sslData?.hostname_match === false ? "Certificate does not match hostname" :
                "Hostname verification status unknown"
      }
    ];

    // Add SAN domains if available
    if (sslData?.san_domains && sslData.san_domains.length > 0) {
      checks.push({
        name: "Subject Alternative Names",
        description: "Additional domains covered by this certificate",
        value: sslData.san_domains,
        status: 'good',
        details: `Also covers: ${sslData.san_domains.join(', ')}`
      });
    }

    return (
      <div className="mt-3 p-4 bg-blue-50 border border-blue-200 rounded-lg dark:bg-gray-900 dark:border-blue-500/30">
        <h4 className="font-medium text-sm mb-3 text-gray-900 dark:text-blue-400">SSL/TLS Security Analysis</h4>
        <div className="space-y-2">
          {checks.map((check, index) => (
            <div key={index} className="flex items-center justify-between py-2 px-3 bg-white rounded border border-gray-200 dark:bg-black dark:border-blue-500/20">
              <div className="flex items-center space-x-3">
                <div className={`w-3 h-3 rounded-full ${
                  check.status === 'good' ? 'bg-green-500' :
                  check.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                }`}></div>
                <div>
                  <div className="font-medium text-sm text-gray-900 dark:text-blue-300">{check.name}</div>
                  <div className="text-xs text-gray-500 dark:text-blue-200/70">{check.description}</div>
                </div>
              </div>
              <div className="text-right">
                <div className={`text-sm font-medium ${
                  check.status === 'good' ? 'text-green-600 dark:text-green-400' :
                  check.status === 'warning' ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400'
                }`}>
                  {check.status === 'good' ? '✓' : check.status === 'warning' ? '⚠' : '✗'}
                </div>
                <div className="text-xs text-gray-600 dark:text-blue-200 max-w-48 text-right">{check.details}</div>
              </div>
            </div>
          ))}
        </div>
        
        {sslData?.errors && sslData.errors.length > 0 && (
          <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded dark:bg-red-900/20 dark:border-red-800">
            <h5 className="font-medium text-sm text-red-800 dark:text-red-300 mb-2">SSL/TLS Errors:</h5>
            {sslData.errors.map((error, index) => (
              <div key={index} className="text-xs text-red-700 dark:text-red-400">• {error}</div>
            ))}
          </div>
        )}

        {/* Certificate Summary */}
        {sslData?.https_ok && (
          <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded dark:bg-blue-900/20 dark:border-blue-500">
            <h5 className="font-medium text-sm text-blue-800 dark:text-blue-300 mb-2">Certificate Summary:</h5>
            <div className="text-xs text-blue-700 dark:text-blue-200 space-y-1">
              {sslData.subject_cn && <div>• Subject: {sslData.subject_cn}</div>}
              {sslData.issuer_cn && <div>• Issuer: {sslData.issuer_cn}</div>}
              {sslData.expires_on && <div>• Expires: {formatDate(sslData.expires_on)}</div>}
              {sslData.tls_version && <div>• Protocol: {sslData.tls_version}</div>}
              {daysUntilExpiry !== null && (
                <div className={`font-medium ${daysUntilExpiry > 30 ? 'text-green-600 dark:text-green-400' : daysUntilExpiry > 7 ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400'}`}>
                  • Status: {daysUntilExpiry > 0 ? `Valid for ${daysUntilExpiry} days` : 'Expired'}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  // WHOIS detailed analysis component
  const WhoisDetails = ({ whoisData }) => {
    const checks = [
      {
        name: "Domain Name",
        description: "Verify correct spelling and TLD",
        value: whoisData?.domain,
        status: whoisData?.domain ? 'good' : 'bad',
        details: whoisData?.domain ? `Domain: ${whoisData.domain}` : "Domain name not found"
      },
      {
        name: "Registrar",
        description: "Who manages the domain registration",
        value: whoisData?.registrar,
        status: whoisData?.registrar ? 'good' : 'bad',
        details: whoisData?.registrar ? `Managed by: ${whoisData.registrar}` : "Registrar information not available"
      },
      {
        name: "Creation Date",
        description: "When the domain was first registered",
        value: whoisData?.creation_date,
        status: whoisData?.creation_date ? 'good' : 'bad',
        details: whoisData?.creation_date ? `Registered: ${new Date(whoisData.creation_date).toLocaleDateString()}` : "Creation date not available"
      },
      {
        name: "Expiration Date", 
        description: "When the domain registration ends",
        value: whoisData?.expiration_date,
        status: whoisData?.expiration_date ? 'good' : 'bad',
        details: whoisData?.expiration_date ? `Expires: ${new Date(whoisData.expiration_date).toLocaleDateString()}` : "Expiration date not available"
      },
      {
        name: "Last Updated",
        description: "Last time the domain info changed",
        value: whoisData?.updated_date,
        status: whoisData?.updated_date ? 'good' : 'warning',
        details: whoisData?.updated_date ? `Updated: ${new Date(whoisData.updated_date).toLocaleDateString()}` : "Last update date not available"
      },
      {
        name: "Domain Age",
        description: "How long the domain has been registered",
        value: whoisData?.age_days,
        status: whoisData?.age_days > 365 ? 'good' : whoisData?.age_days > 30 ? 'warning' : 'bad',
        details: whoisData?.age_days 
          ? `${Math.round(whoisData.age_days / 365)} years old (${whoisData.age_days} days)`
          : "Domain age cannot be determined"
      }
    ];

    return (
      <div className="mt-3 p-4 bg-blue-50 border border-blue-200 rounded-lg dark:bg-gray-900 dark:border-blue-500/30">
        <h4 className="font-medium text-sm mb-3 text-gray-900 dark:text-blue-400">WHOIS Checkup Details</h4>
        <div className="space-y-2">
          {checks.map((check, index) => (
            <div key={index} className="flex items-center justify-between py-2 px-3 bg-white rounded border border-gray-200 dark:bg-black dark:border-blue-500/20">
              <div className="flex items-center space-x-3">
                <div className={`w-3 h-3 rounded-full ${
                  check.status === 'good' ? 'bg-green-500' :
                  check.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                }`}></div>
                <div>
                  <div className="font-medium text-sm text-gray-900 dark:text-blue-300">{check.name}</div>
                  <div className="text-xs text-gray-500 dark:text-blue-200/70">{check.description}</div>
                </div>
              </div>
              <div className="text-right">
                <div className={`text-sm font-medium ${
                  check.status === 'good' ? 'text-green-600 dark:text-green-400' :
                  check.status === 'warning' ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400'
                }`}>
                  {check.value ? '✓' : '✗'}
                </div>
                <div className="text-xs text-gray-600 dark:text-blue-200">{check.details}</div>
              </div>
            </div>
          ))}
        </div>
        
        {whoisData?.errors && whoisData.errors.length > 0 && (
          <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded dark:bg-red-900/20 dark:border-red-800">
            <h5 className="font-medium text-sm text-red-800 dark:text-red-300 mb-2">Errors Encountered:</h5>
            {whoisData.errors.map((error, index) => (
              <div key={index} className="text-xs text-red-700 dark:text-red-400">• {error}</div>
            ))}
          </div>
        )}
      </div>
    );
  };

  // Transform backend response to frontend format
  const transformBackendResponse = (backendData) => {
    const results = backendData.results || {};
    const headers = results.headers || {};
    const ssl = results.ssl || {};
    const whois = results.whois || {};
    const rules = results.rules || {};
    const idn = results.idn || {};

    // Calculate risk components based on backend data
    let safeScore = 0;
    let suspiciousScore = 0;
    let dangerousScore = 0;

    // Risk assessment logic based on your backend structure
    if (ssl.https_ok && !ssl.expired && !ssl.self_signed_hint) {
      safeScore += 30;
    } else {
      if (ssl.expired) dangerousScore += 25;
      if (ssl.self_signed_hint) suspiciousScore += 15;
      if (!ssl.https_ok) suspiciousScore += 20;
    }

    // Security headers assessment
    const securityHeaders = headers.security_headers || {};
    const headerCount = Object.values(securityHeaders).filter(Boolean).length;
    if (headerCount >= 3) {
      safeScore += 20;
    } else if (headerCount >= 1) {
      safeScore += 10;
    } else {
      suspiciousScore += 15;
    }

    // WHOIS age assessment - CORRECTED CALCULATION
    const whoisAgeMonths = (() => {
      if (!whois.creation_date) return 0;
      
      try {
        const creationDate = new Date(whois.creation_date);
        const currentDate = new Date();
        
        let months = (currentDate.getFullYear() - creationDate.getFullYear()) * 12;
        months += currentDate.getMonth() - creationDate.getMonth();
        
        // Adjust for partial months
        if (currentDate.getDate() < creationDate.getDate()) {
          months--;
        }
        
        return Math.max(0, months); // Ensure non-negative
      } catch (error) {
        // Fallback to days calculation if date parsing fails
        return whois.age_days ? Math.round(whois.age_days / 30.44) : 0;
      }
    })();

    // Age-based risk assessment
    if (whoisAgeMonths > 12) { // > 1 year
      safeScore += 25;
    } else if (whoisAgeMonths > 3) { // > 3 months
      safeScore += 10;
    } else {
      suspiciousScore += 20;
    }

    // Suspicious patterns
    if (rules.has_suspicious_words || rules.has_brand_words_in_host) {
      suspiciousScore += 25;
    }

    // IDN/Punycode risks
    if (idn.is_idn || idn.mixed_confusable_scripts) {
      suspiciousScore += 15;
    }

    // Normalize scores to 100%
    const total = Math.max(safeScore + suspiciousScore + dangerousScore, 100);
    const normalizedSafe = Math.round((safeScore / total) * 100);
    const normalizedSuspicious = Math.round((suspiciousScore / total) * 100);
    const normalizedDangerous = 100 - normalizedSafe - normalizedSuspicious;

    // Determine classification
    let classification = "Low Risk";
    if (backendData.risk_score >= 70) classification = "High Risk";
    else if (backendData.risk_score >= 40) classification = "Medium Risk";

    // Extract security headers present
    const presentHeaders = [];
    if (securityHeaders.strict_transport_security) presentHeaders.push("HSTS");
    if (securityHeaders.content_security_policy) presentHeaders.push("CSP");
    if (securityHeaders.x_content_type_options) presentHeaders.push("X-Content-Type-Options");
    if (securityHeaders.x_frame_options) presentHeaders.push("X-Frame-Options");
    if (securityHeaders.referrer_policy) presentHeaders.push("Referrer-Policy");

    // Extract suspicious keywords
    const keywords = [];
    if (rules.matched_suspicious && rules.matched_suspicious.length > 0) {
      keywords.push(...rules.matched_suspicious);
    }
    if (rules.matched_brands && rules.matched_brands.length > 0) {
      keywords.push(...rules.matched_brands);
    }

    // Simulate ML phishing score based on available data
    const mlPhishingScore = Math.min(
      Math.round(
        (rules.has_suspicious_words ? 0.3 : 0) +
        (rules.has_brand_words_in_host ? 0.4 : 0) +
        (idn.is_idn ? 0.2 : 0) +
        (!ssl.https_ok ? 0.1 : 0)
      ) * 100, 100
    );

    return {
      url: backendData.url,
      riskScore: backendData.risk_score,
      classification: classification,
      details: {
        sslValid: ssl.https_ok || false,
        sslExpired: ssl.expired || false,
        sslSelfSigned: ssl.self_signed_hint || false,
        whoisAgeMonths: whoisAgeMonths,
        openPorts: [], // Your backend doesn't include port scan yet
        securityHeaders: presentHeaders,
        keywords: keywords,
        mlPhishingScore: mlPhishingScore,
        httpStatus: headers.status || null,
        redirects: headers.redirects || 0,
        httpsRedirect: headers.https_redirect,
        domainAge: whois.age_days || 0,
        registrar: whois.registrar || "Unknown",
        whoisData: whois, // Store full WHOIS data for detailed view
        sslData: ssl, // Store full SSL data for detailed view
        errors: {
          ssl: ssl.errors || [],
          headers: headers.errors || [],
          whois: whois.errors || [],
          idn: idn.errors || [],
          rules: rules.errors || []
        }
      }
    };
  };

  const onScan = async () => {
    if (!url.trim()) return;
    
    setLoading(true);
    setError(null);
    
    try {
      // Call your Flask backend
      const backendResponse = await analyzeUrl(url.trim());
      
      // Transform backend response to frontend format
      const transformedResult = transformBackendResponse(backendResponse);
      
      setResult(transformedResult);
      recordScan(transformedResult);
    } catch (err) {
      setError(`Analysis failed: ${err.message}. Make sure your Flask backend is running on http://127.0.0.1:5000`);
      console.error('Scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  const onClear = () => {
    setUrl("");
    setResult(null);
    setError(null);
    setLoading(false);
    setExpandedRows({});
  };

  const exportPdf = () => {
    try {
      if (!result) {
        alert("No scan results available to export.");
        return;
      }

      const doc = new jsPDF({ unit: "pt", format: "a4" });

      doc.setFont("helvetica", "bold");
      doc.setFontSize(16);
      doc.text("URL Safety Report", 40, 40);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      const ts = new Date().toLocaleString();
      doc.text(`Generated: ${ts}`, 40, 60);
      doc.text(`URL: ${String(result.url ?? "")}`, 40, 76);
      doc.text(`Risk Score: ${String(result.riskScore ?? "")}`, 40, 92);
      doc.text(`Classification: ${String(result.classification ?? "")}`, 40, 108);

      const d = result.details || {};
      const rows = [
        ["SSL Valid", d.sslValid ? "Yes" : "No"],
        ["WHOIS Age (months)", String(d.whoisAgeMonths ?? "")],
        ["Open Ports", Array.isArray(d.openPorts) ? d.openPorts.join(", ") || "None" : "None"],
        ["Security Headers", Array.isArray(d.securityHeaders) ? d.securityHeaders.join(", ") || "None" : "None"],
        ["Keywords", Array.isArray(d.keywords) ? d.keywords.join(", ") || "None" : "None"],
        ["ML Phishing Score", String(d.mlPhishingScore ?? "")],
      ];

      autoTable(doc, {
        startY: 130,
        head: [["Field", "Value"]],
        body: rows,
        styles: { fontSize: 10, cellPadding: 6 },
        headStyles: { fillColor: [67, 56, 202] },
        theme: "grid",
        margin: { left: 40, right: 40 },
      });

      const comp = ["Safe", "Suspicious", "Dangerous"]
        .map((l, i) => `${l}: ${result.pie?.series?.[i] ?? ""}%`)
        .join(" | ");
      const finalY = doc.lastAutoTable?.finalY || 130;
      doc.text(`Risk Composition: ${comp}`, 40, finalY + 24);

      doc.save(`url-safety-report-${Date.now()}.pdf`);
      console.log("PDF with tables exported successfully");
    } catch (e) {
      console.error("Export error:", e);
      alert("PDF export failed. Please check the console for details.");
    }
  };

  return (
    <div className="min-h-screen bg-white dark:bg-black">
      {/* Header */}
      <div className="text-center pt-16 pb-8">
        <h1 className="text-4xl font-normal text-gray-900 dark:text-blue-400 mb-3">
          URL Safety Scanner
        </h1>
        <p className="text-lg text-gray-600 dark:text-blue-300">
          Check if a website is safe to visit
        </p>
      </div>

      {/* Scanner Input */}
      <div className="max-w-2xl mx-auto px-4 mb-8">
        <div className="flex flex-col items-center space-y-4">
          {/* URL Input */}
          <div className="w-full max-w-xl">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan (e.g., https://example.com)"
              className="w-full px-6 py-4 text-base border border-gray-300 rounded-full bg-white text-gray-900 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 dark:bg-black dark:border-blue-500 dark:text-blue-300 dark:placeholder-blue-400/70 dark:focus:ring-blue-400"
              onKeyPress={(e) => e.key === 'Enter' && onScan()}
              disabled={loading}
            />
          </div>

          {/* Scan Button */}
          <button
            onClick={onScan}
            disabled={loading || !url.trim()}
            className="px-8 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium rounded-lg text-base transition-all duration-200 flex items-center gap-2 dark:bg-blue-500 dark:hover:bg-blue-400 dark:disabled:bg-gray-600 dark:text-black"
          >
            {loading ? (
              <>
                <svg className="animate-spin h-5 w-5 text-white dark:text-black" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Scanning...
              </>
            ) : (
              <>
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Scan URL
              </>
            )}
          </button>

          {/* Error Display */}
          {error && (
            <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg max-w-xl dark:bg-red-900/20 dark:border-red-800">
              <p className="text-red-600 dark:text-red-400 text-sm text-center">{error}</p>
            </div>
          )}
        </div>
      </div>

      {/* Feature Tags */}
      <div className="max-w-4xl mx-auto px-4 mb-12">
        <div className="flex flex-wrap justify-center gap-6">
          {[
            { name: "SSL/TLS Check", icon: "🔒" },
            { name: "WHOIS Lookup", icon: "🌐" },
            { name: "Security Headers", icon: "🛡️" },
            { name: "ML Analysis", icon: "🤖" },
            { name: "Keyword Detection", icon: "🔍" },
          ].map((feature, index) => (
            <div key={index} className="text-center px-4 py-2">
              <div className="text-2xl mb-1">{feature.icon}</div>
              <div className="text-sm font-medium text-gray-700 dark:text-blue-300">{feature.name}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Results Section - Only shown after scan */}
      {result && (
        <div className="max-w-6xl mx-auto px-4 pb-12 animate-fade-in">
          {/* Summary Section */}
          <div className="mb-8 text-center">
            <h2 className="text-2xl font-semibold text-gray-900 dark:text-blue-400 mb-4">
              Scan Results for: {result.url}
            </h2>
            <div className="inline-flex items-center gap-4 bg-gray-50 rounded-lg px-6 py-3 dark:bg-gray-900">
              <span className="text-lg font-medium text-gray-700 dark:text-blue-300">
                Risk Score: <span className={result.riskScore >= 70 ? 'text-red-600 dark:text-red-400' : result.riskScore >= 40 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'}>
                  {result.riskScore}
                </span>
              </span>
              <span className="text-gray-400 dark:text-blue-500">•</span>
              <span className="text-lg font-medium text-gray-700 dark:text-blue-300">
                Classification: <span className={result.classification === 'High Risk' ? 'text-red-600 dark:text-red-400' : result.classification === 'Medium Risk' ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'}>
                  {result.classification}
                </span>
              </span>
            </div>
          </div>

          {/* Risk Explanation */}
          <div className="mb-8 p-6 bg-blue-50 rounded-lg dark:bg-gray-900">
            <h3 className="text-xl font-semibold text-gray-900 dark:text-blue-400 mb-4">Risk Analysis</h3>
            <div className="text-gray-700 dark:text-blue-200 leading-relaxed">
              {explain(result)}
            </div>
          </div>

          {/* Detailed Results */}
          <div className="border border-gray-200 rounded-lg overflow-hidden dark:border-blue-500/30">
            <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4 dark:border-blue-500/30 dark:bg-gray-900">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-blue-400">Scan Details</h3>
              <button
                onClick={exportPdf}
                className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 transition-colors duration-200 dark:bg-blue-500 dark:hover:bg-blue-400 dark:text-black"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Export PDF
              </button>
            </div>
            
            <div className="overflow-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-blue-500/20">
                <thead className="bg-gray-50 dark:bg-gray-900">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider dark:text-blue-300">Field</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider dark:text-blue-300">Value</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200 dark:bg-black dark:divide-blue-500/20">
                  <tr>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-blue-400">URL</td>
                    <td className="px-6 py-4 text-sm text-gray-700 dark:text-blue-200">{result.url}</td>
                  </tr>
                  <tr>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-blue-400">Risk Score</td>
                    <td className="px-6 py-4 text-sm text-gray-700 dark:text-blue-200">{result.riskScore}</td>
                  </tr>
                  <tr>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-blue-400">Classification</td>
                    <td className="px-6 py-4 text-sm text-gray-700 dark:text-blue-200">{result.classification}</td>
                  </tr>
                  
                  {/* SSL Valid with expandable details */}
                  <tr>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-blue-400">SSL Valid</td>
                    <td className="px-6 py-4 text-sm text-gray-700 dark:text-blue-200">
                      <div className="flex items-center justify-between">
                        <span>{result.details.sslValid ? "Yes" : "No"}</span>
                        {result.details.sslData && (
                          <button
                            onClick={() => toggleRowExpansion('ssl')}
                            className="ml-2 text-xs text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300"
                          >
                            {expandedRows['ssl'] ? 'Hide Details' : 'View Details'}
                          </button>
                        )}
                      </div>
                      {expandedRows['ssl'] && result.details.sslData && (
                        <SSLDetails sslData={result.details.sslData} />
                      )}
                    </td>
                  </tr>
                  
                  {/* WHOIS Age with expandable details */}
                  <tr>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-blue-400">WHOIS Age (months)</td>
                    <td className="px-6 py-4 text-sm text-gray-700 dark:text-blue-200">
                      <div className="flex items-center justify-between">
                        <span>{result.details.whoisAgeMonths}</span>
                        {result.details.whoisData && (
                          <button
                            onClick={() => toggleRowExpansion('whois')}
                            className="ml-2 text-xs text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300"
                          >
                            {expandedRows['whois'] ? 'Hide Details' : 'View Details'}
                          </button>
                        )}
                      </div>
                      {expandedRows['whois'] && result.details.whoisData && (
                        <WhoisDetails whoisData={result.details.whoisData} />
                      )}
                    </td>
                  </tr>
                  
                  <tr>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-blue-400">Open Ports</td>
                    <td className="px-6 py-4 text-sm text-gray-700 dark:text-blue-200">{result.details.openPorts.join(", ") || "None"}</td>
                  </tr>
                  <tr>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-blue-400">Security Headers</td>
                    <td className="px-6 py-4 text-sm text-gray-700 dark:text-blue-200">{result.details.securityHeaders.join(", ") || "None"}</td>
                  </tr>
                  <tr>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-blue-400">Keywords</td>
                    <td className="px-6 py-4 text-sm text-gray-700 dark:text-blue-200">{result.details.keywords.join(", ") || "None"}</td>
                  </tr>
                  <tr>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-blue-400">ML Phishing Score</td>
                    <td className="px-6 py-4 text-sm text-gray-700 dark:text-blue-200">{result.details.mlPhishingScore}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Scanner;