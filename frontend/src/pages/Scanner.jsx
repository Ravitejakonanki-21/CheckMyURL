import { useState } from "react";
import { explain } from "../utils/riskExplain";
import { useScan } from "../context/ScanContext";

// PDF deps: npm i jspdf jspdf-autotable (then restart dev server)
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

function Scanner() {
  const [currentPage, setCurrentPage] = useState('input'); // 'input' or 'results'
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [expandedRows, setExpandedRows] = useState({});
  const [showNewScanModal, setShowNewScanModal] = useState(false); // NEW
  
  // Make recordScan optional in case context isn't set up
  let recordScan;
  try {
    const scanContext = useScan();
    recordScan = scanContext?.recordScan;
  } catch (err) {
    console.warn('ScanContext not available:', err);
    recordScan = null;
  }

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

  // Transform backend response to frontend format - UPDATED WITHOUT TRUST SCORE
  const transformBackendResponse = (backendData) => {
    const results = backendData.results || {};
    const headers = results.headers || {};
    const ssl = results.ssl || {}; // This now contains enhanced SSL data
    const whois = results.whois || {};
    const rules = results.rules || {};
    const idn = results.idn || {};

    // Use enhanced SSL data if available (from enhanced_ssl_check)
    const enhancedSSL = ssl.enhanced_data || ssl;

    // Calculate risk components based on backend data
    let safeScore = 0;
    let suspiciousScore = 0;
    let dangerousScore = 0;

    // Enhanced SSL risk assessment using new data structure (REMOVED TRUST SCORE)
    if (enhancedSSL.https_ok && !enhancedSSL.expired && !enhancedSSL.self_signed) {
      safeScore += 45; // Increased base weight since we removed trust score bonus
    } else {
      if (enhancedSSL.expired) dangerousScore += 30;
      if (enhancedSSL.self_signed) suspiciousScore += 20;
      if (!enhancedSSL.https_ok) suspiciousScore += 25;
    }

    // TLS version bonus/penalty
    if (enhancedSSL.tls_version === 'TLSv1.3') {
      safeScore += 10;
    } else if (enhancedSSL.tls_version === 'TLSv1.2') {
      safeScore += 5;
    } else if (enhancedSSL.tls_version) {
      suspiciousScore += 10; // Old TLS version
    }

    // Certificate chain validation
    if (enhancedSSL.certificate_chain_complete) {
      safeScore += 10;
    } else {
      suspiciousScore += 15;
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

    // WHOIS age assessment
    const whoisAgeMonths = (() => {
      if (!whois.creation_date) return 0;
      
      try {
        const creationDate = new Date(whois.creation_date);
        const currentDate = new Date();
        
        let months = (currentDate.getFullYear() - creationDate.getFullYear()) * 12;
        months += currentDate.getMonth() - creationDate.getMonth();
        
        if (currentDate.getDate() < creationDate.getDate()) {
          months--;
        }
        
        return Math.max(0, months);
      } catch (error) {
        return whois.age_days ? Math.round(whois.age_days / 30.44) : 0;
      }
    })();

    // Age-based risk assessment
    if (whoisAgeMonths > 12) {
      safeScore += 25;
    } else if (whoisAgeMonths > 3) {
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

    // Incorporate backend risk score
    const backendRiskScore = backendData.risk_score || 0;
    
    if (backendRiskScore >= 70) {
      dangerousScore += Math.max(40, dangerousScore);
      suspiciousScore = Math.max(suspiciousScore, 30);
      safeScore = Math.max(10, safeScore - 20);
    } else if (backendRiskScore >= 40) {
      suspiciousScore += Math.max(25, suspiciousScore);
      dangerousScore = Math.max(10, dangerousScore);
      safeScore = Math.max(20, safeScore - 10);
    } else {
      safeScore += Math.max(20, safeScore);
      suspiciousScore = Math.max(5, suspiciousScore);
      dangerousScore = Math.max(0, dangerousScore - 10);
    }

    // Additional risk factors
    if (rules.has_suspicious_words && rules.has_brand_words_in_host) {
      dangerousScore += 20;
      safeScore = Math.max(0, safeScore - 15);
    }

    if (idn.is_idn && idn.mixed_confusable_scripts) {
      dangerousScore += 15;
      suspiciousScore += 10;
    }

    if (enhancedSSL.expired && !enhancedSSL.https_ok) {
      dangerousScore += 25;
      safeScore = Math.max(0, safeScore - 20);
    }

    // Normalize scores
    safeScore = Math.max(0, safeScore);
    suspiciousScore = Math.max(0, suspiciousScore);
    dangerousScore = Math.max(0, dangerousScore);

    const total = Math.max(safeScore + suspiciousScore + dangerousScore, 100);
    
    let normalizedSafe = Math.round((safeScore / total) * 100);
    let normalizedSuspicious = Math.round((suspiciousScore / total) * 100);
    let normalizedDangerous = 100 - normalizedSafe - normalizedSuspicious;

    // Ensure backend risk dominance
    if (backendRiskScore >= 70 && normalizedDangerous < 50) {
      normalizedDangerous = Math.max(50, normalizedDangerous);
      const remaining = 100 - normalizedDangerous;
      normalizedSuspicious = Math.round(remaining * 0.7);
      normalizedSafe = remaining - normalizedSuspicious;
    } else if (backendRiskScore >= 40 && normalizedSuspicious < 40) {
      normalizedSuspicious = Math.max(40, normalizedSuspicious);
      const remaining = 100 - normalizedSuspicious;
      normalizedDangerous = Math.round(remaining * 0.3);
      normalizedSafe = remaining - normalizedDangerous;
    }

    // Final validation
    const finalTotal = normalizedSafe + normalizedSuspicious + normalizedDangerous;
    if (finalTotal !== 100) {
      const diff = 100 - finalTotal;
      if (normalizedDangerous >= normalizedSuspicious && normalizedDangerous >= normalizedSafe) {
        normalizedDangerous += diff;
      } else if (normalizedSuspicious >= normalizedSafe) {
        normalizedSuspicious += diff;
      } else {
        normalizedSafe += diff;
      }
    }

    // Classification
    let classification = "Low Risk";
    if (backendRiskScore >= 70) classification = "High Risk";
    else if (backendRiskScore >= 40) classification = "Medium Risk";

    // Extract data for display
    const presentHeaders = [];
    if (securityHeaders.strict_transport_security) presentHeaders.push("HSTS");
    if (securityHeaders.content_security_policy) presentHeaders.push("CSP");
    if (securityHeaders.x_content_type_options) presentHeaders.push("X-Content-Type-Options");
    if (securityHeaders.x_frame_options) presentHeaders.push("X-Frame-Options");
    if (securityHeaders.referrer_policy) presentHeaders.push("Referrer-Policy");

    const keywords = [];
    if (rules.matched_suspicious && rules.matched_suspicious.length > 0) {
      keywords.push(...rules.matched_suspicious);
    }
    if (rules.matched_brands && rules.matched_brands.length > 0) {
      keywords.push(...rules.matched_brands);
    }

    const mlPhishingScore = Math.min(
      Math.round(
        (rules.has_suspicious_words ? 0.3 : 0) +
        (rules.has_brand_words_in_host ? 0.4 : 0) +
        (idn.is_idn ? 0.2 : 0) +
        (!enhancedSSL.https_ok ? 0.1 : 0)
      ) * 100, 100
    );

    return {
      url: backendData.url,
      riskScore: backendRiskScore,
      classification: classification,
      pie: {
        series: [normalizedSafe, normalizedSuspicious, normalizedDangerous],
        labels: ['Safe', 'Suspicious', 'Dangerous'],
        colors: ['#344F1F', '#FAB12F', '#DD0303'] // Updated colors as requested
      },
      details: {
        // Legacy SSL fields for backward compatibility
        sslValid: enhancedSSL.https_ok || false,
        sslExpired: enhancedSSL.expired || false,
        sslSelfSigned: enhancedSSL.self_signed_hint || enhancedSSL.self_signed || false,
        
        // Enhanced SSL data (REMOVED TRUST SCORE)
        sslData: {
          ...enhancedSSL,
          // Remove trust score fields
          certificate_valid: enhancedSSL.certificate_valid,
          hostname_match: enhancedSSL.hostname_match,
          serial_number: enhancedSSL.serial_number,
          issuer_org: enhancedSSL.issuer_org,
          subject_org: enhancedSSL.subject_org,
          key_algorithm: enhancedSSL.key_algorithm,
          key_size: enhancedSSL.key_size,
          signature_algorithm: enhancedSSL.signature_algorithm,
          san_domains: enhancedSSL.san_domains || [],
          wildcard_cert: enhancedSSL.wildcard_cert,
          chain_length: enhancedSSL.chain_length,
          full_chain: enhancedSSL.full_chain || []
        },
        
        whoisAgeMonths: whoisAgeMonths,
        openPorts: [],
        securityHeaders: presentHeaders,
        keywords: keywords,
        mlPhishingScore: mlPhishingScore,
        httpStatus: headers.status || null,
        redirects: headers.redirects || 0,
        httpsRedirect: headers.https_redirect,
        domainAge: whois.age_days || 0,
        registrar: whois.registrar || "Unknown",
        whoisData: whois,
        headersData: headers,
        errors: {
          ssl: enhancedSSL.errors || [],
          headers: headers.errors || [],
          whois: whois.errors || [],
          idn: idn.errors || [],
          rules: rules.errors || []
        },
        scanTime: new Date().toISOString() // Add scan time
      }
    };
  };

  const onScan = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to scan');
      return;
    }
    
    setLoading(true);
    setError(null);
    
    try {
      const backendResponse = await analyzeUrl(url.trim());
      const transformedResult = transformBackendResponse(backendResponse);
      
      setResult(transformedResult);
      if (recordScan && typeof recordScan === 'function') {
        recordScan(transformedResult);
      }
      setCurrentPage('results');
    } catch (err) {
      setError(`Analysis failed: ${err.message}. Make sure your Flask backend is running on http://127.0.0.1:5000`);
      console.error('Scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  // IMPROVED NEW SCAN WITH MODAL
  const onNewScan = () => {
    setShowNewScanModal(true);
  };

  const confirmNewScan = () => {
    setCurrentPage('input');
    setUrl("");
    setResult(null);
    setError(null);
    setExpandedRows({});
    setShowNewScanModal(false);
  };

  const onClear = () => {
    setUrl("");
    setError(null);
  };

  // Render results page if we have results
  if (currentPage === 'results' && result) {
    return <ResultsPage 
      result={result} 
      onNewScan={onNewScan}
      expandedRows={expandedRows}
      setExpandedRows={setExpandedRows}
      showNewScanModal={showNewScanModal}
      setShowNewScanModal={setShowNewScanModal}
      confirmNewScan={confirmNewScan}
    />;
  }

  // Input Page with updated icons
  return (
    <div className="min-h-screen bg-white dark:bg-black flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-2xl">
        <div className="text-center mb-12">
          <h1 className="text-6xl md:text-5xl font-bold mb-5">
            <span className="text-gray-900 dark:text-white">URL </span>
            <span className="text-cyan-500 dark:text-cyan-400">Scanner</span>
          </h1>
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            Enter a URL to scan and analyze
          </p>
        </div>

        <div className="relative mb-10">
          <div className="flex items-center bg-gradient-to-r from-cyan-500/10 to-blue-500/10 dark:from-cyan-500/10 dark:to-blue-500/10 border border-cyan-500/40 dark:border-cyan-500/30 rounded-full px-6 py-5 backdrop-blur-sm">
            <svg className="w-6 h-6 text-cyan-500 dark:text-cyan-400 mr-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan..."
              className="flex-1 text-lg bg-transparent text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-500 outline-none"
              onKeyPress={(e) => e.key === 'Enter' && onScan()}
              disabled={loading}
              autoFocus
            />
            
            <button
              onClick={onScan}
              disabled={loading || !url.trim()}
              className="ml-4 px-8 py-3 bg-cyan-500 hover:bg-cyan-600 dark:bg-cyan-400 dark:hover:bg-cyan-300 disabled:bg-gray-400 dark:disabled:bg-gray-600 disabled:opacity-50 text-white dark:text-black font-semibold rounded-full transition-all duration-200 disabled:cursor-not-allowed"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Scanning
                </span>
              ) : (
                'Scan'
              )}
            </button>
          </div>
        </div>

        <div className="flex items-center justify-center gap-10 mb-20">
          <button
            onClick={onScan}
            disabled={loading || !url.trim()}
            className="px-8 py-3 bg-gray-200 hover:bg-gray-300 dark:bg-black disabled:bg-gray-200 dark:disabled:bg-gray-900 disabled:opacity-50 text-gray-700 dark:text-gray-300 rounded-lg transition-all duration-200 border border-gray-400 dark:border-gray-700 disabled:cursor-not-allowed"
          >
            Quick Scan
          </button>
          
          <button
            onClick={onScan}
            disabled={loading || !url.trim()}
            className="px-8 py-3 bg-gray-200 hover:bg-gray-300 dark:bg-black disabled:bg-gray-200 dark:disabled:bg-gray-900 disabled:opacity-50 text-gray-700 dark:text-gray-300 rounded-lg transition-all duration-200 border border-gray-400 dark:border-gray-700 disabled:cursor-not-allowed"
          >
            Deep Analysis
          </button>
        </div>

        <div className="max-w-4xl mx-auto px-4 mb-12">
          <div className="flex flex-wrap justify-center gap-6">
            {[
              { name: "SSL/TLS Check", icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              ) },
              { name: "WHOIS Lookup", icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                </svg>
              ) },
              { name: "ML Analysis", icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              ) },
              { name: "Keyword Detection", icon: (
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              ) },
            ].map((feature, index) => (
              <div key={index} className="text-center px-4 py-2">
                <div className="text-gray-600 dark:text-gray-400 mb-1 flex justify-center">{feature.icon}</div>
                <div className="text-sm font-medium text-gray-700 dark:text-blue-300">{feature.name}</div>
              </div>
            ))}
          </div>
        </div>

        {error && (
          <div className="mt-6 p-4 bg-red-100 dark:bg-red-500/10 border border-red-400 dark:border-red-500/30 rounded-lg backdrop-blur-sm">
            <div className="flex items-start justify-between">
              <p className="text-red-600 dark:text-red-400 text-sm flex-1">
                {error}
              </p>
              <button
                onClick={() => setError(null)}
                className="ml-4 text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// MODERN NEW SCAN MODAL COMPONENT
const NewScanModal = ({ isOpen, onClose, onConfirm }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 backdrop-blur-sm">
      <div className="bg-white dark:bg-gray-900 rounded-2xl max-w-md w-full mx-4 shadow-2xl border border-gray-300 dark:border-gray-600 transform transition-all duration-300 scale-100">
        
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center">
              <svg className="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h3 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
              Start New Scan
            </h3>
          </div>
          
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition-colors duration-200"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="p-6">
          <div className="mb-4">
            <div className="w-16 h-16 bg-yellow-100 dark:bg-yellow-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8 text-yellow-600 dark:text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
          </div>
          
          <p className="text-gray-700 dark:text-gray-300 text-center mb-2 text-lg">
            Are you sure you want to start a new scan?
          </p>
          <p className="text-gray-500 dark:text-gray-400 text-center text-sm">
            This will clear all current scan results and analysis data.
          </p>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end space-x-3 p-6 bg-gray-50 dark:bg-gray-800 rounded-b-2xl border-t border-gray-200 dark:border-gray-700">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-400 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors duration-200"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors duration-200"
          >
            Start New Scan
          </button>
        </div>
      </div>
    </div>
  );
};

// PEM Modal Component
const PEMModal = ({ isOpen, onClose, pemData }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-900 rounded-lg max-w-4xl max-h-[90vh] w-full mx-4 flex flex-col border border-gray-400 dark:border-gray-600">
        <div className="flex items-center justify-between p-4 border-b border-gray-300 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Raw Certificate Data (PEM)
          </h3>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        <div className="flex-1 overflow-auto p-4">
          <div className="bg-black dark:bg-gray-800 rounded p-4 relative border border-gray-400 dark:border-gray-600">
            <pre className="text-sm text-green-400 font-mono overflow-x-auto whitespace-pre-wrap break-all">
              {pemData}
            </pre>
            <button 
              onClick={() => navigator.clipboard?.writeText(pemData)}
              className="absolute top-2 right-2 text-green-400 hover:text-green-200 text-xs px-3 py-1 bg-black/50 rounded border border-green-500"
              title="Copy PEM Certificate"
            >
              <svg className="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
              Copy PEM
            </button>
          </div>
        </div>
        
        <div className="p-4 border-t border-gray-300 dark:border-gray-700 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors duration-200"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

// CALCULATE INDIVIDUAL SECURITY SCORES WITHOUT TRUST SCORE
const calculateSecurityScores = (result) => {
  const scores = {
    ssl: 0,
    domainAge: 0,
    ports: 0,
    headers: 0,
    keywords: 0,
    mlPhishing: 0
  };

  const weights = {
    ssl: 30, // Keep same weight
    domainAge: 20,
    ports: 10,
    headers: 15,
    keywords: 15,
    mlPhishing: 10
  };

  // Basic SSL Score (removed trust score dependency)
  if (result.details.sslValid && !result.details.sslExpired && !result.details.sslSelfSigned) {
    scores.ssl = 100;
  } else if (result.details.sslValid && !result.details.sslExpired) {
    scores.ssl = 80;
  } else if (result.details.sslValid) {
    scores.ssl = 60;
  } else {
    scores.ssl = 20;
  }

  // Domain Age Score (0-100)
  if (result.details.whoisAgeMonths > 12) {
    scores.domainAge = 100;
  } else if (result.details.whoisAgeMonths > 6) {
    scores.domainAge = 75;
  } else if (result.details.whoisAgeMonths > 3) {
    scores.domainAge = 50;
  } else {
    scores.domainAge = 25;
  }

  // Open Ports Score (0-100) - fewer ports = better score
  const portCount = result.details.openPorts.length;
  if (portCount === 0) {
    scores.ports = 100;
  } else if (portCount <= 2) {
    scores.ports = 80;
  } else if (portCount <= 5) {
    scores.ports = 60;
  } else {
    scores.ports = 30;
  }

  // Security Headers Score (0-100)
  const headerCount = result.details.securityHeaders.length;
  if (headerCount >= 4) {
    scores.headers = 100;
  } else if (headerCount >= 3) {
    scores.headers = 80;
  } else if (headerCount >= 2) {
    scores.headers = 60;
  } else if (headerCount >= 1) {
    scores.headers = 40;
  } else {
    scores.headers = 20;
  }

  // Keywords Score (0-100) - fewer suspicious keywords = better score
  const keywordCount = result.details.keywords.length;
  if (keywordCount === 0) {
    scores.keywords = 100;
  } else if (keywordCount <= 2) {
    scores.keywords = 60;
  } else if (keywordCount <= 4) {
    scores.keywords = 40;
  } else {
    scores.keywords = 20;
  }

  // ML Phishing Score (invert - lower ML score = better security score)
  scores.mlPhishing = Math.max(0, 100 - result.details.mlPhishingScore);

  // Calculate weighted average for overall score
  const weightedSum = Object.keys(scores).reduce((sum, key) => sum + (scores[key] * weights[key]), 0);
  const totalWeight = Object.values(weights).reduce((sum, weight) => sum + weight, 0);
  const overallPercentage = Math.round(weightedSum / totalWeight);

  // Use the pie chart data from the backend if available
  const pieData = result.pie ? result.pie.series : [60, 25, 15]; // fallback

  return { 
    ...scores, 
    overall: overallPercentage, 
    weights,
    pieData: pieData
  };
};

// FORMAT LAST UPDATED TIME
const formatLastUpdated = (scanTime) => {
  if (!scanTime) return "Unknown";
  
  const now = new Date();
  const scanDate = new Date(scanTime);
  const diffMs = now - scanDate;
  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins} minutes ago`;
  if (diffHours < 24) return `${diffHours} hours ago`;
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 30) return `${diffDays} days ago`;
  return scanDate.toLocaleDateString();
};

// QUICK ACTION FUNCTIONS WITH INLINE FEEDBACK
const copyToClipboard = async (text, buttonElement) => {
  try {
    await navigator.clipboard.writeText(text);
    showInlineFeedback(buttonElement, 'Copied!');
  } catch (err) {
    // Fallback for older browsers
    const textArea = document.createElement("textarea");
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand('copy');
    document.body.removeChild(textArea);
    showInlineFeedback(buttonElement, 'Copied!');
  }
};

const showInlineFeedback = (buttonElement, message) => {
  const originalText = buttonElement.textContent;
  buttonElement.textContent = message;
  buttonElement.style.color = '#22c55e'; // Green color
  
  setTimeout(() => {
    buttonElement.textContent = originalText;
    buttonElement.style.color = ''; // Reset color
  }, 1500);
};

const openLearnMore = (topic, buttonElement) => {
  const urls = {
    ssl: "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
    domain: "https://www.icann.org/resources/pages/whois-2018-01-17-en",
    ports: "https://owasp.org/www-community/vulnerabilities/Port_Scanning",
    headers: "https://owasp.org/www-project-secure-headers/",
    keywords: "https://www.phishing.org/what-is-phishing",
    ml: "https://en.wikipedia.org/wiki/Machine_learning_in_computer_security"
  };
  
  if (urls[topic]) {
    window.open(urls[topic], '_blank');
    showInlineFeedback(buttonElement, 'Opened!');
  }
};

const reportFalsePositive = (field, value, buttonElement) => {
  const subject = `False Positive Report: ${field}`;
  const body = `I believe there's a false positive in the URL Scanner results:\n\nField: ${field}\nValue: ${value}\nURL: ${window.location.href}\n\nPlease review this result.`;
  const mailtoUrl = `mailto:support@urlscanner.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  window.location.href = mailtoUrl;
  showInlineFeedback(buttonElement, 'Reported!');
};

// RESULTS PAGE - ALL ROWS ALWAYS VISIBLE
function ResultsPage({ result, onNewScan, expandedRows, setExpandedRows, showNewScanModal, setShowNewScanModal, confirmNewScan }) {
  const toggleRowExpansion = (rowKey) => {
    setExpandedRows(prev => ({
      ...prev,
      [rowKey]: !prev[rowKey]
    }));
  };

  // Calculate security scores without trust score
  const securityScores = calculateSecurityScores(result);
  const lastUpdated = formatLastUpdated(result.details.scanTime);

  // Update result's pie chart data to match detailed scores
  const updatedResult = {
    ...result,
    pie: {
      ...result.pie,
      series: securityScores.pieData
    }
  };

  const copyAllResults = (buttonElement) => {
    const sslData = result.details.sslData;
    const allData = [
      `URL: ${result.url}`,
      `Risk Score: ${result.riskScore}%`,
      `Classification: ${result.classification}`,
      `SSL/TLS: ${result.details.sslValid ? 'Valid' : 'Invalid'} (Score: ${securityScores.ssl})`,
      sslData.tls_version ? `TLS Version: ${sslData.tls_version}` : '',
      sslData.cipher_suite ? `Cipher Suite: ${sslData.cipher_suite}` : '',
      `Domain Age: ${result.details.whoisAgeMonths} months (Score: ${securityScores.domainAge})`,
      `Open Ports: ${result.details.openPorts.join(", ") || "None"} (Score: ${securityScores.ports})`,
      `Security Headers: ${result.details.securityHeaders.join(", ") || "None"} (Score: ${securityScores.headers})`,
      `Keywords: ${result.details.keywords.join(", ") || "None"} (Score: ${securityScores.keywords})`,
      `ML Score: ${result.details.mlPhishingScore}% risk (Score: ${securityScores.mlPhishing})`,
      `Overall Score: ${securityScores.overall}%`
    ].filter(Boolean).join('\n');
    
    copyToClipboard(allData, buttonElement);
  };

  const exportPdf = () => {
    try {
      if (!result) {
        return;
      }

      const doc = new jsPDF({ unit: "pt", format: "a4" });

      doc.setFont("helvetica", "bold");
      doc.setFontSize(16);
      doc.text("Enhanced URL Security Report", 40, 40);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      const ts = new Date().toLocaleString();
      doc.text(`Generated: ${ts}`, 40, 60);
      doc.text(`URL: ${String(result.url ?? "")}`, 40, 76);
      doc.text(`Risk Score: ${String(result.riskScore ?? "")}`, 40, 92);
      doc.text(`Classification: ${String(result.classification ?? "")}`, 40, 108);

      const d = result.details || {};
      const sslData = d.sslData || {};
      const rows = [
        ["SSL Valid", d.sslValid ? "Yes" : "No", String(securityScores.ssl), `${securityScores.weights.ssl}%`],
        ["TLS Version", sslData.tls_version || "N/A", sslData.cipher_suite ? "Secure" : "Unknown", "Protocol"],
        ["WHOIS Age (months)", String(d.whoisAgeMonths ?? ""), String(securityScores.domainAge), `${securityScores.weights.domainAge}%`],
        ["Open Ports", Array.isArray(d.openPorts) ? d.openPorts.join(", ") || "None" : "None", String(securityScores.ports), `${securityScores.weights.ports}%`],
        ["Security Headers", Array.isArray(d.securityHeaders) ? d.securityHeaders.join(", ") || "None" : "None", String(securityScores.headers), `${securityScores.weights.headers}%`],
        ["Keywords", Array.isArray(d.keywords) ? d.keywords.join(", ") || "None" : "None", String(securityScores.keywords), `${securityScores.weights.keywords}%`],
        ["ML Phishing Score", String(d.mlPhishingScore ?? ""), String(securityScores.mlPhishing), `${securityScores.weights.mlPhishing}%`],
      ];

      autoTable(doc, {
        startY: 130,
        head: [["Field", "Value", "Score", "Weight"]],
        body: rows,
        styles: { fontSize: 10, cellPadding: 6 },
        headStyles: { fillColor: [67, 56, 202] },
        theme: "grid",
        margin: { left: 40, right: 40 },
      });

      const comp = ["Safe", "Suspicious", "Dangerous"]
        .map((l, i) => `${l}: ${securityScores.pieData?.[i] ?? ""}%`)
        .join(" | ");
      const finalY = doc.lastAutoTable?.finalY || 130;
      doc.text(`Risk Composition: ${comp}`, 40, finalY + 24);
      doc.text(`Overall Security Score: ${securityScores.overall}%`, 40, finalY + 44);

      doc.save(`enhanced-url-security-report-${Date.now()}.pdf`);
    } catch (e) {
      console.error("Export error:", e);
    }
  };

  return (
    <div className="min-h-screen bg-white dark:bg-black">
      {/* NEW SCAN MODAL */}
      <NewScanModal 
        isOpen={showNewScanModal}
        onClose={() => setShowNewScanModal(false)}
        onConfirm={confirmNewScan}
      />

      {/* Header - Full Width */}
      <div className="border-b border-gray-300 dark:border-gray-700 bg-white dark:bg-black">
        <div className="w-full px-6 py-3">
          <div className="flex items-center justify-between">
            <button
              onClick={onNewScan}
              className="inline-flex items-center gap-2 text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-3 py-1.5 rounded-lg hover:bg-blue-50 dark:hover:bg-gray-700 text-sm border border-blue-300 dark:border-blue-600 hover:border-blue-400 dark:hover:border-blue-500"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
              New Scan
            </button>
            <h1 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Enhanced Security Scan Results
            </h1>
            <button
              onClick={exportPdf}
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700 transition-colors duration-200 dark:bg-blue-500 dark:hover:bg-blue-600 border border-blue-700 dark:border-blue-400"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export PDF
            </button>
          </div>
        </div>
      </div>

      {/* COMPACT SUMMARY SECTION - Full Width */}
      <div className="w-full px-6 py-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          
          {/* LEFT - URL, Risk Score, Classification & Enhanced Analysis */}
          <div className="lg:col-span-1">
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-300 dark:border-gray-700 p-4 shadow-sm">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                {result.url}
              </h2>
              
              <div className="flex items-center space-x-4 mb-2">
                <span className="text-sm text-gray-600 dark:text-gray-400">Risk Score:</span>
                <span className={`text-2xl font-bold ${
                  result.riskScore >= 70 ? 'text-red-600 dark:text-red-400' : 
                  result.riskScore >= 40 ? 'text-yellow-600 dark:text-yellow-400' : 
                  'text-green-600 dark:text-green-400'
                }`}>
                  {result.riskScore}
                </span>
                <span className="text-sm text-gray-600 dark:text-gray-400">Total Score:</span>
                <span className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  {securityScores.overall}%
                </span>
              </div>
              
              <div className="flex items-center space-x-4 mb-4">
                <span className="text-sm text-gray-600 dark:text-gray-400">Classification:</span>
                <span className={`text-lg font-semibold ${
                  result.classification === 'High Risk' ? 'text-red-600 dark:text-red-400' : 
                  result.classification === 'Medium Risk' ? 'text-yellow-600 dark:text-yellow-400' : 
                  'text-green-600 dark:text-green-400'
                }`}>
                  {result.classification}
                </span>
              </div>

              {/* Risk Analysis Section */}
              <div className="border-t border-gray-300 dark:border-gray-700 pt-3">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  Risk Analysis
                </h3>
                <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                  Overall risk score is {result.riskScore} classifying as {result.classification}. 
                  {result.details.keywords && result.details.keywords.length > 0 && (
                    <span> Detected risky keywords: {result.details.keywords.join(', ')}.</span>
                  )}
                  {(!result.details.keywords || result.details.keywords.length === 0) && (
                    <span> No suspicious keywords detected.</span>
                  )}
                </p>
              </div>
            </div>
          </div>

          {/* RIGHT - Risk Composition */}
          <div className="lg:col-span-2">
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-300 dark:border-gray-700 p-4 shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Risk Composition
              </h3>
              {updatedResult.pie && <InteractivePieChart data={updatedResult.pie} />}
            </div>
          </div>
        </div>
      </div>

      {/* MAIN FOCUS - Complete Scan Details Table - ALL ROWS ALWAYS VISIBLE */}
      <div className="w-full px-6 pb-8">
        <div className="border border-gray-300 dark:border-gray-700 rounded-2xl overflow-hidden bg-white dark:bg-gray-900 shadow-lg">
          <div className="bg-gray-50 dark:bg-gray-800 border-b border-gray-300 dark:border-gray-700 px-6 py-4">
            <div className="flex items-center space-x-2">
              <svg className="w-6 h-6 text-gray-600 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100">Enhanced Security Analysis</h3>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">Complete security assessment with professional SSL analysis, domain validation, and threat detection</p>
          </div>
          
          <div className="overflow-auto">
            <table className="min-w-full divide-y divide-gray-300 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-4 text-left text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-600">Field</th>
                  <th className="px-4 py-4 text-left text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-600">Value</th>
                  <th className="px-4 py-4 text-left text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-600">Details</th>
                  <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-600">
                    Total Score: {securityScores.overall}%
                  </th>
                  <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-600">Weight</th>
                  <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-600">Last Updated</th>
                  <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Quick Actions
                    <button 
                      onClick={(e) => copyAllResults(e.target)}
                      className="ml-2 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200"
                      title="Copy All Results"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-300 dark:divide-gray-700">
                
                {/* URL ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-600">URL</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">{result.url}</td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">Scanned domain with enhanced analysis</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">—</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">—</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(result.url, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy URL"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </td>
                </tr>

                {/* RISK SCORE ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-600">Risk Score</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    <span className={`font-bold ${
                      result.riskScore >= 70 ? 'text-red-600 dark:text-red-400' : 
                      result.riskScore >= 40 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-green-600 dark:text-green-400'
                    }`}>
                      {result.riskScore}%
                    </span>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">Overall security risk assessment</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">—</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">—</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Risk Score: ${result.riskScore}%`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Risk Score"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </td>
                </tr>
                
                {/* ENHANCED SSL/TLS SECURITY ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-600">SSL/TLS Security</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className={`px-3 py-1 rounded text-xs font-medium ${
                          result.details.sslValid ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 
                          'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                        }`}>
                          {result.details.sslValid ? "✓ Valid" : "✗ Invalid"}
                        </span>
                      </div>
                      {result.details.sslData && (
                        <button
                          onClick={() => toggleRowExpansion('ssl')}
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600"
                        >
                          {expandedRows['ssl'] ? 'Hide Details ▼' : 'View Enhanced Details ▶'}
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">
                    Professional SSL/TLS certificate validation
                  </td>
                  <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-600">
                    <div className={`text-lg font-bold ${
                      securityScores.ssl >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.ssl >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.ssl}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    {securityScores.weights.ssl}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`SSL: ${result.details.sslValid ? 'Valid' : 'Invalid'}`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy SSL Status"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('ssl', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('SSL/TLS Security', result.details.sslValid ? 'Valid' : 'Invalid', e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                    </button>
                  </td>
                </tr>
                
                {/* SSL ENHANCED DETAILS - SHOW WHEN EXPANDED */}
                {expandedRows['ssl'] && result.details.sslData && (
                  <tr>
                    <td colSpan="7" className="px-0 py-0 border-t border-gray-200 dark:border-gray-600">
                      <EnhancedSSLDetails sslData={result.details.sslData} securityScores={securityScores} lastUpdated={lastUpdated} />
                    </td>
                  </tr>
                )}
                
                {/* DOMAIN AGE ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-600">Domain Age</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    <div className="flex items-center justify-between">
                      <span className={`font-medium px-2 py-1 rounded text-xs ${
                        result.details.whoisAgeMonths > 12 ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 
                        result.details.whoisAgeMonths > 3 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' : 
                        'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                      }`}>
                        {result.details.whoisAgeMonths} months
                      </span>
                      {result.details.whoisData && (
                        <button
                          onClick={() => toggleRowExpansion('whois')}
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600"
                        >
                          {expandedRows['whois'] ? 'Hide Details ▼' : 'View Enhanced Details ▶'}
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">Domain registration history and age</td>
                  <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-600">
                    <div className={`text-lg font-bold ${
                      securityScores.domainAge >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.domainAge >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.domainAge}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    {securityScores.weights.domainAge}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Domain Age: ${result.details.whoisAgeMonths} months`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Domain Age"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('domain', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('Domain Age', `${result.details.whoisAgeMonths} months`, e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                    </button>
                  </td>
                </tr>
                
                {/* WHOIS DETAILS - SHOW WHEN EXPANDED */}
                {expandedRows['whois'] && result.details.whoisData && (
                  <tr>
                    <td colSpan="7" className="px-6 py-0 border-t border-gray-200 dark:border-gray-600">
                      <WhoisDetails whoisData={result.details.whoisData} />
                    </td>
                  </tr>
                )}

                {/* OPEN PORTS ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-600">Open Ports</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    <div className="flex items-center justify-between">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        result.details.openPorts.length === 0 ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 
                        result.details.openPorts.length <= 2 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' : 
                        'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                      }`}>
                        {result.details.openPorts.length === 0 ? "None detected" : `${result.details.openPorts.length} ports`}
                      </span>
                      {result.details.openPorts.length > 0 && (
                        <button
                          onClick={() => toggleRowExpansion('ports')}
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600"
                        >
                          {expandedRows['ports'] ? 'Hide Details ▼' : 'View Enhanced Details ▶'}
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">Network port scanning and availability check</td>
                  <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-600">
                    <div className={`text-lg font-bold ${
                      securityScores.ports >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.ports >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.ports}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    {securityScores.weights.ports}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Open Ports: ${result.details.openPorts.length === 0 ? "None" : result.details.openPorts.join(", ")}`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Ports"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('ports', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('Open Ports', result.details.openPorts.length === 0 ? "None" : result.details.openPorts.join(", "), e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                    </button>
                  </td>
                </tr>
                
                {/* PORTS DETAILS - SHOW WHEN EXPANDED */}
                {expandedRows['ports'] && result.details.openPorts.length > 0 && (
                  <tr>
                    <td colSpan="7" className="px-6 py-4 border-t border-gray-200 dark:border-gray-600">
                      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-500/30 rounded-lg p-4">
                        <h4 className="font-medium text-lg mb-4 text-gray-900 dark:text-blue-300 flex items-center">
                          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                          Detected Open Ports
                        </h4>
                        <div className="grid grid-cols-4 gap-4">
                          {result.details.openPorts.map((port, index) => (
                            <div key={index} className="text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-black px-4 py-3 rounded-lg border border-blue-300 dark:border-blue-800 text-center">
                              Port {port}
                            </div>
                          ))}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}

                {/* SECURITY HEADERS ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-600">Security Headers</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    <div className="flex items-center justify-between">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        result.details.securityHeaders.length >= 3 ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 
                        result.details.securityHeaders.length >= 1 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' : 
                        'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                      }`}>
                        {result.details.securityHeaders.length === 0 ? "None found" : `${result.details.securityHeaders.length} headers`}
                      </span>
                      {result.details.securityHeaders.length > 0 && (
                        <button
                          onClick={() => toggleRowExpansion('headers')}
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600"
                        >
                          {expandedRows['headers'] ? 'Hide Details ▼' : 'View Enhanced Details ▶'}
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">HTTP security headers implementation check</td>
                  <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-600">
                    <div className={`text-lg font-bold ${
                      securityScores.headers >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.headers >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.headers}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    {securityScores.weights.headers}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Security Headers: ${result.details.securityHeaders.length === 0 ? "None" : result.details.securityHeaders.join(", ")}`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Headers"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('headers', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('Security Headers', result.details.securityHeaders.length === 0 ? "None" : result.details.securityHeaders.join(", "), e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                    </button>
                  </td>
                </tr>
                
                {/* HEADERS DETAILS - SHOW WHEN EXPANDED */}
                {expandedRows['headers'] && result.details.securityHeaders.length > 0 && (
                  <tr>
                    <td colSpan="7" className="px-6 py-4 border-t border-gray-200 dark:border-gray-600">
                      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-500/30 rounded-lg p-4">
                        <h4 className="font-medium text-lg mb-4 text-gray-900 dark:text-blue-300 flex items-center">
                          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                          </svg>
                          Security Headers Found
                        </h4>
                        <div className="grid grid-cols-4 gap-4">
                          {result.details.securityHeaders.map((header, index) => (
                            <div key={index} className="text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-black px-4 py-3 rounded-lg border border-blue-300 dark:border-blue-800">
                              {header}
                            </div>
                          ))}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}

                {/* SUSPICIOUS KEYWORDS ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-600">Suspicious Keywords</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    <div className="flex items-center justify-between">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        result.details.keywords.length === 0 ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 
                        result.details.keywords.length <= 2 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' : 
                        'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                      }`}>
                        {result.details.keywords.length === 0 ? "None found" : `${result.details.keywords.length} detected`}
                      </span>
                      {result.details.keywords.length > 0 && (
                        <button
                          onClick={() => toggleRowExpansion('keywords')}
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600"
                        >
                          {expandedRows['keywords'] ? 'Hide Details ▼' : 'View Enhanced Details ▶'}
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">Phishing and malicious keyword detection</td>
                  <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-600">
                    <div className={`text-lg font-bold ${
                      securityScores.keywords >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.keywords >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.keywords}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    {securityScores.weights.keywords}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Keywords: ${result.details.keywords.length === 0 ? "None" : result.details.keywords.join(", ")}`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Keywords"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('keywords', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('Keywords', result.details.keywords.length === 0 ? "None" : result.details.keywords.join(", "), e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                    </button>
                  </td>
                </tr>
                
                {/* KEYWORDS DETAILS - SHOW WHEN EXPANDED */}
                {expandedRows['keywords'] && result.details.keywords.length > 0 && (
                  <tr>
                    <td colSpan="7" className="px-6 py-4 border-t border-gray-200 dark:border-gray-600">
                      <div className="bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-800 rounded-lg p-4">
                        <h4 className="font-medium text-lg mb-4 text-red-800 dark:text-red-300 flex items-center">
                          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                          </svg>
                          Suspicious Keywords Detected
                        </h4>
                        <div className="grid grid-cols-4 gap-4">
                          {result.details.keywords.map((keyword, index) => (
                            <div key={index} className="text-sm text-red-700 dark:text-red-400 bg-white dark:bg-black px-4 py-3 rounded-lg border border-red-300 dark:border-red-800">
                              {keyword}
                            </div>
                          ))}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}

                {/* ML PHISHING SCORE ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-600">ML Phishing Score</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    <div className="flex items-center justify-between">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        result.details.mlPhishingScore <= 30 ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 
                        result.details.mlPhishingScore <= 60 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' : 
                        'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                      }`}>
                        {result.details.mlPhishingScore}% risk
                      </span>
                      <button
                        onClick={() => toggleRowExpansion('ml')}
                        className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600"
                      >
                        {expandedRows['ml'] ? 'Hide Details ▼' : 'View Enhanced Details ▶'}
                      </button>
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">Machine learning phishing detection algorithm</td>
                  <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-600">
                    <div className={`text-lg font-bold ${
                      securityScores.mlPhishing >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.mlPhishing >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.mlPhishing}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-600">
                    {securityScores.weights.mlPhishing}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-600">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`ML Score: ${result.details.mlPhishingScore}% risk`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy ML Score"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('ml', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('ML Phishing Score', `${result.details.mlPhishingScore}% risk`, e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                    </button>
                  </td>
                </tr>
                
                {/* ML DETAILS - SHOW WHEN EXPANDED */}
                {expandedRows['ml'] && (
                  <tr>
                    <td colSpan="7" className="px-6 py-4 border-t border-gray-200 dark:border-gray-600">
                      <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-300 dark:border-purple-500/30 rounded-lg p-4">
                        <h4 className="font-medium text-lg mb-4 text-gray-900 dark:text-purple-300 flex items-center">
                          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                          </svg>
                          Machine Learning Analysis
                        </h4>
                        <div className="grid grid-cols-4 gap-4">
                          <div className="text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-black px-4 py-3 rounded-lg border border-purple-300 dark:border-purple-800">
                            URL pattern analysis
                          </div>
                          <div className="text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-black px-4 py-3 rounded-lg border border-purple-300 dark:border-purple-800">
                            Domain reputation scoring
                          </div>
                          <div className="text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-black px-4 py-3 rounded-lg border border-purple-300 dark:border-purple-800">
                            Behavioral threat detection
                          </div>
                          <div className="text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-black px-4 py-3 rounded-lg border border-purple-300 dark:border-purple-800">
                            Real-time risk assessment
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

// ENHANCED SSL DETAILS COMPONENT WITH 4-COLUMN LAYOUT AND PROFESSIONAL ICONS
const EnhancedSSLDetails = ({ sslData, securityScores, lastUpdated }) => {
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

  const enhancedChecks = [
    {
      name: "HTTPS Connection",
      description: "SSL/TLS connection established successfully",
      value: sslData?.https_ok,
      status: sslData?.https_ok ? 'good' : 'bad',
      details: sslData?.https_ok ? "Secure HTTPS connection established" : "Failed to establish HTTPS connection",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      )
    },
    {
      name: "Certificate Validity",
      description: "Certificate is currently valid and not expired",
      value: sslData?.certificate_valid,
      status: sslData?.certificate_valid ? 'good' : sslData?.expired === true ? 'bad' : 'warning',
      details: sslData?.certificate_valid ? "Certificate is currently valid" : 
              sslData?.expired === true ? "Certificate has expired" : "Certificate validity unknown",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      )
    },
    {
      name: "Certificate Chain",
      description: "Complete certificate chain validation",
      value: sslData?.certificate_chain_complete,
      status: sslData?.certificate_chain_complete ? 'good' : 'warning',
      details: sslData?.certificate_chain_complete ? 
        `Complete chain (${sslData.chain_length || 'unknown'} levels)` : 
        "Incomplete certificate chain",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
        </svg>
      )
    },
    {
      name: "Hostname Match",
      description: "Certificate matches the requested hostname",
      value: sslData?.hostname_match,
      status: sslData?.hostname_match ? 'good' : 'bad',
      details: sslData?.hostname_match ? "Hostname verified" : "Hostname mismatch detected",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
        </svg>
      )
    },
    {
      name: "TLS Version",
      description: "The TLS protocol version being used",
      value: sslData?.tls_version,
      status: sslData?.tls_version === 'TLSv1.3' ? 'good' : 
              sslData?.tls_version === 'TLSv1.2' ? 'good' : 
              sslData?.tls_version ? 'warning' : 'bad',
      details: sslData?.tls_version ? `Using ${sslData.tls_version}` : "TLS version information not available",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4.871 4A17.926 17.926 0 003 12c0 2.874.673 5.59 1.871 8m14.13 0a17.926 17.926 0 001.87-8c0-2.874-.673-5.59-1.87-8M9 9h1.246a1 1 0 01.961.725l1.586 5.55a1 1 0 00.961.725H15" />
        </svg>
      )
    },
    {
      name: "Key Algorithm",
      description: "Cryptographic algorithm and key size",
      value: sslData?.key_algorithm,
      status: sslData?.key_algorithm ? 'good' : 'warning',
      details: sslData?.key_algorithm ? 
        `${sslData.key_algorithm}${sslData.key_size ? ` (${sslData.key_size} bits)` : ''}` : 
        "Key algorithm information not available",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
      )
    },
    {
      name: "Certificate Expiration",
      description: "When the SSL certificate expires",
      value: sslData?.expires_on,
      status: daysUntilExpiry > 30 ? 'good' : daysUntilExpiry > 7 ? 'warning' : 'bad',
      details: sslData?.expires_on ? 
        `Expires: ${formatDate(sslData.expires_on)}${daysUntilExpiry !== null ? ` (${daysUntilExpiry} days remaining)` : ''}` :
        "Expiration date not available",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      )
    }
  ];

  // Add SAN domains if available
  if (sslData?.san_domains && sslData.san_domains.length > 0) {
    enhancedChecks.push({
      name: "Subject Alternative Names",
      description: "Additional domains covered by this certificate",
      value: sslData.san_domains,
      status: 'good',
      details: `Also covers: ${sslData.san_domains.slice(0, 3).join(', ')}${sslData.san_domains.length > 3 ? ` (+${sslData.san_domains.length - 3} more)` : ''}`,
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
        </svg>
      )
    });
  }

  return (
    <div className="w-full p-6 bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-500/30 rounded-lg">
      {/* FOUR COLUMN LAYOUT */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* COLUMN 1: Enhanced SSL/TLS Security Analysis */}
        <div className="space-y-3">
          <h4 className="font-medium text-sm mb-3 text-gray-900 dark:text-blue-300 border-b border-blue-300 dark:border-blue-500/30 pb-2 flex items-center">
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            Enhanced SSL/TLS Security Analysis
          </h4>
          
          <div className="space-y-2">
            {enhancedChecks.map((check, index) => (
              <div key={index} className="flex items-center justify-between py-2 px-3 bg-white dark:bg-black rounded border border-gray-300 dark:border-gray-600">
                <div className="flex items-center space-x-3">
                  <div className={`w-3 h-3 rounded-full ${
                    check.status === 'good' ? 'bg-green-500' :
                    check.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                  }`}></div>
                  <div className="text-gray-600 dark:text-gray-400">
                    {check.icon}
                  </div>
                  <div>
                    <div className="font-medium text-sm text-gray-900 dark:text-gray-100">{check.name}</div>
                    <div className="text-xs text-gray-500 dark:text-gray-400">{check.description}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className={`text-sm font-medium ${
                    check.status === 'good' ? 'text-green-600 dark:text-green-400' :
                    check.status === 'warning' ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400'
                  }`}>
                    {check.status === 'good' ? '✓' : check.status === 'warning' ? '⚠' : '✗'}
                  </div>
                  <div className="text-xs text-gray-600 dark:text-gray-300 max-w-48 text-right">{check.details}</div>
                </div>
              </div>
            ))}
          </div>
          
          {sslData?.errors && sslData.errors.length > 0 && (
            <div className="mt-3 p-3 bg-red-50 dark:bg-red-900/20 rounded border border-red-300 dark:border-red-800">
              <h5 className="font-medium text-sm text-red-800 dark:text-red-300 mb-2 flex items-center">
                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
                SSL/TLS Errors:
              </h5>
              {sslData.errors.map((error, index) => (
                <div key={index} className="text-xs text-red-700 dark:text-red-400">• {error}</div>
              ))}
            </div>
          )}
        </div>

        {/* COLUMN 2: Advanced Technical Details Part 1 */}
        <div className="space-y-3">
          <TechnicalSSLDetailsColumn1 sslData={sslData} securityScores={securityScores} lastUpdated={lastUpdated} />
        </div>

        {/* COLUMN 3: Advanced Technical Details Part 2 */}
        <div className="space-y-3">
          <TechnicalSSLDetailsColumn2 sslData={sslData} />
        </div>
        
        {/* COLUMN 4: Summary Details */}
        <div className="space-y-4">
          <h5 className="font-medium text-sm text-gray-900 dark:text-gray-100 mb-3 flex items-center border-b border-blue-300 dark:border-blue-500/30 pb-2">
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            Summary Details
          </h5>
          
          <div className="space-y-3">
            <div className="bg-gray-50 dark:bg-gray-800 rounded p-3 border border-gray-300 dark:border-gray-600">
              <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase mb-1">Details:</div>
              <div className="text-sm text-gray-700 dark:text-gray-300">Professional SSL/TLS certificate validation</div>
            </div>
            
            <div className="bg-gray-50 dark:bg-gray-800 rounded p-3 border border-gray-300 dark:border-gray-600">
              <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase mb-1">Total Score:</div>
              <div className="text-sm font-bold text-green-600 dark:text-green-400">{securityScores?.ssl || 100}</div>
            </div>
            
            <div className="bg-gray-50 dark:bg-gray-800 rounded p-3 border border-gray-300 dark:border-gray-600">
              <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase mb-1">Weight:</div>
              <div className="text-sm text-gray-700 dark:text-gray-300">{securityScores?.weights?.ssl || 30}%</div>
            </div>
            
            <div className="bg-gray-50 dark:bg-gray-800 rounded p-3 border border-gray-300 dark:border-gray-600">
              <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase mb-1">Last Updated:</div>
              <div className="text-sm text-gray-700 dark:text-gray-300">{lastUpdated}</div>
            </div>
            
            <div className="bg-gray-50 dark:bg-gray-800 rounded p-3 border border-gray-300 dark:border-gray-600">
              <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase mb-1">Quick Actions:</div>
              <div className="flex items-center space-x-2 mt-1">
                <button 
                  onClick={() => navigator.clipboard?.writeText("SSL Certificate Details")}
                  className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 text-sm"
                  title="Copy Details"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                </button>
                <button 
                  onClick={() => window.open('https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security', '_blank')}
                  className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 text-sm"
                  title="Learn More"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                </button>
                <button 
                  className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 text-sm"
                  title="Report False Positive"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// TECHNICAL SSL DETAILS COLUMN 1
const TechnicalSSLDetailsColumn1 = ({ sslData, securityScores, lastUpdated }) => {
  const technicalData1 = [
    {
      name: "Certificate Issue Date",
      value: sslData?.not_before ? new Date(sslData.not_before).toLocaleString() : "Not available",
      description: "When the certificate became valid (Not Before)",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3a2 2 0 012-2h4a2 2 0 012 2v4m-6 0V6a2 2 0 012-2h4a2 2 0 012 2v1m-6 0h6m-6 0l-.5-1.5A2 2 0 0014.5 3H16a2 2 0 012 2v1M8 7l-.5-1.5A2 2 0 005.5 3H4a2 2 0 00-2 2v1m6 1v10a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h2a2 2 0 012 2z" />
        </svg>
      )
    },
    {
      name: "Certificate Expiry Date", 
      value: sslData?.expires_on ? new Date(sslData.expires_on).toLocaleString() : "Not available",
      description: "When the certificate expires (Not After)",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      )
    },
    {
      name: "Certificate Validity Period",
      value: sslData?.not_before && sslData?.expires_on ? 
        `${Math.round((new Date(sslData.expires_on) - new Date(sslData.not_before)) / (1000 * 60 * 60 * 24))} days` : "Not available",
      description: "Total certificate validity period",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3a2 2 0 012-2h4a2 2 0 012 2v4m-6 0V6a2 2 0 012-2h4a2 2 0 012 2v1m-6 0h6m-6 0l-.5-1.5A2 2 0 0014.5 3H16a2 2 0 012 2v1M8 7l-.5-1.5A2 2 0 005.5 3H4a2 2 0 00-2 2v1m6 1v10a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h2a2 2 0 012 2z" />
        </svg>
      )
    },
    {
      name: "Certificate Subject",
      value: sslData?.subject_cn || "Not available",
      description: "Subject Common Name (CN) from certificate",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
        </svg>
      )
    },
    {
      name: "Certificate Issuer", 
      value: sslData?.issuer_cn || "Not available",
      description: "Certificate Authority that signed this certificate",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
        </svg>
      )
    },
    {
      name: "Subject Organization",
      value: sslData?.subject_org || "Not available",
      description: "Organization listed in certificate subject",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
        </svg>
      )
    },
    {
      name: "Issuer Organization",
      value: sslData?.issuer_org || "Not available", 
      description: "Certificate Authority organization name",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z" />
        </svg>
      )
    },
    {
      name: "Serial Number",
      value: sslData?.serial_number || "Not available",
      description: "Unique certificate serial number",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14" />
        </svg>
      )
    }
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-3">
        <h5 className="font-medium text-sm text-gray-900 dark:text-gray-100 flex items-center border-b border-blue-300 dark:border-blue-500/30 pb-2 w-full">
          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          Advanced Technical Details
          <span className="ml-2 text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded">
            Part 1
          </span>
        </h5>
      </div>
      
      <div className="space-y-2">
        {technicalData1.map((item, index) => (
          <div key={index} className="bg-gray-50 dark:bg-gray-800 rounded border border-gray-300 dark:border-gray-600 p-3">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center mb-1">
                  <div className="text-gray-600 dark:text-gray-400 mr-2">
                    {item.icon}
                  </div>
                  <div className="font-medium text-xs text-gray-900 dark:text-gray-100 uppercase tracking-wide">
                    {item.name}
                  </div>
                </div>
                <div className="text-sm text-gray-700 dark:text-gray-300 font-mono break-all">
                  {item.value}
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  {item.description}
                </div>
              </div>
              <button 
                onClick={() => navigator.clipboard?.writeText(String(item.value))}
                className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 ml-2 text-xs"
                title="Copy Value"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// TECHNICAL SSL DETAILS COLUMN 2 WITH PEM MODAL
const TechnicalSSLDetailsColumn2 = ({ sslData }) => {
  const [showPEMModal, setShowPEMModal] = useState(false);

  const technicalData2 = [
    {
      name: "Signature Algorithm",
      value: sslData?.signature_algorithm || "Not available",
      description: "Algorithm used to sign the certificate",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      )
    },
    {
      name: "Certificate Chain Length",
      value: sslData?.chain_length || "Not available",
      description: "Number of certificates in the trust chain",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
        </svg>
      )
    },
    {
      name: "Key Curve",
      value: sslData?.key_curve || "Not available",
      description: "Elliptic curve name (for EC keys)",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
        </svg>
      )
    },
    {
      name: "Cipher Suite",
      value: sslData?.cipher_suite || "Not available",
      description: "Encryption algorithm suite being used",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4.871 4A17.926 17.926 0 003 12c0 2.874.673 5.59 1.871 8m14.13 0a17.926 17.926 0 001.87-8c0-2.874-.673-5.59-1.87-8M9 9h1.246a1 1 0 01.961.725l1.586 5.55a1 1 0 00.961.725H15" />
        </svg>
      )
    },
    {
      name: "Wildcard Certificate",
      value: sslData?.wildcard_cert ? "Yes" : "No",
      description: "Whether this is a wildcard certificate",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
        </svg>
      )
    },
    {
      name: "Certificate Version",
      value: sslData?.version ? `v${sslData.version}` : "Not available",
      description: "X.509 certificate version",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 4V2a1 1 0 011-1h8a1 1 0 011 1v2m-9 0h10m-10 0a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V6a2 2 0 00-2-2M8 9h8M8 13h8" />
        </svg>
      )
    },
    {
      name: "Extensions Present",
      value: sslData?.extensions_count || "Not available",
      description: "Number of certificate extensions",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
        </svg>
      )
    },
    {
      name: "Certificate Fingerprint",
      value: sslData?.fingerprint_sha256 ? `${sslData.fingerprint_sha256.substring(0, 16)}...` : "Not available",
      description: "SHA-256 fingerprint of the certificate",
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
        </svg>
      )
    }
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-3">
        <h5 className="font-medium text-sm text-gray-900 dark:text-gray-100 flex items-center border-b border-blue-300 dark:border-blue-500/30 pb-2 w-full">
          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          Advanced Technical Details
          <span className="ml-2 text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded">
            Part 2
          </span>
        </h5>
      </div>
      
      <div className="space-y-2">
        {technicalData2.map((item, index) => (
          <div key={index} className="bg-gray-50 dark:bg-gray-800 rounded border border-gray-300 dark:border-gray-600 p-3">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center mb-1">
                  <div className="text-gray-600 dark:text-gray-400 mr-2">
                    {item.icon}
                  </div>
                  <div className="font-medium text-xs text-gray-900 dark:text-gray-100 uppercase tracking-wide">
                    {item.name}
                  </div>
                </div>
                <div className="text-sm text-gray-700 dark:text-gray-300 font-mono break-all">
                  {item.value}
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  {item.description}
                </div>
              </div>
              <button 
                onClick={() => navigator.clipboard?.writeText(String(item.value))}
                className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 ml-2 text-xs"
                title="Copy Value"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* PEM CERTIFICATE SECTION */}
      {sslData?.certificate_pem && (
        <div className="mt-4 border-t border-gray-300 dark:border-gray-600 pt-4">
          <div className="flex items-center justify-between mb-2">
            <h6 className="font-medium text-xs text-gray-900 dark:text-gray-100 uppercase tracking-wide flex items-center">
              <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Raw Certificate Data (PEM)
            </h6>
            <button
              onClick={() => setShowPEMModal(true)}
              className="text-xs text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600"
            >
              Show PEM
              <svg className="w-3 h-3 inline ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </button>
          </div>
          
          <div className="text-xs text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 rounded p-2 border border-gray-300 dark:border-gray-600">
            Certificate data available in PEM format. Click "Show PEM" to view in modal.
          </div>

          <PEMModal 
            isOpen={showPEMModal}
            onClose={() => setShowPEMModal(false)}
            pemData={sslData.certificate_pem}
          />
        </div>
      )}
    </div>
  );
};

// INTERACTIVE PIE CHART WITH NO HOVER MOVEMENT ON LABELS
const InteractivePieChart = ({ data }) => {
  const { series, labels, colors } = data;
  const [hoveredIndex, setHoveredIndex] = useState(null);
  
  return (
    <div className="grid grid-cols-2 gap-4 items-start">
      
      {/* LEFT - Static Legend (NO MOVEMENT ON HOVER) */}
      <div className="space-y-2">
        {series.map((value, index) => (
          <div 
            key={index} 
            className="flex items-center justify-between text-sm p-2 rounded-lg cursor-default"
          >
            <div className="flex items-center space-x-3">
              <div 
                className="w-4 h-4 rounded-full"
                style={{ backgroundColor: colors[index] }}
              />
              <span className="text-gray-700 dark:text-gray-300">
                {labels[index]}
              </span>
            </div>
            <span className="font-semibold text-gray-900 dark:text-white">
              {value}%
            </span>
          </div>
        ))}
        
        {/* Total Summary - Static */}
        <div className="pt-2 border-t border-gray-300 dark:border-gray-600">
          <div className="flex items-center justify-between p-2">
            <span className="font-semibold text-gray-800 dark:text-gray-200 text-sm">
              Total Risk
            </span>
            <span className="font-bold text-lg text-gray-900 dark:text-white">
              100%
            </span>
          </div>
        </div>
      </div>

      {/* RIGHT - Interactive Pie Chart (MOVEMENT ONLY ON PIE CHART) */}
      <div className="flex justify-center items-start -mt-2">
        <div className="relative">
          <div 
            className={`w-40 h-40 rounded-full border-4 border-gray-300 dark:border-gray-600 transition-all duration-500 cursor-pointer relative overflow-hidden ${
              hoveredIndex !== null ? 'transform scale-125 shadow-2xl rotate-3' : 'hover:shadow-lg hover:scale-105'
            }`}
            style={{
              background: `conic-gradient(${colors.map((color, index) => {
                const start = series.slice(0, index).reduce((sum, val) => sum + val, 0);
                const end = start + series[index];
                const opacity = hoveredIndex === null || hoveredIndex === index ? 1 : 0.4;
                return `${color}${Math.round(opacity * 255).toString(16).padStart(2, '0')} ${start}% ${end}%`;
              }).join(', ')})`,
            }}
          >
            {/* Center circle with dynamic content */}
            <div className={`absolute inset-0 flex items-center justify-center transition-all duration-300 ${
              hoveredIndex !== null ? 'transform scale-75' : ''
            }`}>
              <div className="bg-white dark:bg-gray-900 rounded-full w-16 h-16 flex items-center justify-center shadow-lg border-2 border-gray-300 dark:border-gray-700">
                <div className="text-center">
                  {hoveredIndex !== null ? (
                    <>
                      <div className={`text-xs font-bold transition-colors duration-300`} style={{ color: colors[hoveredIndex] }}>
                        {labels[hoveredIndex]}
                      </div>
                      <div className="text-lg font-bold text-gray-900 dark:text-white">
                        {series[hoveredIndex]}%
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="text-xs font-medium text-gray-600 dark:text-gray-400">Risk</div>
                      <div className="text-sm font-bold text-gray-900 dark:text-white">100%</div>
                    </>
                  )}
                </div>
              </div>
            </div>
            
            {/* Invisible hover zones for each segment */}
            {series.map((value, index) => {
              const startAngle = series.slice(0, index).reduce((sum, val) => sum + val, 0) * 3.6;
              const endAngle = startAngle + (value * 3.6);
              
              return (
                <div
                  key={index}
                  className="absolute inset-0 cursor-pointer"
                  style={{
                    clipPath: `polygon(50% 50%, ${50 + 40 * Math.cos((startAngle - 90) * Math.PI / 180)}% ${50 + 40 * Math.sin((startAngle - 90) * Math.PI / 180)}%, ${50 + 40 * Math.cos((endAngle - 90) * Math.PI / 180)}% ${50 + 40 * Math.sin((endAngle - 90) * Math.PI / 180)}%)`
                  }}
                  onMouseEnter={() => setHoveredIndex(index)}
                  onMouseLeave={() => setHoveredIndex(null)}
                />
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

// WHOIS DETAILS COMPONENT
const WhoisDetails = ({ whoisData }) => {
  const formatDate = (dateString) => {
    if (!dateString) return "Not available";
    try {
      return new Date(dateString).toLocaleDateString();
    } catch {
      return dateString;
    }
  };

  return (
    <div className="mt-3 p-3 bg-green-50 dark:bg-green-900/20 border border-green-300 dark:border-green-500/30 rounded-lg">
      <h4 className="font-medium text-sm mb-2 text-gray-900 dark:text-green-300 flex items-center">
        <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        WHOIS Information
      </h4>
      <div className="grid grid-cols-2 gap-4 text-xs">
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Creation Date:</div>
          <div className="text-gray-600 dark:text-gray-400">{formatDate(whoisData.creation_date)}</div>
        </div>
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Expiration Date:</div>
          <div className="text-gray-600 dark:text-gray-400">{formatDate(whoisData.expiration_date)}</div>
        </div>
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Registrar:</div>
          <div className="text-gray-600 dark:text-gray-400">{whoisData.registrar || "Not available"}</div>
        </div>
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Status:</div>
          <div className="text-gray-600 dark:text-gray-400">{whoisData.status || "Not available"}</div>
        </div>
      </div>
      {whoisData.errors && whoisData.errors.length > 0 && (
        <div className="mt-2 text-xs text-red-600 dark:text-red-400">
          <div className="font-medium">Errors:</div>
          {whoisData.errors.map((error, index) => (
            <div key={index}>• {error}</div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Scanner;
