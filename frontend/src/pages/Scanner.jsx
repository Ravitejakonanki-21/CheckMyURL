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

  // NEW SCAN CONFIRMATION
  const onNewScan = () => {
    const confirmNewScan = window.confirm(
      "Are you sure you want to start a new scan? This will clear the current results."
    );
    
    if (confirmNewScan) {
      setCurrentPage('input');
      setUrl("");
      setResult(null);
      setError(null);
      setExpandedRows({});
    }
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
    />;
  }

  // Input Page (unchanged)
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
          <div className="flex items-center bg-gradient-to-r from-cyan-500/10 to-blue-500/10 dark:from-cyan-500/10 dark:to-blue-500/10 border border-cyan-500/30 dark:border-cyan-500/30 rounded-full px-6 py-5 backdrop-blur-sm">
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
            className="px-8 py-3 bg-gray-200 hover:bg-gray-300 dark:bg-black disabled:bg-gray-200 dark:disabled:bg-gray-900 disabled:opacity-50 text-gray-700 dark:text-gray-300 rounded-lg transition-all duration-200 border border-gray-300 dark:border-gray-700 disabled:cursor-not-allowed"
          >
            Quick Scan
          </button>
          
          <button
            onClick={onScan}
            disabled={loading || !url.trim()}
            className="px-8 py-3 bg-gray-200 hover:bg-gray-300 dark:bg-black disabled:bg-gray-200 dark:disabled:bg-gray-900 disabled:opacity-50 text-gray-700 dark:text-gray-300 rounded-lg transition-all duration-200 border border-gray-300 dark:border-gray-700 disabled:cursor-not-allowed"
          >
            Deep Analysis
          </button>
        </div>

        <div className="max-w-4xl mx-auto px-4 mb-12">
          <div className="flex flex-wrap justify-center gap-6">
            {[
              { name: "SSL/TLS Check", icon: "🔒" },
              { name: "WHOIS Lookup", icon: "🌐" },
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

        {error && (
          <div className="mt-6 p-4 bg-red-100 dark:bg-red-500/10 border border-red-300 dark:border-red-500/30 rounded-lg backdrop-blur-sm">
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

// RESULTS PAGE - With TRUST SCORE REMOVED
function ResultsPage({ result, onNewScan, expandedRows, setExpandedRows }) {
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
      {/* Header - Full Width */}
      <div className="border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-black">
        <div className="w-full px-6 py-3">
          <div className="flex items-center justify-between">
            <button
              onClick={onNewScan}
              className="inline-flex items-center gap-2 text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-3 py-1.5 rounded-lg hover:bg-blue-50 dark:hover:bg-gray-700 text-sm"
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
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700 transition-colors duration-200 dark:bg-blue-500 dark:hover:bg-blue-600"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export PDF
            </button>
          </div>
        </div>
      </div>

      {/* COMPACT SUMMARY SECTION - Full Width with Enhanced SSL Display */}
      <div className="w-full px-6 py-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          
          {/* LEFT - URL, Risk Score, Classification & Enhanced Analysis */}
          <div className="lg:col-span-1">
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4 shadow-sm">
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
              <div className="border-t border-gray-200 dark:border-gray-700 pt-3">
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

          {/* RIGHT - Risk Composition with Movement */}
          <div className="lg:col-span-2">
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4 shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Risk Composition
              </h3>
              {updatedResult.pie && <InteractivePieChart data={updatedResult.pie} />}
            </div>
          </div>
        </div>
      </div>

      {/* MAIN FOCUS - Complete Scan Details Table with ALL ROWS (TRUST SCORE REMOVED) */}
      <div className="w-full px-6 pb-8">
        <div className="border border-gray-200 dark:border-gray-700 rounded-2xl overflow-hidden bg-white dark:bg-gray-900 shadow-lg">
          <div className="bg-gray-50 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-4">
            <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100">🔒 Enhanced Security Analysis</h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">Complete security assessment with professional SSL analysis, domain validation, and threat detection</p>
          </div>
          
          <div className="overflow-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-4 text-left text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider">Field</th>
                  <th className="px-4 py-4 text-left text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider">Value</th>
                  <th className="px-4 py-4 text-left text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider">Details</th>
                  <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Total Score: {securityScores.overall}%
                  </th>
                  <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider">Weight</th>
                  <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider">Last Updated</th>
                  <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Quick Actions
                    <button 
                      onClick={(e) => copyAllResults(e.target)}
                      className="ml-2 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200"
                      title="Copy All Results"
                    >
                      ⧉
                    </button>
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                
                {/* URL ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">URL</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">{result.url}</td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">Scanned domain with enhanced analysis</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">—</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">—</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(result.url, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy URL"
                    >
                      ⧉
                    </button>
                  </td>
                </tr>

                {/* RISK SCORE ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Risk Score</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
                    <span className={`font-bold ${
                      result.riskScore >= 70 ? 'text-red-600 dark:text-red-400' : 
                      result.riskScore >= 40 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-green-600 dark:text-green-400'
                    }`}>
                      {result.riskScore}%
                    </span>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">Overall security risk assessment</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">—</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">—</td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Risk Score: ${result.riskScore}%`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Risk Score"
                    >
                      ⧉
                    </button>
                  </td>
                </tr>
                
                {/* ENHANCED SSL/TLS SECURITY ROW (NO TRUST SCORE) */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">SSL/TLS Security</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
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
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900"
                        >
                          {expandedRows['ssl'] ? 'Hide Details ▼' : 'View Details ▶'}
                        </button>
                      )}
                    </div>
                    {expandedRows['ssl'] && result.details.sslData && (
                      <EnhancedSSLDetails sslData={result.details.sslData} />
                    )}
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">
                    Professional SSL/TLS certificate validation
                  </td>
                  <td className="px-4 py-4 text-center">
                    <div className={`text-lg font-bold ${
                      securityScores.ssl >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.ssl >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.ssl}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300">
                    {securityScores.weights.ssl}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`SSL: ${result.details.sslValid ? 'Valid' : 'Invalid'}`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy SSL Status"
                    >
                      ⧉
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('ssl', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      ↗
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('SSL/TLS Security', result.details.sslValid ? 'Valid' : 'Invalid', e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      ⚠
                    </button>
                  </td>
                </tr>
                
                {/* DOMAIN AGE ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Domain Age</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
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
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900"
                        >
                          {expandedRows['whois'] ? 'Hide Details ▼' : 'View More Details ▶'}
                        </button>
                      )}
                    </div>
                    {expandedRows['whois'] && result.details.whoisData && (
                      <WhoisDetails whoisData={result.details.whoisData} />
                    )}
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">Domain registration history and age</td>
                  <td className="px-4 py-4 text-center">
                    <div className={`text-lg font-bold ${
                      securityScores.domainAge >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.domainAge >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.domainAge}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300">
                    {securityScores.weights.domainAge}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Domain Age: ${result.details.whoisAgeMonths} months`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Domain Age"
                    >
                      ⧉
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('domain', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      ↗
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('Domain Age', `${result.details.whoisAgeMonths} months`, e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      ⚠
                    </button>
                  </td>
                </tr>

                {/* OPEN PORTS ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Open Ports</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
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
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900"
                        >
                          {expandedRows['ports'] ? 'Hide Ports ▼' : 'View Ports ▶'}
                        </button>
                      )}
                    </div>
                    {expandedRows['ports'] && result.details.openPorts.length > 0 && (
                      <div className="mt-3 p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-500/30 rounded-lg">
                        <h4 className="font-medium text-sm mb-2 text-gray-900 dark:text-blue-300">Detected Open Ports</h4>
                        <div className="space-y-1">
                          {result.details.openPorts.map((port, index) => (
                            <div key={index} className="text-xs text-gray-700 dark:text-gray-300 bg-white dark:bg-black px-2 py-1 rounded border">
                              Port {port}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">Network port scanning and availability check</td>
                  <td className="px-4 py-4 text-center">
                    <div className={`text-lg font-bold ${
                      securityScores.ports >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.ports >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.ports}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300">
                    {securityScores.weights.ports}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Open Ports: ${result.details.openPorts.length === 0 ? "None" : result.details.openPorts.join(", ")}`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Ports"
                    >
                      ⧉
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('ports', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      ↗
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('Open Ports', result.details.openPorts.length === 0 ? "None" : result.details.openPorts.join(", "), e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      ⚠
                    </button>
                  </td>
                </tr>

                {/* SECURITY HEADERS ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Security Headers</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
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
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900"
                        >
                          {expandedRows['headers'] ? 'Hide Headers ▼' : 'View Headers ▶'}
                        </button>
                      )}
                    </div>
                    {expandedRows['headers'] && result.details.securityHeaders.length > 0 && (
                      <div className="mt-3 p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-500/30 rounded-lg">
                        <h4 className="font-medium text-sm mb-2 text-gray-900 dark:text-blue-300">Security Headers Found</h4>
                        <div className="space-y-1">
                          {result.details.securityHeaders.map((header, index) => (
                            <div key={index} className="text-xs text-gray-700 dark:text-gray-300 bg-white dark:bg-black px-2 py-1 rounded border">
                              {header}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">HTTP security headers implementation check</td>
                  <td className="px-4 py-4 text-center">
                    <div className={`text-lg font-bold ${
                      securityScores.headers >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.headers >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.headers}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300">
                    {securityScores.weights.headers}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Security Headers: ${result.details.securityHeaders.length === 0 ? "None" : result.details.securityHeaders.join(", ")}`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Headers"
                    >
                      ⧉
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('headers', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      ↗
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('Security Headers', result.details.securityHeaders.length === 0 ? "None" : result.details.securityHeaders.join(", "), e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      ⚠
                    </button>
                  </td>
                </tr>

                {/* SUSPICIOUS KEYWORDS ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Suspicious Keywords</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
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
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900"
                        >
                          {expandedRows['keywords'] ? 'Hide Keywords ▼' : 'View Keywords ▶'}
                        </button>
                      )}
                    </div>
                    {expandedRows['keywords'] && result.details.keywords.length > 0 && (
                      <div className="mt-3 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                        <h4 className="font-medium text-sm mb-2 text-red-800 dark:text-red-300">Suspicious Keywords Detected</h4>
                        <div className="space-y-1">
                          {result.details.keywords.map((keyword, index) => (
                            <div key={index} className="text-xs text-red-700 dark:text-red-400 bg-white dark:bg-black px-2 py-1 rounded border border-red-200 dark:border-red-800">
                              {keyword}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">Phishing and malicious keyword detection</td>
                  <td className="px-4 py-4 text-center">
                    <div className={`text-lg font-bold ${
                      securityScores.keywords >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.keywords >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.keywords}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300">
                    {securityScores.weights.keywords}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`Keywords: ${result.details.keywords.length === 0 ? "None" : result.details.keywords.join(", ")}`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy Keywords"
                    >
                      ⧉
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('keywords', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      ↗
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('Keywords', result.details.keywords.length === 0 ? "None" : result.details.keywords.join(", "), e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      ⚠
                    </button>
                  </td>
                </tr>

                {/* ML PHISHING SCORE ROW */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">ML Phishing Score</td>
                  <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
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
                        className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900"
                      >
                        {expandedRows['ml'] ? 'Hide ML Details ▼' : 'View ML Analysis ▶'}
                      </button>
                    </div>
                    {expandedRows['ml'] && (
                      <div className="mt-3 p-3 bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-500/30 rounded-lg">
                        <h4 className="font-medium text-sm mb-2 text-gray-900 dark:text-purple-300">Machine Learning Analysis</h4>
                        <div className="text-xs text-gray-700 dark:text-gray-300 space-y-1">
                          <div>• URL pattern analysis</div>
                          <div>• Domain reputation scoring</div>
                          <div>• Behavioral threat detection</div>
                          <div>• Real-time risk assessment</div>
                        </div>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">Machine learning phishing detection algorithm</td>
                  <td className="px-4 py-4 text-center">
                    <div className={`text-lg font-bold ${
                      securityScores.mlPhishing >= 80 ? 'text-green-600 dark:text-green-400' : 
                      securityScores.mlPhishing >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {securityScores.mlPhishing}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300">
                    {securityScores.weights.mlPhishing}%
                  </td>
                  <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400">{lastUpdated}</td>
                  <td className="px-4 py-4 text-center">
                    <button 
                      onClick={(e) => copyToClipboard(`ML Score: ${result.details.mlPhishingScore}% risk`, e.target)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1"
                      title="Copy ML Score"
                    >
                      ⧉
                    </button>
                    <button 
                      onClick={(e) => openLearnMore('ml', e.target)}
                      className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1"
                      title="Learn More"
                    >
                      ↗
                    </button>
                    <button 
                      onClick={(e) => reportFalsePositive('ML Phishing Score', `${result.details.mlPhishingScore}% risk`, e.target)}
                      className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1"
                      title="Report False Positive"
                    >
                      ⚠
                    </button>
                  </td>
                </tr>

              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

// ENHANCED SSL DETAILS COMPONENT (TRUST SCORE REMOVED)
const EnhancedSSLDetails = ({ sslData }) => {
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
      details: sslData?.https_ok ? "Secure HTTPS connection established" : "Failed to establish HTTPS connection"
    },
    {
      name: "Certificate Validity",
      description: "Certificate is currently valid and not expired",
      value: sslData?.certificate_valid,
      status: sslData?.certificate_valid ? 'good' : sslData?.expired === true ? 'bad' : 'warning',
      details: sslData?.certificate_valid ? "Certificate is currently valid" : 
              sslData?.expired === true ? "Certificate has expired" : "Certificate validity unknown"
    },
    {
      name: "Certificate Chain",
      description: "Complete certificate chain validation",
      value: sslData?.certificate_chain_complete,
      status: sslData?.certificate_chain_complete ? 'good' : 'warning',
      details: sslData?.certificate_chain_complete ? 
        `Complete chain (${sslData.chain_length || 'unknown'} levels)` : 
        "Incomplete certificate chain"
    },
    {
      name: "Hostname Match",
      description: "Certificate matches the requested hostname",
      value: sslData?.hostname_match,
      status: sslData?.hostname_match ? 'good' : 'bad',
      details: sslData?.hostname_match ? "Hostname verified" : "Hostname mismatch detected"
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
      name: "Key Algorithm",
      description: "Cryptographic algorithm and key size",
      value: sslData?.key_algorithm,
      status: sslData?.key_algorithm ? 'good' : 'warning',
      details: sslData?.key_algorithm ? 
        `${sslData.key_algorithm}${sslData.key_size ? ` (${sslData.key_size} bits)` : ''}` : 
        "Key algorithm information not available"
    },
    {
      name: "Certificate Expiration",
      description: "When the SSL certificate expires",
      value: sslData?.expires_on,
      status: daysUntilExpiry > 30 ? 'good' : daysUntilExpiry > 7 ? 'warning' : 'bad',
      details: sslData?.expires_on ? 
        `Expires: ${formatDate(sslData.expires_on)}${daysUntilExpiry !== null ? ` (${daysUntilExpiry} days remaining)` : ''}` :
        "Expiration date not available"
    }
  ];

  // Add SAN domains if available
  if (sslData?.san_domains && sslData.san_domains.length > 0) {
    enhancedChecks.push({
      name: "Subject Alternative Names",
      description: "Additional domains covered by this certificate",
      value: sslData.san_domains,
      status: 'good',
      details: `Also covers: ${sslData.san_domains.slice(0, 3).join(', ')}${sslData.san_domains.length > 3 ? ` (+${sslData.san_domains.length - 3} more)` : ''}`
    });
  }

  return (
    <div className="mt-3 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-500/30 rounded-lg">
      <h4 className="font-medium text-sm mb-3 text-gray-900 dark:text-blue-300">
        🔒 Enhanced SSL/TLS Security Analysis
      </h4>
      
      <div className="space-y-2">
        {enhancedChecks.map((check, index) => (
          <div key={index} className="flex items-center justify-between py-2 px-3 bg-white dark:bg-black rounded border border-gray-200 dark:border-gray-600">
            <div className="flex items-center space-x-3">
              <div className={`w-3 h-3 rounded-full ${
                check.status === 'good' ? 'bg-green-500' :
                check.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
              }`}></div>
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
        <div className="mt-3 p-3 bg-red-50 dark:bg-red-900/20 rounded border border-red-200 dark:border-red-800">
          <h5 className="font-medium text-sm text-red-800 dark:text-red-300 mb-2">SSL/TLS Errors:</h5>
          {sslData.errors.map((error, index) => (
            <div key={index} className="text-xs text-red-700 dark:text-red-400">• {error}</div>
          ))}
        </div>
      )}
    </div>
  );
};

// INTERACTIVE PIE CHART WITH MOVEMENT ANIMATIONS
const InteractivePieChart = ({ data }) => {
  const { series, labels, colors } = data;
  const [hoveredIndex, setHoveredIndex] = useState(null);
  
  return (
    <div className="grid grid-cols-2 gap-4 items-start">
      
      {/* LEFT - Compact Interactive Legend */}
      <div className="space-y-2">
        {series.map((value, index) => (
          <div 
            key={index} 
            className={`flex items-center justify-between text-sm p-2 rounded-lg transition-all duration-300 cursor-pointer ${
              hoveredIndex === index 
                ? 'bg-gray-100 dark:bg-gray-800 transform scale-110 shadow-lg' 
                : 'hover:bg-gray-50 dark:hover:bg-gray-800/50 hover:scale-105'
            }`}
            onMouseEnter={() => setHoveredIndex(index)}
            onMouseLeave={() => setHoveredIndex(null)}
          >
            <div className="flex items-center space-x-3">
              <div 
                className={`w-4 h-4 rounded-full transition-all duration-300 ${
                  hoveredIndex === index ? 'ring-4 ring-opacity-40 scale-125' : 'hover:scale-110'
                }`}
                style={{ 
                  backgroundColor: colors[index],
                  ringColor: colors[index]
                }}
              />
              <span className={`text-gray-700 dark:text-gray-300 transition-all duration-300 ${
                hoveredIndex === index ? 'font-bold text-gray-900 dark:text-white transform translate-x-1' : ''
              }`}>
                {labels[index]}
              </span>
            </div>
            <span className={`font-semibold transition-all duration-300 ${
              hoveredIndex === index 
                ? 'text-xl font-bold text-gray-900 dark:text-white transform scale-110' 
                : 'text-gray-900 dark:text-white'
            }`}>
              {value}%
            </span>
          </div>
        ))}
        
        {/* Total Summary - Compact */}
        <div className="pt-2 border-t border-gray-200 dark:border-gray-600">
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

      {/* RIGHT - Large Interactive Pie Chart with movement */}
      <div className="flex justify-center items-start -mt-2">
        <div className="relative">
          <div 
            className={`w-40 h-40 rounded-full border-4 border-gray-200 dark:border-gray-600 transition-all duration-500 cursor-pointer relative overflow-hidden ${
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
            
            {/* Center Label with animation */}
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className={`text-center transition-all duration-300 ${
                hoveredIndex !== null ? 'transform scale-110' : ''
              }`}>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {hoveredIndex !== null ? series[hoveredIndex] : '100'}%
                </div>
                <div className="text-xs text-gray-500 dark:text-black">
                  {hoveredIndex !== null ? labels[hoveredIndex] : 'Total'}
                </div>
              </div>
            </div>
          </div>
          
          {/* Hover Tooltip with animation */}
          {hoveredIndex !== null && (
            <div className="absolute -top-12 left-1/2 transform -translate-x-1/2 bg-black dark:bg-white text-white dark:text-black px-3 py-1 rounded-lg text-sm font-medium shadow-lg z-10 animate-bounce">
              {labels[hoveredIndex]}: {series[hoveredIndex]}%
              <div className="absolute bottom-[-4px] left-1/2 transform -translate-x-1/2 w-2 h-2 bg-black dark:bg-white rotate-45"></div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// WHOIS DETAILS COMPONENT (keeping the existing one)
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
    <div className="mt-3 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-500/30 rounded-lg">
      <h4 className="font-medium text-sm mb-3 text-gray-900 dark:text-blue-300">WHOIS Checkup Details</h4>
      <div className="space-y-2">
        {checks.map((check, index) => (
          <div key={index} className="flex items-center justify-between py-2 px-3 bg-white dark:bg-black rounded border border-gray-200 dark:border-gray-600">
            <div className="flex items-center space-x-3">
              <div className={`w-3 h-3 rounded-full ${
                check.status === 'good' ? 'bg-green-500' :
                check.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
              }`}></div>
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
                {check.value ? '✓' : '✗'}
              </div>
              <div className="text-xs text-gray-600 dark:text-gray-300">{check.details}</div>
            </div>
          </div>
        ))}
      </div>
      
      {whoisData?.errors && whoisData.errors.length > 0 && (
        <div className="mt-3 p-3 bg-red-50 dark:bg-red-900/20 rounded border border-red-200 dark:border-red-800">
          <h5 className="font-medium text-sm text-red-800 dark:text-red-300 mb-2">Errors Encountered:</h5>
          {whoisData.errors.map((error, index) => (
            <div key={index} className="text-xs text-red-700 dark:text-red-400">• {error}</div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Scanner;
