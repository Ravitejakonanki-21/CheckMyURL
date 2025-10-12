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

  // Transform backend response to frontend format - ENHANCED VERSION
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

    // NEW: Incorporate backend risk score into pie chart calculation
    // Use backend risk score as the primary driver for dangerous component
    const backendRiskScore = backendData.risk_score || 0;
    
    // Adjust the scores based on backend risk assessment
    if (backendRiskScore >= 70) {
      // High risk from backend - shift towards dangerous
      dangerousScore += Math.max(40, dangerousScore);
      suspiciousScore = Math.max(suspiciousScore, 30);
      safeScore = Math.max(10, safeScore - 20);
    } else if (backendRiskScore >= 40) {
      // Medium risk from backend - shift towards suspicious
      suspiciousScore += Math.max(25, suspiciousScore);
      dangerousScore = Math.max(10, dangerousScore);
      safeScore = Math.max(20, safeScore - 10);
    } else {
      // Low risk from backend - reinforce safe score
      safeScore += Math.max(20, safeScore);
      suspiciousScore = Math.max(5, suspiciousScore);
      dangerousScore = Math.max(0, dangerousScore - 10);
    }

    // NEW: Factor in specific backend flags that indicate high risk
    if (rules.has_suspicious_words && rules.has_brand_words_in_host) {
      // Both suspicious words and brand impersonation - high risk
      dangerousScore += 20;
      safeScore = Math.max(0, safeScore - 15);
    }

    if (idn.is_idn && idn.mixed_confusable_scripts) {
      // IDN with mixed scripts - very suspicious
      dangerousScore += 15;
      suspiciousScore += 10;
    }

    if (ssl.expired && !ssl.https_ok) {
      // Both expired and no HTTPS - critical risk
      dangerousScore += 25;
      safeScore = Math.max(0, safeScore - 20);
    }

    // Ensure minimum values and normalize
    safeScore = Math.max(0, safeScore);
    suspiciousScore = Math.max(0, suspiciousScore);
    dangerousScore = Math.max(0, dangerousScore);

    // Normalize scores to 100% while preserving backend risk influence
    const total = Math.max(safeScore + suspiciousScore + dangerousScore, 100);
    
    // Calculate normalized percentages
    let normalizedSafe = Math.round((safeScore / total) * 100);
    let normalizedSuspicious = Math.round((suspiciousScore / total) * 100);
    let normalizedDangerous = 100 - normalizedSafe - normalizedSuspicious;

    // Ensure the pie chart reflects backend risk score dominance
    if (backendRiskScore >= 70 && normalizedDangerous < 50) {
      // Force dangerous to be prominent for high risk backend scores
      normalizedDangerous = Math.max(50, normalizedDangerous);
      const remaining = 100 - normalizedDangerous;
      normalizedSuspicious = Math.round(remaining * 0.7);
      normalizedSafe = remaining - normalizedSuspicious;
    } else if (backendRiskScore >= 40 && normalizedSuspicious < 40) {
      // Force suspicious to be prominent for medium risk backend scores
      normalizedSuspicious = Math.max(40, normalizedSuspicious);
      const remaining = 100 - normalizedSuspicious;
      normalizedDangerous = Math.round(remaining * 0.3);
      normalizedSafe = remaining - normalizedDangerous;
    }

    // Final validation to ensure total is 100
    const finalTotal = normalizedSafe + normalizedSuspicious + normalizedDangerous;
    if (finalTotal !== 100) {
      // Adjust the largest component to make total 100
      const diff = 100 - finalTotal;
      if (normalizedDangerous >= normalizedSuspicious && normalizedDangerous >= normalizedSafe) {
        normalizedDangerous += diff;
      } else if (normalizedSuspicious >= normalizedSafe) {
        normalizedSuspicious += diff;
      } else {
        normalizedSafe += diff;
      }
    }

    // Determine classification based on backend risk score
    let classification = "Low Risk";
    if (backendRiskScore >= 70) classification = "High Risk";
    else if (backendRiskScore >= 40) classification = "Medium Risk";

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
      riskScore: backendRiskScore, // Use the backend risk score
      classification: classification,
      pie: {
        series: [normalizedSafe, normalizedSuspicious, normalizedDangerous],
        labels: ['Safe', 'Suspicious', 'Dangerous'],
        colors: ['#10B981', '#F59E0B', '#EF4444']
      },
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
    if (!url.trim()) {
      setError('Please enter a URL to scan');
      return;
    }
    
    setLoading(true);
    setError(null);
    
    try {
      // Call your Flask backend
      const backendResponse = await analyzeUrl(url.trim());
      
      // Transform backend response to frontend format
      const transformedResult = transformBackendResponse(backendResponse);
      
      setResult(transformedResult);
      if (recordScan && typeof recordScan === 'function') {
        recordScan(transformedResult);
      }
      setCurrentPage('results'); // Navigate to results page
    } catch (err) {
      setError(`Analysis failed: ${err.message}. Make sure your Flask backend is running on http://127.0.0.1:5000`);
      console.error('Scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  const onNewScan = () => {
    setCurrentPage('input');
    setUrl("");
    setResult(null);
    setError(null);
    setExpandedRows({});
  };

  const onClear = () => {
    setUrl("");
    setError(null);
  };

  // Render different pages based on currentPage state
  if (currentPage === 'results' && result) {
    return <ResultsPage 
      result={result} 
      onNewScan={onNewScan}
      expandedRows={expandedRows}
      setExpandedRows={setExpandedRows}
    />;
  }

  // Input Page - Modern design that works in both light and dark theme
  return (
    <div className="min-h-screen bg-white dark:bg-black flex flex-col items-center justify-center px-4">
      {/* Main Content Container */}
      <div className="w-full max-w-2xl">
        {/* Title */}
        <div className="text-center mb-12">
          <h1 className="text-6xl md:text-5xl font-bold mb-5">
            <span className="text-gray-900 dark:text-white">URL </span>
            <span className="text-cyan-500 dark:text-cyan-400">Scanner</span>
          </h1>
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            Enter a URL to scan and analyze
          </p>
        </div>

        {/* Search Box */}
        <div className="relative mb-10">
          <div className="flex items-center bg-gradient-to-r from-cyan-500/10 to-blue-500/10 dark:from-cyan-500/10 dark:to-blue-500/10 border border-cyan-500/30 dark:border-cyan-500/30 rounded-full px-6 py-5 backdrop-blur-sm">
            {/* Search Icon */}
            <svg className="w-6 h-6 text-cyan-500 dark:text-cyan-400 mr-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            
            {/* Input Field */}
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan..."
              className="flex-1 text-lg bg-transparent text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-500 outline-none"
              onKeyPress={(e) => e.key === 'Enter' && onScan()}
              disabled={loading}
              autoFocus
            />
            
            {/* Scan Button */}
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

        {/* Action Buttons */}
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

        {/* Error Display */}
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

// Pie Chart Component
const PieChart = ({ data }) => {
  const { series, labels, colors } = data;
  const total = series.reduce((sum, value) => sum + value, 0);
  
  // Calculate cumulative percentages for the conic gradient
  let cumulative = 0;
  const gradients = series.map((value, index) => {
    const start = cumulative;
    cumulative += (value / total) * 100;
    return `${colors[index]} ${start}% ${cumulative}%`;
  }).join(', ');

  return (
    <div className="flex flex-col items-center">
      {/* Pie Chart Visualization */}
      <div className="relative w-48 h-48 mb-6">
        <div 
          className="w-full h-full rounded-full border-4 border-gray-200 dark:border-gray-700"
          style={{
            background: `conic-gradient(${gradients})`
          }}
        />
        
        {/* Center text */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {total}%
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">
              Total
            </div>
          </div>
        </div>
      </div>

      {/* Legend */}
      <div className="space-y-3 w-full">
        {series.map((value, index) => (
          <div key={index} className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div 
                className="w-4 h-4 rounded-full"
                style={{ backgroundColor: colors[index] }}
              />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                {labels[index]}
              </span>
            </div>
            <span className="text-sm font-semibold text-gray-900 dark:text-white">
              {value}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

// Separate Results Page Component
function ResultsPage({ result, onNewScan, expandedRows, setExpandedRows }) {
  // Toggle row expansion
  const toggleRowExpansion = (rowKey) => {
    setExpandedRows(prev => ({
      ...prev,
      [rowKey]: !prev[rowKey]
    }));
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
      {/* Header with navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-black">
        <div className="max-w-6xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <button
              onClick={onNewScan}
              className="inline-flex items-center gap-2 text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-4 py-2 rounded-lg hover:bg-blue-50 dark:hover:bg-gray-700"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
              New Scan
            </button>
            <h1 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
              Scan Results
            </h1>
            <button
              onClick={exportPdf}
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 transition-colors duration-200 dark:bg-blue-500 dark:hover:bg-blue-600"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export PDF
            </button>
          </div>
        </div>
      </div>

      {/* Results Content */}
      <div className="max-w-6xl mx-auto px-4 py-8">
        {/* Summary Section */}
        <div className="mb-8">
          <h2 className="text-xl font-medium text-gray-900 dark:text-gray-100 mb-4">
            {result.url}
          </h2>
          <div className="inline-flex items-center gap-4 bg-gray dark:bg-black rounded-lg px-6 py-3">
            <span className="text-base text-gray-700 dark:text-gray-300">
              Risk Score: <span className={`font-semibold ${result.riskScore >= 70 ? 'text-red-600 dark:text-red-400' : result.riskScore >= 40 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'}`}>
                {result.riskScore}
              </span>
            </span>
            <span className="text-gray-400 dark:text-gray-600">•</span>
            <span className="text-base text-gray-700 dark:text-gray-300">
              Classification: <span className={`font-semibold ${result.classification === 'High Risk' ? 'text-red-600 dark:text-red-400' : result.classification === 'Medium Risk' ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'}`}>
                {result.classification}
              </span>
            </span>
          </div>
        </div>

        {/* Risk Overview Cards */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Pie Chart Card */}
          <div className="lg:col-span-1">
            <div className="bg-white dark:bg-black rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                Risk Composition
              </h3>
              {result.pie && <PieChart data={result.pie} />}
            </div>
          </div>

          {/* Risk Explanation Card */}
          <div className="lg:col-span-2">
            <div className="bg-blue-50 dark:bg-black rounded-lg border border-blue-100 dark:border-gray-700 p-6 h-full">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">Risk Analysis</h3>
              <div className="text-gray-700 dark:text-gray-300 leading-relaxed">
                {explain(result)}
              </div>
            </div>
          </div>
        </div>

        {/* Detailed Results */}
        <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden bg-white dark:bg-black">
          <div className="bg-black-50 dark:bg-gray-750 border-b border-gray-200 dark:border-gray-700 px-6 py-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Scan Details</h3>
          </div>
          
          <div className="overflow-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-black-50 dark:bg-gray-750">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Field</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Value</th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-black divide-y divide-gray-200 dark:divide-gray-700">
                <tr>
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">URL</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">{result.url}</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Risk Score</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">{result.riskScore}</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Classification</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">{result.classification}</td>
                </tr>
                
                {/* SSL Valid with expandable details */}
                <tr>
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">SSL Valid</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">
                    <div className="flex items-center justify-between">
                      <span>{result.details.sslValid ? "Yes" : "No"}</span>
                      {result.details.sslData && (
                        <button
                          onClick={() => toggleRowExpansion('ssl')}
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
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
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">WHOIS Age (months)</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">
                    <div className="flex items-center justify-between">
                      <span>{result.details.whoisAgeMonths}</span>
                      {result.details.whoisData && (
                        <button
                          onClick={() => toggleRowExpansion('whois')}
                          className="ml-2 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
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
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Open Ports</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">{result.details.openPorts.join(", ") || "None"}</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Security Headers</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">{result.details.securityHeaders.join(", ") || "None"}</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">Keywords</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">{result.details.keywords.join(", ") || "None"}</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-200">ML Phishing Score</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">{result.details.mlPhishingScore}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

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
    <div className="mt-3 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-500/30 rounded-lg">
      <h4 className="font-medium text-sm mb-3 text-gray-900 dark:text-blue-300">SSL/TLS Security Analysis</h4>
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

      {/* Certificate Summary */}
      {sslData?.https_ok && (
        <div className="mt-3 p-3 bg-blue-50 dark:bg-blue-900/20 rounded border border-blue-200 dark:border-blue-500">
          <h5 className="font-medium text-sm text-blue-800 dark:text-blue-300 mb-2">Certificate Summary:</h5>
          <div className="text-xs text-blue-700 dark:text-blue-400 space-y-1">
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