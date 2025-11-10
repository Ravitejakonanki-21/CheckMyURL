import { useState, useEffect } from "react";
import EnhancedSSLDetails from "./SSLDetails.jsx";
import WhoisDetails from "./WhoisDetails.jsx";
import SecurityHeaderDetails from "../../components/SecurityHeaderDetails.jsx";
import { copyToClipboard, openLearnMore, reportFalsePositive } from "../../utils/quickActions.js";
import { checkWhois } from "../../services/whoisService.js";
import KeywordDetails from "./KeywordDetails.jsx";


function ResultsTable({ result, securityScores, lastUpdated, expandedRows, setExpandedRows }) {
  const toggleRowExpansion = (key) => setExpandedRows(prev => ({ ...prev, [key]: !prev[key] }));
  const [copiedStates, setCopiedStates] = useState({});
  const [whoisData, setWhoisData] = useState(null);
  const [loadingWhois, setLoadingWhois] = useState(false);
  const [whoisError, setWhoisError] = useState(null);
  const [securityHeadersExpanded, setSecurityHeadersExpanded] = useState(false);


  useEffect(() => {
    const fetchWhoisData = async () => {
      if (expandedRows['whois'] && !whoisData && !loadingWhois) {
        setLoadingWhois(true);
        setWhoisError(null);
        try {
          const data = await checkWhois(result.url);
          setWhoisData(data);
        } catch (error) {
          console.error('Failed to fetch WHOIS data:', error);
          setWhoisError(error.message || 'Failed to fetch domain information');
        } finally {
          setLoadingWhois(false);
        }
      }
    };
    fetchWhoisData();
  }, [expandedRows['whois'], result.url, whoisData, loadingWhois]);


  const handleCopy = (text, field) => {
    copyToClipboard(text);
    setCopiedStates(prev => ({ ...prev, [field]: true }));
    setTimeout(() => {
      setCopiedStates(prev => ({ ...prev, [field]: false }));
    }, 2000);
  };


  const handleLearnMore = (type, e) => {
    e.preventDefault();
    e.stopPropagation();
    openLearnMore(type);
  };


  const handleReportFalsePositive = (field, value, e) => {
    e.preventDefault();
    e.stopPropagation();
    reportFalsePositive(field, value);
  };


  const copyAllResults = () => {
    const d = result.details, ssl = d.sslData;
    const text = [
      `URL: ${result.url}`, `Risk Score: ${result.riskScore}%`, `Classification: ${result.classification}`,
      `SSL/TLS: ${d.sslValid ? 'Valid' : 'Invalid'} (Score: ${securityScores.ssl})`,
      ssl.tls_version ? `TLS Version: ${ssl.tls_version}` : '', ssl.cipher_suite ? `Cipher Suite: ${ssl.cipher_suite}` : '',
      `Domain Age: ${d.whoisAgeMonths} months (Score: ${securityScores.domainAge})`,
      `Security Headers: ${d.securityHeaders.join(", ") || "None"} (Score: ${securityScores.headers})`,
      `Keywords: ${d.keywords.join(", ") || "None"} (Score: ${securityScores.keywords})`,
      `ML Score: ${d.mlPhishingScore}% risk (Score: ${securityScores.mlPhishing})`,
      `Overall Score: ${securityScores.overall}%`
    ].filter(Boolean).join('\n');
    handleCopy(text, 'all');
  };


  const handleWhoisToggle = () => {
    toggleRowExpansion('whois');
  };


  const copyKeywords = () => {
    const keywords = result.details.keywords || [];
    copyToClipboard(keywords.join(", ") || "None");
    setCopiedStates(prev => ({ ...prev, keywords: true }));
    setTimeout(() => {
      setCopiedStates(prev => ({ ...prev, keywords: false }));
    }, 2000);
  };


  // Format WHOIS summary for display
  const getWhoisSummary = () => {
    if (!whoisData) return "No data";
    
    const registrar = whoisData.registrar || "Unknown Registrar";
    const age = whoisData.age_days ? `${whoisData.age_days} days` : "Unknown age";
    const organization = whoisData.registrant_organization || "Unknown organization";
    
    return `${registrar} • ${age} • ${organization}`;
  };

  // Prepare keywordInfo object for KeywordDetails
  const getKeywordInfo = () => {
    const keywords = result.details.keywords || [];
    return {
      keywords: keywords,
      count: keywords.length,
      riskLevel: keywords.length > 5 ? 'high' : keywords.length > 2 ? 'medium' : 'low',
      score: securityScores.keywords,
      detectedAt: lastUpdated
    };
  };


  return (
    <div className="w-full px-6 pb-8">
      <div className="border border-gray-300 dark:border-gray-700 rounded-2xl overflow-hidden bg-white dark:bg-black shadow-lg">
        <div className="bg-transparent border-b border-gray-300 dark:border-gray-700 px-6 py-4">
          <div className="flex items-center space-x-2">
            <svg className="w-6 h-6 text-gray-600 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100">Enhanced Security Analysis</h3>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            Complete security assessment with professional SSL analysis, domain validation, and threat detection
          </p>
        </div>
        <div className="overflow-auto">
          <table className="min-w-full divide-y divide-gray-300 dark:divide-gray-700">
            <thead className="bg-transparent">
              <tr>
                <th className="px-4 py-4 text-left text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-700">Field</th>
                <th className="px-4 py-4 text-left text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-700">Value</th>
                <th className="px-4 py-4 text-left text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-700">Details</th>
                <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-700">Total Score: {securityScores.overall}%</th>
                <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-700">Weight</th>
                <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider border-r border-gray-300 dark:border-gray-700">Last Updated</th>
                <th className="px-4 py-4 text-center text-sm font-bold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                  Quick Actions
                  <button 
                    onClick={copyAllResults}
                    className="ml-2 w-12 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 transition-colors duration-200"
                    title="Copy All Results"
                  >
                    {copiedStates.all ? (
                      <span className="text-green-600 dark:text-green-400 text-xs font-medium">Copied!</span>
                    ) : (
                      <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    )}
                  </button>
                </th>
              </tr>
            </thead>
         <tbody className="bg-white dark:bg-black divide-y divide-gray-300 dark:divide-gray-700">


  {/* URL Row */}
  <tr className="hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors duration-150">
    <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-700">URL</td>
    <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-700">{result.url}</td>
    <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">Scanned domain with enhanced analysis</td>
    <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">—</td>
    <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">—</td>
    <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">{lastUpdated}</td>
    <td className="px-4 py-4 text-center">
      <button 
        onClick={() => handleCopy(result.url, 'url')}
        className="w-12 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1 transition-colors duration-200"
        title="Copy URL"
      >
        {copiedStates.url ? (
          <span className="text-green-600 dark:text-green-400 text-xs font-medium">Copied!</span>
        ) : (
          <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
      </button>
    </td>
  </tr>


  {/* Risk Score Row */}
  <tr className="hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors duration-150">
    <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-700">Risk Score</td>
    <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-700">
      <span className={`font-bold ${
        result.riskScore >= 70 ? 'text-red-600 dark:text-red-400' : 
        result.riskScore >= 40 ? 'text-yellow-600 dark:text-yellow-400' : 
        'text-green-600 dark:text-green-400'
      }`}>
        {result.riskScore}%
      </span>
    </td>
    <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">Overall security risk assessment</td>
    <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">—</td>
    <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">—</td>
    <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">{lastUpdated}</td>
    <td className="px-4 py-4 text-center">
      <button 
        onClick={() => handleCopy(`Risk Score: ${result.riskScore}%`, 'riskScore')}
        className="w-12 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1 transition-colors duration-200"
        title="Copy Risk Score"
      >
        {copiedStates.riskScore ? (
          <span className="text-green-600 dark:text-green-400 text-xs font-medium">Copied!</span>
        ) : (
          <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
      </button>
    </td>
  </tr>


  {/* SSL/TLS Security Row */}
  <tr className="hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors duration-150">
    <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-700">SSL/TLS Security</td>
    <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-700">
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
            className="ml-3 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600 whitespace-nowrap self-center"
          >
            {expandedRows['ssl'] ? 'Hide Details ▼' : 'Show All Details ▶'}
          </button>
        )}
      </div>
    </td>
    <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">
      Professional SSL/TLS certificate validation
    </td>
    <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-700">
      <div className={`text-lg font-bold ${
        securityScores.ssl >= 80 ? 'text-green-600 dark:text-green-400' : 
        securityScores.ssl >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
        'text-red-600 dark:text-red-400'
      }`}>
        {securityScores.ssl}
      </div>
    </td>
    <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-700">
      {securityScores.weights.ssl}%
    </td>
    <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">{lastUpdated}</td>
    <td className="px-4 py-4 text-center">
      <button 
        onClick={() => handleCopy(`SSL: ${result.details.sslValid ? 'Valid' : 'Invalid'}`, 'ssl')}
        className="w-12 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1 transition-colors duration-200"
        title="Copy SSL Status"
      >
        {copiedStates.ssl ? (
          <span className="text-green-600 dark:text-green-400 text-xs font-medium">Copied!</span>
        ) : (
          <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
      </button>
      <button 
        onClick={(e) => handleLearnMore('ssl', e)}
        className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1 transition-colors duration-200"
        title="Learn More"
      >
        <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
        </svg>
      </button>
      <button 
        onClick={(e) => handleReportFalsePositive('SSL/TLS Security', result.details.sslValid ? 'Valid' : 'Invalid', e)}
        className="text-orange-600 hover:text-orange-800 dark:text-orange-400 dark:hover:text-orange-200 mx-1 transition-colors duration-200"
        title="Report False Positive"
      >
        <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      </button>
    </td>
  </tr>
  {expandedRows['ssl'] && result.details.sslData && (
    <tr>
      <td colSpan="7" className="px-0 py-0 border-t border-gray-200 dark:border-gray-700">
        <EnhancedSSLDetails 
          sslData={result.details.sslData} 
          securityScores={securityScores} 
          lastUpdated={lastUpdated} 
          onHide={() => toggleRowExpansion('ssl')}
        />
      </td>
    </tr>
  )}


  {/* WHOIS Row */}
  <tr className="hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors duration-150">
    <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-700">WHOIS</td>
    <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-700">
      <div className="flex items-center justify-between">
        <div>
          {loadingWhois ? (
            <span className="text-gray-500 dark:text-gray-400">Loading domain information...</span>
          ) : whoisData ? (
            <span>{getWhoisSummary()}</span>
          ) : (
            <span className="text-gray-500 dark:text-gray-400">No data</span>
          )}
        </div>
        <button
          onClick={handleWhoisToggle}
          className="ml-3 text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600 whitespace-nowrap self-center"
        >
          {expandedRows['whois'] ? 'Hide Details ▼' : 'Show More Details ▶'}
        </button>
      </div>
    </td>
    <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">WHOIS domain registration details</td>
    <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-700">—</td>
    <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-700">—</td>
    <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-700">{lastUpdated}</td>
    <td className="px-4 py-4 text-center">
      <button 
        onClick={() => copyToClipboard(JSON.stringify(whoisData, null, 2))}
        className="w-12 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1 transition-colors duration-200"
        title="Copy WHOIS Data"
        disabled={!whoisData}
      >
        {copiedStates.whois ? (
          <span className="text-green-600 dark:text-green-400 text-xs font-medium">Copied!</span>
        ) : (
          <svg className={`w-4 h-4 inline ${!whoisData ? 'text-gray-400' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
      </button>
    </td>
  </tr>



  {expandedRows['whois'] && (
    <tr>
      <td colSpan="7" className="px-0 py-0 border-t border-gray-200 dark:border-gray-700">
        {loadingWhois ? (
          <div className="py-8 text-center bg-gray-50 dark:bg-gray-900">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-3">Fetching comprehensive domain information...</p>
            <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">This may take a few seconds</p>
          </div>
        ) : whoisError ? (
          <div className="py-8 text-center bg-red-50 dark:bg-red-900/20">
            <svg className="w-12 h-12 text-red-400 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            <p className="text-red-600 dark:text-red-400 font-medium">Error fetching WHOIS data</p>
            <p className="text-sm text-red-500 dark:text-red-400 mt-1">{whoisError}</p>
            <button
              onClick={() => {
                setWhoisData(null);
                setWhoisError(null);
              }}
              className="mt-3 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors"
            >
              Retry
            </button>
          </div>
        ) : whoisData ? (
          <WhoisDetails 
            whoisData={whoisData} 
            securityScores={securityScores}
            lastUpdated={lastUpdated}
            onHide={handleWhoisToggle}
            loading={loadingWhois}
          />
        ) : (
          <div className="py-8 text-center bg-yellow-50 dark:bg-yellow-900/20">
            <svg className="w-12 h-12 text-yellow-400 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            <p className="text-yellow-600 dark:text-yellow-400 font-medium">No WHOIS data available</p>
            <p className="text-sm text-yellow-500 dark:text-yellow-400 mt-1">The domain may not exist or WHOIS lookup failed</p>
          </div>
        )}
      </td>
    </tr>
  )}

  {/* SECURITY HEADERS ROW */}
  <tr className="hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors duration-150">
    <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-700">
      Security Headers
    </td>
    <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-700">
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          {result.details.securityHeaders.length > 0 ? (
            result.details.securityHeaders.map(h => (
              <span
                key={h}
                className="inline-block min-w-[70px] px-3 py-1 mr-2 rounded text-xs font-medium
                  bg-cyan-100 dark:bg-cyan-900 text-cyan-700 dark:text-cyan-200 border border-cyan-300 dark:border-cyan-700 text-center"
              >
                {h}
              </span>
            ))
          ) : (
            <span
              className="inline-block min-w-[110px] px-3 py-1 mr-2 rounded text-xs font-medium
                bg-gray-700 dark:bg-gray-800 text-gray-200 dark:text-gray-300 border border-gray-700 dark:border-gray-700 text-center"
            >
              None detected
            </span>
          )}
        </div>

        {result.details.headersData && (
          <button
            onClick={() => setSecurityHeadersExpanded(x => !x)}
            className="ml-3 px-3 py-1 rounded text-xs font-semibold border border-blue-700 dark:border-blue-400 text-blue-500 dark:text-blue-300 hover:bg-blue-900/20 focus:outline-none whitespace-nowrap self-center"
          >
            {securityHeadersExpanded ? "Hide Details ▼" : "Show All Details ▶"}
          </button>
        )}
      </div>
    </td>
    <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">
      Analysis of all major response headers affecting browser and data safety
    </td>
    <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-700">
      <div className={`text-lg font-bold ${
        securityScores.headers >= 80 ? 'text-green-600 dark:text-green-400' :
        securityScores.headers >= 60 ? 'text-yellow-600 dark:text-yellow-400' :
        'text-red-600 dark:text-red-400'
      }`}>
        {securityScores.headers}
      </div>
    </td>
    <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-700">
      {securityScores.weights.headers}%
    </td>
    <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">
      {lastUpdated}
    </td>
    <td className="px-4 py-4 text-center">
      <button
        onClick={() =>
          handleCopy(
            `Security Headers:\n${result.details.securityHeaders.join(", ")}\n\n` +
            (result.details.headersData && result.details.headersData.all_headers
              ? Object.entries(result.details.headersData.all_headers)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join("\n")
              : "")
          , 'securityHeaders')
        }
        className="w-12 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1 transition-colors duration-200"
        title="Copy Security Headers"
      >
        {copiedStates.securityHeaders ? (
          <span className="text-green-600 dark:text-green-400 text-xs font-medium">Copied!</span>
        ) : (
          <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
      </button>
      <button
        onClick={e => handleLearnMore('headers', e)}
        className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 mx-1 transition-colors duration-200"
        title="Learn more about Security Headers"
      >
        <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
        </svg>
      </button>
    </td>
  </tr>
  {securityHeadersExpanded && result.details.headersData && (
    <tr>
      <td colSpan="7" className="px-0 py-0 border-t border-gray-200 dark:border-gray-700">
        <SecurityHeaderDetails
          securityHeadersData={result.details.headersData}
          onHide={() => setSecurityHeadersExpanded(false)}
        />
      </td>
    </tr>
  )}


  {/* Keywords Row */}
  <tr className="hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors duration-150">
    <td className="px-4 py-4 text-sm font-medium text-gray-900 dark:text-gray-200 border-r border-gray-300 dark:border-gray-700">Keywords</td>
    <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-700">
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          {result.details.keywords && result.details.keywords.length > 0 ? (
            result.details.keywords.join(", ")
          ) : (
            <span className="italic text-gray-500 dark:text-gray-400">None detected</span>
          )}
        </div>

        <button
          onClick={() => toggleRowExpansion('keywords')}
          className="ml-3 px-2 py-1 text-xs text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 border border-blue-300 dark:border-blue-600 rounded whitespace-nowrap self-center"
        >
          {expandedRows['keywords'] ? 'Hide Details ▼' : 'Show More Details ▶'}
        </button>
      </div>
    </td>
    <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">
      Risky keywords detected in URL affecting security risk score
    </td>
    <td className="px-4 py-4 text-center border-r border-gray-300 dark:border-gray-700">
      <div className={`text-lg font-bold ${
        securityScores.keywords >= 80 ? 'text-green-600 dark:text-green-400' : 
        securityScores.keywords >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
        'text-red-600 dark:text-red-400'
      }`}>
        {securityScores.keywords}
      </div>
    </td>
    <td className="px-4 py-4 text-center text-sm font-semibold text-gray-700 dark:text-gray-300 border-r border-gray-300 dark:border-gray-700">
      {securityScores.weights.keywords}%
    </td>
    <td className="px-4 py-4 text-center text-sm text-gray-500 dark:text-gray-400 border-r border-gray-300 dark:border-gray-700">{lastUpdated}</td>
    <td className="px-4 py-4 text-center">
      <button 
        onClick={copyKeywords}
        className="w-12 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 mx-1 transition-colors duration-200"
        title="Copy Keywords"
      >
        {copiedStates.keywords ? (
          <span className="text-green-600 dark:text-green-400 text-xs font-medium">Copied!</span>
        ) : (
          <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
      </button>
    </td>
  </tr>
  {expandedRows['keywords'] && (
    <tr>
      <td colSpan={7} className="px-0 py-0 border-t border-gray-200 dark:border-gray-700">
        <KeywordDetails 
          keywordInfo={getKeywordInfo()} 
          onHide={() => toggleRowExpansion('keywords')} 
        />
      </td>
    </tr>
  )}


</tbody>


          </table>
        </div>
      </div>
    </div>
  );
}


export default ResultsTable;