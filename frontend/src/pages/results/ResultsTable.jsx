import { useState } from "react";
import EnhancedSSLDetails from "./SSLDetails.jsx";
import WhoisDetails from "./WhoisDetails.jsx";
import { copyToClipboard, openLearnMore, reportFalsePositive } from "../../utils/quickActions.js";

function ResultsTable({ result, securityScores, lastUpdated, expandedRows, setExpandedRows }) {
  const toggleRowExpansion = (key) => setExpandedRows(prev => ({ ...prev, [key]: !prev[key] }));

  const copyAllResults = (btn) => {
    const d = result.details, ssl = d.sslData;
    copyToClipboard([
      `URL: ${result.url}`, `Risk Score: ${result.riskScore}%`, `Classification: ${result.classification}`,
      `SSL/TLS: ${d.sslValid?'Valid':'Invalid'} (Score: ${securityScores.ssl})`,
      ssl.tls_version?`TLS Version: ${ssl.tls_version}`:'', ssl.cipher_suite?`Cipher Suite: ${ssl.cipher_suite}`:'',
      `Domain Age: ${d.whoisAgeMonths} months (Score: ${securityScores.domainAge})`,
      `Open Ports: ${d.openPorts.join(", ")||"None"} (Score: ${securityScores.ports})`,
      `Security Headers: ${d.securityHeaders.join(", ")||"None"} (Score: ${securityScores.headers})`,
      `Keywords: ${d.keywords.join(", ")||"None"} (Score: ${securityScores.keywords})`,
      `ML Score: ${d.mlPhishingScore}% risk (Score: ${securityScores.mlPhishing})`,
      `Overall Score: ${securityScores.overall}%`
    ].filter(Boolean).join('\n'), btn);
  };

  return (
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

              {/* Add other rows as needed... */}
              
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default ResultsTable;