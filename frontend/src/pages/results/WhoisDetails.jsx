// src/pages/results/WhoisDetails.jsx
import { useState } from "react";
import { getAgeInMonths } from "../../services/whoisService.js";

const WhoisDetails = ({ whoisData, loading = false, securityScores, lastUpdated, onHide }) => {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(true);
  const [copiedStates, setCopiedStates] = useState({});

  // Copy function
  const handleCopy = (text, field) => {
    navigator.clipboard.writeText(text);
    setCopiedStates(prev => ({ ...prev, [field]: true }));
    setTimeout(() => {
      setCopiedStates(prev => ({ ...prev, [field]: false }));
    }, 2000);
  };

  // Loading state
  if (loading) {
    return (
      <div className="bg-slate-800 border border-gray-600 rounded-lg p-4">
        <div className="animate-pulse">
          <div className="h-5 bg-gray-700 rounded w-1/3 mb-3"></div>
          <div className="grid grid-cols-5 gap-3">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="bg-black p-3 rounded border border-gray-600">
                <div className="h-3 bg-gray-700 rounded w-2/3 mb-2"></div>
                <div className="h-4 bg-gray-700 rounded"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (!whoisData) {
    return (
      <div className="bg-slate-800 border border-gray-600 rounded-lg p-4">
        <div className="text-yellow-400 text-center text-sm">
          No WHOIS data available. The domain may not exist or WHOIS lookup failed.
        </div>
      </div>
    );
  }

  const formatDate = (dateString) => {
    if (!dateString) return "Not available";
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    } catch {
      return "Invalid date";
    }
  };

  const ageMonths = whoisData.age_days ? getAgeInMonths(whoisData.age_days) : 0;

  const getRiskColor = (classification) => {
    switch (classification?.toLowerCase()) {
      case 'high risk': return 'border-red-600';
      case 'suspicious': return 'border-yellow-600';
      case 'moderate risk': return 'border-orange-600';
      case 'low risk': return 'border-green-600';
      default: return 'border-gray-600';
    }
  };

  const getRiskDot = (classification) => {
    switch (classification?.toLowerCase()) {
      case 'high risk': return 'bg-red-500';
      case 'suspicious': return 'bg-yellow-500';
      case 'moderate risk': return 'bg-orange-500';
      case 'low risk': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  // Handle hide button click - calls parent's onHide if provided
  const handleHideDetails = () => {
    setShowTechnicalDetails(!showTechnicalDetails);
    if (onHide && showTechnicalDetails) {
      onHide(); // This will sync with Domain Age row button
    }
  };

  return (
    <div className="bg-slate-800 border border-gray-600 rounded-lg">
      {/* Header - aligned with other components */}
      <div className="p-4 pb-3">
        <h4 className="flex items-center text-lg font-semibold" style={{color: 'rgb(147 197 253)'}}>
          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          WHOIS Domain Information
        </h4>
      </div>

      <div className="px-4 pb-4">
        {/* Updated Grid Layout - 5 columns instead of 4 */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 mb-4">
          
          {/* Summary Cards Column */}
          <div className="space-y-2">
            {/* Risk Assessment */}
            <div className={`bg-black p-3 rounded border ${getRiskColor(whoisData.classification)}`}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center">
                  <div className={`w-2 h-2 rounded-full ${getRiskDot(whoisData.classification)} mr-2`}></div>
                  <div className="text-sm text-gray-300">Risk Assessment</div>
                </div>
                <button 
                  onClick={() => handleCopy(`Risk: ${whoisData.classification || 'Unknown'} (${whoisData.risk_score || 0}/100)`, 'risk')}
                  className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                  title="Copy Risk Assessment"
                >
                  {copiedStates.risk ? (
                    <span className="text-green-400 text-sm font-medium">Copied!</span>
                  ) : (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                  )}
                </button>
              </div>
              <div className="text-base font-semibold text-white">{whoisData.classification || 'Unknown'}</div>
              <div className="text-sm text-gray-400">Score: {whoisData.risk_score || 0}/100</div>
            </div>

            {/* Domain Age */}
            <div className="bg-black p-3 rounded border border-gray-600">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-blue-500 mr-2"></div>
                  <div className="text-sm text-gray-300">Domain Age</div>
                </div>
                <button 
                  onClick={() => handleCopy(`Domain Age: ${whoisData.age_days ? `${whoisData.age_days} days` : 'Unknown'} (${ageMonths} months)`, 'age')}
                  className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                  title="Copy Domain Age"
                >
                  {copiedStates.age ? (
                    <span className="text-green-400 text-sm font-medium">Copied!</span>
                  ) : (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                  )}
                </button>
              </div>
              <div className="text-base font-semibold text-white">
                {whoisData.age_days ? `${whoisData.age_days} days` : 'Unknown'}
              </div>
              <div className="text-sm text-gray-400">({ageMonths} months)</div>
            </div>

            {/* Registrar */}
            <div className="bg-black p-3 rounded border border-gray-600">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-purple-500 mr-2"></div>
                  <div className="text-sm text-gray-300">Registrar</div>
                </div>
                <button 
                  onClick={() => handleCopy(`Registrar: ${whoisData.registrar || 'Not available'}`, 'registrar')}
                  className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                  title="Copy Registrar"
                >
                  {copiedStates.registrar ? (
                    <span className="text-green-400 text-sm font-medium">Copied!</span>
                  ) : (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                  )}
                </button>
              </div>
              <div className="text-base font-semibold text-white truncate">
                {whoisData.registrar || 'Not available'}
              </div>
            </div>

            {/* Privacy Protection */}
            <div className="bg-black p-3 rounded border border-gray-600">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center">
                  <div className={`w-2 h-2 rounded-full ${whoisData.privacy_protected ? 'bg-green-500' : 'bg-red-500'} mr-2`}></div>
                  <div className="text-sm text-gray-300">Privacy Protection</div>
                </div>
                <button 
                  onClick={() => handleCopy(`Privacy Protection: ${whoisData.privacy_protected ? 'Protected' : 'Disabled'}`, 'privacy')}
                  className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                  title="Copy Privacy Status"
                >
                  {copiedStates.privacy ? (
                    <span className="text-green-400 text-sm font-medium">Copied!</span>
                  ) : (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                  )}
                </button>
              </div>
              <div className="text-base font-semibold text-white">
                {whoisData.privacy_protected ? 'Protected' : 'Disabled'}
              </div>
            </div>

            {/* Registrant Organization - NEW */}
            {whoisData.registrant_organization && (
              <div className="bg-black p-3 rounded border border-gray-600">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center">
                    <div className="w-2 h-2 rounded-full bg-cyan-500 mr-2"></div>
                    <div className="text-sm text-gray-300">Organization</div>
                  </div>
                  <button 
                    onClick={() => handleCopy(`Organization: ${whoisData.registrant_organization}`, 'organization')}
                    className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                    title="Copy Organization"
                  >
                    {copiedStates.organization ? (
                      <span className="text-green-400 text-sm font-medium">Copied!</span>
                    ) : (
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    )}
                  </button>
                </div>
                <div className="text-base font-semibold text-white truncate">
                  {whoisData.registrant_organization}
                </div>
              </div>
            )}
          </div>

          {/* Technical Details Columns - Now 4 balanced columns */}
          {showTechnicalDetails && (
            <>
              {/* Part 1 Column - Domain & Dates (5 fields) */}
              <div className="space-y-2">
                <div className="flex items-center text-base text-gray-300 mb-2">
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                  Domain & Dates
                  <span className="ml-2 text-xs bg-blue-600 text-blue-200 px-2 py-0.5 rounded">Part 1</span>
                </div>

                {/* Domain Details */}
                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9v-9m0-9v9" />
                      </svg>
                      DOMAIN
                    </div>
                    <button 
                      onClick={() => handleCopy(whoisData.domain || "Not available", 'domain')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Domain"
                    >
                      {copiedStates.domain ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white font-mono mb-1">{whoisData.domain || "Not available"}</div>
                  <div className="text-sm text-gray-400">Primary domain identifier</div>
                </div>

                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                      </svg>
                      CREATION DATE
                    </div>
                    <button 
                      onClick={() => handleCopy(formatDate(whoisData.creation_date), 'creation')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Creation Date"
                    >
                      {copiedStates.creation ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">{formatDate(whoisData.creation_date)}</div>
                  <div className="text-sm text-gray-400">When domain was first registered</div>
                </div>

                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                      UPDATED DATE
                    </div>
                    <button 
                      onClick={() => handleCopy(formatDate(whoisData.updated_date), 'updated')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Updated Date"
                    >
                      {copiedStates.updated ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">{formatDate(whoisData.updated_date)}</div>
                  <div className="text-sm text-gray-400">Last modification date</div>
                </div>

                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      EXPIRATION DATE
                    </div>
                    <button 
                      onClick={() => handleCopy(formatDate(whoisData.expiration_date), 'expiration')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Expiration Date"
                    >
                      {copiedStates.expiration ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">{formatDate(whoisData.expiration_date)}</div>
                  <div className="text-sm text-gray-400">When registration expires</div>
                </div>
              </div>

              {/* Part 2 Column - DNS & Contacts (4 fields) */}
              <div className="space-y-2">
                <div className="flex items-center text-base text-gray-300 mb-2">
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                  </svg>
                  DNS & Contacts
                  <span className="ml-2 text-xs bg-green-600 text-green-200 px-2 py-0.5 rounded">Part 2</span>
                </div>

                {/* Name Servers */}
                {whoisData.name_servers && whoisData.name_servers.length > 0 && (
                  <div className="bg-black p-3 rounded border border-gray-600">
                    <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                      <div className="flex items-center">
                        <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                        </svg>
                        NAME SERVERS
                      </div>
                      <button 
                        onClick={() => handleCopy(whoisData.name_servers.join(', '), 'nameservers')}
                        className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                        title="Copy Name Servers"
                      >
                        {copiedStates.nameservers ? (
                          <span className="text-green-400 text-sm font-medium">Copied!</span>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        )}
                      </button>
                    </div>
                    <div className="space-y-1">
                      {whoisData.name_servers.slice(0, 4).map((server, index) => (
                        <div key={index} className="text-base font-mono text-white bg-black p-2 rounded border border-gray-800">
                          {server}
                        </div>
                      ))}
                    </div>
                    <div className="text-sm text-gray-400 mt-2">
                      DNS servers handling domain resolution ({whoisData.name_servers.length} total)
                    </div>
                  </div>
                )}

                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                      </svg>
                      ADMIN EMAIL
                    </div>
                    <button 
                      onClick={() => handleCopy(whoisData.admin_email || 'Not available', 'admin')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Admin Email"
                    >
                      {copiedStates.admin ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">{whoisData.admin_email || 'Not available'}</div>
                  <div className="text-sm text-gray-400">Administrative contact email</div>
                </div>

                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                      TECH EMAIL
                    </div>
                    <button 
                      onClick={() => handleCopy(whoisData.tech_email || 'Not available', 'tech')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Tech Email"
                    >
                      {copiedStates.tech ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">{whoisData.tech_email || 'Not available'}</div>
                  <div className="text-sm text-gray-400">Technical contact email</div>
                </div>

                {/* Country */}
                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                      COUNTRY
                    </div>
                    <button 
                      onClick={() => handleCopy(whoisData.registrant_country || whoisData.country || 'Not available', 'country')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Country"
                    >
                      {copiedStates.country ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">{whoisData.registrant_country || whoisData.country || 'Not available'}</div>
                  <div className="text-sm text-gray-400">Registration country</div>
                </div>
              </div>

              {/* Part 3 Column - Registry & Security (5 fields) */}
              <div className="space-y-2">
                <div className="flex items-center text-base text-gray-300 mb-2">
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  Registry & Security
                  <span className="ml-2 text-xs bg-orange-600 text-orange-200 px-2 py-0.5 rounded">Part 3</span>
                </div>

                {/* Registry Domain ID */}
                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                      </svg>
                      REGISTRY ID
                    </div>
                    <button 
                      onClick={() => handleCopy(whoisData.registry_domain_id || 'Not available', 'registryId')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Registry Domain ID"
                    >
                      {copiedStates.registryId ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1 font-mono break-all">{whoisData.registry_domain_id || 'Not available'}</div>
                  <div className="text-sm text-gray-400">Registry domain identifier</div>
                </div>

                {/* IANA ID */}
                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                      </svg>
                      IANA ID
                    </div>
                    <button 
                      onClick={() => handleCopy(whoisData.registrar_iana_id || 'Not available', 'ianaId')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy IANA ID"
                    >
                      {copiedStates.ianaId ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">{whoisData.registrar_iana_id || 'Not available'}</div>
                  <div className="text-sm text-gray-400">Internet Assigned Numbers Authority ID</div>
                </div>

                {/* Abuse Contact Email */}
                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                      ABUSE EMAIL
                    </div>
                    <button 
                      onClick={() => handleCopy(whoisData.registrar_abuse_email || 'Not available', 'abuseEmail')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Abuse Email"
                    >
                      {copiedStates.abuseEmail ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">{whoisData.registrar_abuse_email || 'Not available'}</div>
                  <div className="text-sm text-gray-400">Registrar abuse contact email</div>
                </div>

                {/* Abuse Contact Phone */}
                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                      </svg>
                      ABUSE PHONE
                    </div>
                    <button 
                      onClick={() => handleCopy(whoisData.registrar_abuse_phone || 'Not available', 'abusePhone')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy Abuse Phone"
                    >
                      {copiedStates.abusePhone ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">{whoisData.registrar_abuse_phone || 'Not available'}</div>
                  <div className="text-sm text-gray-400">Registrar abuse contact phone</div>
                </div>

                {/* DNSSEC Status */}
                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                    <div className="flex items-center">
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                      DNSSEC
                    </div>
                    <button 
                      onClick={() => handleCopy(whoisData.dnssec || 'Not available', 'dnssec')}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                      title="Copy DNSSEC Status"
                    >
                      {copiedStates.dnssec ? (
                        <span className="text-green-400 text-sm font-medium">Copied!</span>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <div className="text-base text-white mb-1">
                    <span className={`px-2 py-1 rounded text-xs ${
                      whoisData.dnssec === 'signed' || whoisData.dnssec === 'signedDelegation' 
                        ? 'bg-green-900 text-green-300' 
                        : 'bg-orange-900 text-orange-300'
                    }`}>
                      {whoisData.dnssec || 'Not available'}
                    </span>
                  </div>
                  <div className="text-sm text-gray-400">DNS Security Extensions status</div>
                </div>
              </div>

              {/* Part 4 Column - Summary & Status (Dynamic height) */}
              <div className="space-y-2">
                <div className="flex items-center text-base text-gray-300 mb-2">
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                  Summary & Status
                  <span className="ml-2 text-xs bg-purple-600 text-purple-200 px-2 py-0.5 rounded">Part 4</span>
                </div>

                <div className="bg-black p-3 rounded border border-gray-600">
                  <div className="text-base text-white mb-2">DETAILS:</div>
                  <div className="text-base text-gray-300 mb-3">Professional WHOIS domain information</div>
                  
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">TOTAL SCORE:</span>
                      <span className={`font-bold ${
                        (100 - (whoisData.risk_score || 0)) >= 80 ? 'text-green-400' : 
                        (100 - (whoisData.risk_score || 0)) >= 60 ? 'text-yellow-400' : 'text-red-400'
                      }`}>
                        {100 - (whoisData.risk_score || 0)}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">WEIGHT:</span>
                      <span className="text-gray-300">30%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">LAST UPDATED:</span>
                      <span className="text-gray-300">{lastUpdated || '5 minutes ago'}</span>
                    </div>
                  </div>
                </div>

                {/* Domain Statuses */}
                {whoisData.statuses && whoisData.statuses.length > 0 && (
                  <div className="bg-black p-3 rounded border border-gray-600">
                    <div className="flex items-center justify-between text-sm text-gray-300 mb-2">
                      <div className="flex items-center">
                        <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                        </svg>
                        DOMAIN STATUSES
                      </div>
                      <button 
                        onClick={() => handleCopy(whoisData.statuses.join(', '), 'statuses')}
                        className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                        title="Copy Domain Statuses"
                      >
                        {copiedStates.statuses ? (
                          <span className="text-green-400 text-sm font-medium">Copied!</span>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      )}
                    </button>
                    </div>
                    <div className="space-y-1">
                      {whoisData.statuses.slice(0, 6).map((status, index) => (
                        <div key={index} className={`text-sm p-2 rounded border ${
                          status.toLowerCase().includes('hold') || status.toLowerCase().includes('pending') 
                            ? 'bg-yellow-900 text-yellow-300 border-yellow-600' 
                            : 'bg-black text-gray-300 border-gray-800'
                        }`}>
                          {status}
                        </div>
                      ))}
                    </div>
                    <div className="text-sm text-gray-400 mt-2">
                      Domain protection and status information ({whoisData.statuses.length} total)
                    </div>
                  </div>
                )}

                {/* Risk Factors */}
                {whoisData.risk_factors && whoisData.risk_factors.length > 0 && (
                  <div className="bg-black p-3 rounded border border-red-600">
                    <div className="flex items-center justify-between text-sm text-red-300 mb-2">
                      <div className="flex items-center">
                        <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        RISK FACTORS
                      </div>
                      <button 
                        onClick={() => handleCopy(whoisData.risk_factors.join(', '), 'risks')}
                        className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded hover:bg-blue-900/20"
                        title="Copy Risk Factors"
                      >
                        {copiedStates.risks ? (
                          <span className="text-green-400 text-sm font-medium">Copied!</span>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        )}
                      </button>
                    </div>
                    <div className="space-y-1">
                      {whoisData.risk_factors.map((factor, index) => (
                        <div key={index} className="flex items-start text-sm bg-red-900/20 p-2 rounded">
                          <span className="text-red-400 mr-2">⚠</span>
                          <span className="text-red-300">{factor}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Errors */}
        {whoisData.errors && whoisData.errors.length > 0 && (
          <div className="mt-4 p-3 bg-black border border-red-600 rounded">
            <div className="text-sm text-red-300 mb-2">WHOIS LOOKUP ERRORS</div>
            <div className="space-y-1">
              {whoisData.errors.map((error, index) => (
                <div key={index} className="text-red-400 text-sm flex items-start">
                  <span className="mr-1">•</span>
                  <span>{error}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer with Hide Details Button - Larger size */}
      <div className="px-4 py-3 border-t border-gray-700 flex justify-between items-center">
        <div className="text-sm text-gray-500">
          WHOIS data last updated: {lastUpdated || new Date().toLocaleString()}
        </div>
        <button 
          onClick={handleHideDetails}
          className="text-blue-400 text-base hover:text-blue-300 transition-colors flex items-center px-3 py-1.5 rounded-lg border border-blue-600 hover:bg-blue-900/20"
        >
          {showTechnicalDetails ? 'Hide Details' : 'Show Details'}
          <svg className={`w-4 h-4 ml-2 transition-transform ${showTechnicalDetails ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
      </div>
    </div>
  );
};

export default WhoisDetails;
