// src/services/whoisService.js

// Use ONLY Vite's environment variables - NO process.env
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

/**
 * Performs WHOIS lookup for a given URL
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} WHOIS data including domain info and risk assessment
 */
export const checkWhois = async (url) => {
  try {
    // Validate input
    if (!url || typeof url !== 'string') {
      throw new Error('Invalid URL provided');
    }

    // Clean the URL - extract domain if full URL is provided
    let domain = url;
    try {
      if (url.includes('://')) {
        domain = new URL(url).hostname;
      }
      // Remove www. prefix if present
      domain = domain.replace(/^www\./, '');
    } catch (e) {
      console.warn('URL parsing failed, using original input:', url);
    }

    console.log(`Fetching WHOIS data for: ${domain}`);
    
    const response = await fetch(`${API_BASE_URL}/whois_check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: domain }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.errors?.[0] || `HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    
    // Enhanced data mapping with new fields
    return {
      // Core domain information
      domain: data.domain || domain,
      creation_date: data.creation_date,
      updated_date: data.updated_date,
      expiration_date: data.expiration_date,
      age_days: data.age_days,
      
      // Registrar information
      registrar: data.registrar,
      registrar_iana_id: data.registrar_iana_id,
      registrar_abuse_email: data.registrar_abuse_email,
      registrar_abuse_phone: data.registrar_abuse_phone,
      
      // Registry information
      registry_domain_id: data.registry_domain_id,
      
      // Registrant information
      registrant_organization: data.registrant_organization,
      registrant_country: data.registrant_country,
      
      // Contact information
      admin_email: data.admin_email,
      tech_email: data.tech_email,
      country: data.country || data.registrant_country, // Fallback to registrant_country
      
      // DNS information
      name_servers: data.name_servers || [],
      dnssec: data.dnssec,
      
      // Domain status and protection
      statuses: data.statuses || [],
      privacy_protected: data.privacy_protected || false,
      
      // Risk assessment
      risk_score: data.risk_score || 0,
      risk_factors: data.risk_factors || [],
      classification: data.classification,
      
      // Errors and metadata
      errors: data.errors || []
    };
    
  } catch (error) {
    console.error('WHOIS check failed:', error);
    throw new Error(`WHOIS lookup failed: ${error.message}`);
  }
};

/**
 * Convert age in days to months for display
 * @param {number} ageDays - Age in days
 * @returns {number} Age in months (rounded)
 */
export const getAgeInMonths = (ageDays) => {
  if (!ageDays || typeof ageDays !== 'number' || ageDays < 0) {
    return 0;
  }
  return Math.round(ageDays / 30);
};

/**
 * Get risk classification based on domain age and other factors
 * @param {Object} whoisData - WHOIS data object
 * @returns {Object} Classification and risk score
 */
export const analyzeRisk = (whoisData) => {
  if (!whoisData) {
    return { classification: 'Unknown', risk_score: 0 };
  }

  let riskScore = 0;
  const riskFactors = [];

  // Domain age analysis
  if (whoisData.age_days < 30) {
    riskScore += 40;
    riskFactors.push('Very new domain (less than 30 days)');
  } else if (whoisData.age_days < 365) {
    riskScore += 20;
    riskFactors.push('Relatively new domain (less than 1 year)');
  }

  // Privacy protection
  if (whoisData.privacy_protected) {
    riskScore += 15;
    riskFactors.push('WHOIS privacy protection enabled');
  }

  // Suspicious registrar
  const suspiciousRegistrars = ['unknown', 'privacy service', 'proxy'];
  if (whoisData.registrar && suspiciousRegistrars.some(term => 
    whoisData.registrar.toLowerCase().includes(term))) {
    riskScore += 25;
    riskFactors.push('Suspicious registrar detected');
  }

  // DNSSEC not signed (security concern)
  if (whoisData.dnssec === 'unsigned' || !whoisData.dnssec) {
    riskScore += 10;
    riskFactors.push('DNSSEC not enabled (potential security risk)');
  }

  // No registrant organization (anonymous registration)
  if (!whoisData.registrant_organization || whoisData.registrant_organization.toLowerCase().includes('privacy')) {
    riskScore += 15;
    riskFactors.push('Anonymous or privacy-protected registration');
  }

  // Expired or expiring soon
  if (whoisData.expiration_date) {
    const expDate = new Date(whoisData.expiration_date);
    const today = new Date();
    const daysUntilExpiry = Math.ceil((expDate - today) / (1000 * 60 * 60 * 24));
    
    if (daysUntilExpiry < 30) {
      riskScore += 30;
      riskFactors.push('Domain expiring soon');
    } else if (daysUntilExpiry < 0) {
      riskScore += 50;
      riskFactors.push('Domain has expired');
    }
  }

  // Domain status checks
  if (whoisData.statuses && whoisData.statuses.length > 0) {
    const suspiciousStatuses = ['hold', 'pending', 'redemption', 'quarantine'];
    const hasSuspiciousStatus = whoisData.statuses.some(status => 
      suspiciousStatuses.some(suspicious => status.toLowerCase().includes(suspicious))
    );
    
    if (hasSuspiciousStatus) {
      riskScore += 25;
      riskFactors.push('Domain has suspicious status flags');
    }
  }

  // Determine classification
  let classification = 'Low Risk';
  if (riskScore >= 70) classification = 'High Risk';
  else if (riskScore >= 40) classification = 'Suspicious';
  else if (riskScore >= 20) classification = 'Moderate Risk';

  return {
    classification,
    risk_score: Math.min(riskScore, 100),
    risk_factors: riskFactors
  };
};

/**
 * Format WHOIS date for display
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date
 */
export const formatWhoisDate = (dateString) => {
  if (!dateString) return 'Not available';
  
  try {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch (error) {
    console.warn('Date formatting failed:', error);
    return 'Invalid date';
  }
};

/**
 * Validate WHOIS data completeness
 * @param {Object} whoisData - WHOIS data object
 * @returns {Object} Validation results
 */
export const validateWhoisData = (whoisData) => {
  if (!whoisData) {
    return { isValid: false, missingFields: ['All data missing'] };
  }

  const requiredFields = ['domain', 'creation_date', 'registrar'];
  const missingFields = requiredFields.filter(field => !whoisData[field]);

  const recommendedFields = ['updated_date', 'expiration_date', 'name_servers', 'registrant_organization'];
  const missingRecommended = recommendedFields.filter(field => !whoisData[field]);

  return {
    isValid: missingFields.length === 0,
    missingFields,
    missingRecommended,
    completeness: Math.round(((requiredFields.length + recommendedFields.length - missingFields.length - missingRecommended.length) / (requiredFields.length + recommendedFields.length)) * 100)
  };
};
