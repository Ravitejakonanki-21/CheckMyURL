// CALCULATE INDIVIDUAL SECURITY SCORES WITHOUT TRUST SCORE
const SAFE_THRESHOLD = 70;
const WARNING_THRESHOLD = 40;

const splitRemainder = (remainder, classification, riskScore) => {
  if (remainder <= 0) return [0, 0];

  const score = Number(riskScore);
  const label = (classification || "").toLowerCase();
  const isHigh = label.includes("high") || score >= 70;
  const isMedium = label.includes("medium") || (score >= 40 && score < 70);

  if (isHigh) {
    return [0, remainder];
  }

  if (isMedium) {
    const dangerous = Math.round(remainder * 0.3);
    return [remainder - dangerous, dangerous];
  }

  return [remainder, 0];
};

const buildPieData = (scores, weights, result, overallPercentage) => {
  const safe = Math.max(0, Math.min(100, overallPercentage));
  const remainder = 100 - safe;
  const [suspicious, dangerous] = splitRemainder(remainder, result.classification, result.riskScore);

  const total = safe + suspicious + dangerous;
  if (total !== 100) {
    const diff = 100 - total;
    if (dangerous > 0) {
      return [safe, suspicious, dangerous + diff];
    }
    if (suspicious > 0) {
      return [safe, suspicious + diff, dangerous];
    }
    return [safe + diff, suspicious, dangerous];
  }

  return [safe, suspicious, dangerous];
};

export const calculateSecurityScores = (result) => {
  const scores = { ssl: 0, domainAge: 0, ports: 0, headers: 0, keywords: 0, mlPhishing: 0, ascii: 0, whois: 0 },
        weights = { ssl: 30, domainAge: 30, ports: 10, headers: 15, keywords: 5, mlPhishing: 10, ascii: 10, whois: 15 };

  const { sslValid, sslExpired, sslSelfSigned, whoisAgeMonths, openPorts, securityHeaders, keywords, mlPhishingScore, idnData, whoisData } = result.details;

  scores.ssl = sslValid && !sslExpired && !sslSelfSigned ? 100 : sslValid && !sslExpired ? 80 : sslValid ? 60 : 20;
  scores.domainAge = whoisAgeMonths > 12 ? 100 : whoisAgeMonths > 6 ? 75 : whoisAgeMonths > 3 ? 50 : 25;
  const portCount = openPorts.length; scores.ports = portCount === 0 ? 100 : portCount <= 2 ? 80 : portCount <= 5 ? 60 : 30;
  const headerCount = securityHeaders.length; scores.headers = headerCount >= 4 ? 100 : headerCount >= 3 ? 80 : headerCount >= 2 ? 60 : headerCount >= 1 ? 40 : 20;
  const keywordCount = keywords.length; scores.keywords = keywordCount === 0 ? 100 : keywordCount <= 2 ? 60 : keywordCount <= 4 ? 40 : 20;
  scores.mlPhishing = Math.max(0, 100 - mlPhishingScore);
  
  // ASCII/IDN scoring - use backend calculated score if available, otherwise fallback to heuristic
  if (idnData) {
    if (idnData.ascii_score !== undefined && idnData.ascii_score !== null) {
      // Use the backend calculated ASCII score based on all checks
      scores.ascii = idnData.ascii_score;
    } else {
      // Fallback to heuristic scoring
      if (idnData.mixed_confusable_scripts) {
        scores.ascii = 20; // High risk - mixed scripts can be used for homograph attacks
      } else if (idnData.is_idn) {
        scores.ascii = 60; // Medium risk - IDN detected but no mixed scripts
      } else {
        scores.ascii = 100; // Low risk - ASCII only
      }
    }
  } else {
    scores.ascii = 100; // Default to safe if not analyzed
  }

  // WHOIS scoring based on domain registration details
  if (whoisData) {
    let whoisScore = 100;
    
    // Domain age scoring (already calculated in domainAge, but include in whois)
    const ageDays = whoisData.age_days || 0;
    if (ageDays < 30) {
      whoisScore -= 40; // Very new domain
    } else if (ageDays < 90) {
      whoisScore -= 25; // New domain
    } else if (ageDays < 365) {
      whoisScore -= 15; // Young domain
    }
    
    // Privacy protection reduces trust
    if (whoisData.privacy_protected) {
      whoisScore -= 15;
    }
    
    // Missing registrar info
    if (!whoisData.registrar || whoisData.registrar === "Unknown") {
      whoisScore -= 20;
    }
    
    // Missing creation date
    if (!whoisData.creation_date) {
      whoisScore -= 20;
    }
    
    // Suspicious statuses
    if (whoisData.statuses && whoisData.statuses.length > 0) {
      const suspiciousStatuses = ['hold', 'pending', 'redemption', 'quarantine'];
      const hasSuspicious = whoisData.statuses.some(s => 
        suspiciousStatuses.some(ss => s.toLowerCase().includes(ss))
      );
      if (hasSuspicious) {
        whoisScore -= 25;
      }
    }
    
    // DNSSEC not enabled
    if (whoisData.dnssec === 'unsigned' || !whoisData.dnssec) {
      whoisScore -= 10;
    }
    
    scores.whois = Math.max(0, Math.min(100, whoisScore));
  } else {
    scores.whois = 50; // Default to medium if no WHOIS data
  }

  const weightedSum = Object.keys(scores).reduce((sum, k) => sum + scores[k] * weights[k], 0),
        totalWeight = Object.values(weights).reduce((sum, w) => sum + w, 0),
        overallPercentage = Math.round(weightedSum / totalWeight);

  const pieData = buildPieData(scores, weights, result, overallPercentage);

  return { ...scores, overall: overallPercentage, weights, pieData };
};

// FORMAT LAST UPDATED TIME
export const formatLastUpdated = (scanTime) => {
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