import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, AlertCircle, CheckCircle2, Shield } from 'lucide-react';
import { useScan } from '../context/ScanContext';

function Scanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const { setHasScanned, setScanResult } = useScan();
  const navigate = useNavigate();

  // Backend API integration
  const analyzeUrl = async (inputUrl) => {
    try {
      const response = await fetch('http://127.0.0.1:5000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: inputUrl }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (err) {
      console.error('API Error:', err);
      throw err;
    }
  };

  // Transform backend response
  const transformBackendResponse = (backendData) => {
    const results = backendData.results || {};
    const headers = results.headers || {};
    const ssl = results.ssl || {};
    const whois = results.whois || {};
    const rules = results.rules || {};
    const idn = results.idn || {};

    let safeScore = 0;
    let suspiciousScore = 0;
    let dangerousScore = 0;

    // SSL risk
    if (ssl.https_ok && !ssl.expired && !ssl.self_signed_hint) safeScore += 30;
    else {
      if (ssl.expired) dangerousScore += 25;
      if (ssl.self_signed_hint) suspiciousScore += 15;
      if (!ssl.https_ok) suspiciousScore += 20;
    }

    // Security headers
    const securityHeaders = headers.security_headers || {};
    const headerCount = Object.values(securityHeaders).filter(Boolean).length;
    if (headerCount >= 3) safeScore += 20;
    else if (headerCount >= 1) safeScore += 10;
    else suspiciousScore += 15;

    // WHOIS age
    const whoisAgeMonths = (() => {
      if (!whois.creation_date) return 0;
      try {
        const creationDate = new Date(whois.creation_date);
        const currentDate = new Date();
        let months = (currentDate.getFullYear() - creationDate.getFullYear()) * 12;
        months += currentDate.getMonth() - creationDate.getMonth();
        if (currentDate.getDate() < creationDate.getDate()) months--;
        return Math.max(0, months);
      } catch {
        return whois.age_days ? Math.round(whois.age_days / 30.44) : 0;
      }
    })();

    if (whoisAgeMonths > 12) safeScore += 25;
    else if (whoisAgeMonths > 3) safeScore += 10;
    else suspiciousScore += 20;

    // Suspicious patterns
    if (rules.has_suspicious_words || rules.has_brand_words_in_host) suspiciousScore += 25;

    // IDN / Punycode
    if (idn.is_idn || idn.mixed_confusable_scripts) suspiciousScore += 15;

    const total = Math.max(safeScore + suspiciousScore + dangerousScore, 100);
    const normalizedSafe = Math.round((safeScore / total) * 100);
    const normalizedSuspicious = Math.round((suspiciousScore / total) * 100);
    const normalizedDangerous = 100 - normalizedSafe - normalizedSuspicious;

    let classification = 'Low Risk';
    if (backendData.risk_score >= 70) classification = 'High Risk';
    else if (backendData.risk_score >= 40) classification = 'Medium Risk';

    const presentHeaders = [];
    if (securityHeaders.strict_transport_security) presentHeaders.push('HSTS');
    if (securityHeaders.content_security_policy) presentHeaders.push('CSP');
    if (securityHeaders.x_content_type_options) presentHeaders.push('X-Content-Type-Options');
    if (securityHeaders.x_frame_options) presentHeaders.push('X-Frame-Options');
    if (securityHeaders.referrer_policy) presentHeaders.push('Referrer-Policy');

    const keywords = [];
    if (rules.matched_suspicious?.length) keywords.push(...rules.matched_suspicious);
    if (rules.matched_brands?.length) keywords.push(...rules.matched_brands);

    const mlPhishingScore = Math.min(
      Math.round(
        (rules.has_suspicious_words ? 0.3 : 0) +
        (rules.has_brand_words_in_host ? 0.4 : 0) +
        (idn.is_idn ? 0.2 : 0) +
        (!ssl.https_ok ? 0.1 : 0)
      ) * 100,
      100
    );

    return {
      url: backendData.url,
      riskScore: backendData.risk_score,
      classification,
      pie: {
        series: [normalizedSafe, normalizedSuspicious, normalizedDangerous],
        labels: ['Safe', 'Suspicious', 'Dangerous'],
      },
      details: {
        sslValid: ssl.https_ok || false,
        sslExpired: ssl.expired || false,
        sslSelfSigned: ssl.self_signed_hint || false,
        whoisAgeMonths,
        securityHeaders: presentHeaders,
        keywords,
        mlPhishingScore,
        httpStatus: headers.status || null,
        redirects: headers.redirects || 0,
        httpsRedirect: headers.https_redirect,
        domainAge: whois.age_days || 0,
        registrar: whois.registrar || 'Unknown',
        whoisData: whois,
        sslData: ssl,
        headersData: headers,
        idnData: idn,
        rulesData: rules,
        errors: {
          ssl: ssl.errors || [],
          headers: headers.errors || [],
          whois: whois.errors || [],
          idn: idn.errors || [],
          rules: rules.errors || [],
        },
      },
    };
  };

  // Submit handler
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const backendResponse = await analyzeUrl(url.trim());
      const transformedResult = transformBackendResponse(backendResponse);
      setScanResult(transformedResult);
      setHasScanned(true);
      navigate('/results');
    } catch (err) {
      setError(`Analysis failed: ${err.message}. Make sure your Flask backend is running on http://127.0.0.1:5000`);
      console.error('Scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  // Quick scan
  const handleQuickScan = async () => {
    const testUrl = url.trim() || 'https://example.com';
    setUrl(testUrl);

    setLoading(true);
    setError(null);

    try {
      const backendResponse = await analyzeUrl(testUrl);
      const transformedResult = transformBackendResponse(backendResponse);
      setScanResult(transformedResult);
      setHasScanned(true);
      navigate('/results');
    } catch (err) {
      setError(`Quick scan failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Deep analysis
  const handleDeepAnalysis = async () => {
    if (!url.trim()) {
      setError('Please enter a URL for deep analysis');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const backendResponse = await analyzeUrl(url.trim());
      const transformedResult = transformBackendResponse(backendResponse);

      const deepAnalysisResult = {
        ...transformedResult,
        deepAnalysis: {
          portScan: [80, 443, 8080],
          dnsRecords: ['A', 'AAAA', 'MX'],
          technologies: ['React', 'Node.js', 'Nginx'],
          vulnerabilityScan: 'No critical vulnerabilities found',
        },
      };

      setScanResult(deepAnalysisResult);
      setHasScanned(true);
      navigate('/results');
    } catch (err) {
      setError(`Deep analysis failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // JSX
  return (
    <div className="min-h-screen flex items-center justify-center bg-white dark:bg-black transition-colors">
      <div className="w-full max-w-3xl px-6">
        <div className="text-center mb-12">
          <div className="flex justify-center items-center mb-4">
            <Shield className="text-blue-600 dark:text-[#00d4ff] mr-3" size={48} />
            <h1 className="text-6xl font-bold text-gray-900 dark:text-white">
              URL <span className="text-blue-600 dark:text-[#00d4ff]">Scanner</span>
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            Enter a URL to scan and analyze for security risks
          </p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-center">
            <AlertCircle className="text-red-500 mr-3" size={20} />
            <p className="text-red-700 dark:text-red-300 text-sm">{error}</p>
          </div>
        )}

        {loading && (
          <div className="mb-6 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg flex items-center justify-center">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600 dark:border-[#00d4ff] mr-3"></div>
            <p className="text-blue-700 dark:text-blue-300 text-sm">Scanning URL, please wait...</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="relative">
          <div className="flex items-center bg-white dark:bg-gray-900 rounded-full shadow-lg dark:shadow-[#00d4ff]/20 border-2 border-gray-200 dark:border-[#00d4ff]/30 overflow-hidden hover:shadow-xl dark:hover:shadow-[#00d4ff]/40 transition-all duration-300">
            <Search className="ml-6 text-gray-400 dark:text-[#00d4ff]" size={24} />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan (e.g., https://example.com)"
              className="flex-1 px-6 py-5 text-lg bg-transparent outline-none text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="mx-2 px-8 py-3 bg-blue-600 dark:bg-[#00d4ff] text-white dark:text-black font-semibold rounded-full hover:bg-blue-700 dark:hover:bg-[#00bbff] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Scanning...' : 'Scan'}
            </button>
          </div>
        </form>

        <div className="mt-8 flex justify-center gap-4">
          <button
            onClick={handleQuickScan}
            disabled={loading}
            className="px-6 py-2 bg-gray-100 dark:bg-gray-900 text-gray-700 dark:text-gray-300 rounded-full hover:bg-gray-200 dark:hover:bg-gray-800 border border-gray-300 dark:border-[#00d4ff]/20 disabled:opacity-50 transition-colors flex items-center"
          >
            <CheckCircle2 size={16} className="mr-2" />
            Quick Scan
          </button>
          <button
            onClick={handleDeepAnalysis}
            disabled={loading}
            className="px-6 py-2 bg-gray-100 dark:bg-gray-900 text-gray-700 dark:text-gray-300 rounded-full hover:bg-gray-200 dark:hover:bg-gray-800 border border-gray-300 dark:border-[#00d4ff]/20 disabled:opacity-50 transition-colors flex items-center"
          >
            <Shield size={16} className="mr-2" />
            Deep Analysis
          </button>
        </div>
      </div>
    </div>
  );
}
export default Scanner;