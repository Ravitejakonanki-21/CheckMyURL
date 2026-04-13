import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useScan } from "../context/ScanContext";
import ResultsPage from "./results/ResultsPage.jsx";

// Helper to call your backend header check API
const checkHeadersUrl = async (inputUrl) => {
  try {
    const res = await fetch('/api/check-headers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: inputUrl })
    });
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error('Security Headers API Error:', err);
    throw err;
  }
};

function Scanner() {
  const navigate = useNavigate();
  const [currentPage, setCurrentPage] = useState('input');
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [headerResult, setHeaderResult] = useState(null);
  const [error, setError] = useState(null);
  const [expandedRows, setExpandedRows] = useState({});
  const [showNewScanModal, setShowNewScanModal] = useState(false);
  const [showScanner, setShowScanner] = useState(false);

  const isAuthenticated = localStorage.getItem("isAuthenticated") === "true";
  const userRole = (localStorage.getItem("role") ?? "USER").toUpperCase();
  const isAdmin = userRole === "ADMIN";

  const { setIsShowingResults } = useScan();

  let recordScan;
  try {
    const scanContext = useScan();
    recordScan = scanContext?.recordScan;
  } catch (err) {
    console.warn('ScanContext not available:', err);
    recordScan = null;
  }

  const analyzeUrl = async (inputUrl) => {
    try {
      const token = localStorage.getItem('access_token') || localStorage.getItem('token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/analyze', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ url: inputUrl })
      });
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
      return await res.json();
    } catch (err) {
      console.error('API Error:', err);
      throw err;
    }
  };

  const transformBackendResponse = (backendData) => {
    const r = backendData.results || {}, h = r.headers || {}, ssl = r.ssl || {}, whois = r.whois || {}, rules = r.rules || {}, idn = r.idn || {}, eSSL = ssl.enhanced_data || ssl;
    let safe = 0, suspicious = 0, dangerous = 0;

    if (eSSL.https_ok && !eSSL.is_http_only && !eSSL.expired && !eSSL.self_signed) safe += 45;
    else {
      if (eSSL.is_http_only) suspicious += 35;
      else if (!eSSL.https_ok) suspicious += 25;
      if (eSSL.expired) dangerous += 30;
      if (eSSL.self_signed) suspicious += 20;
    }
    safe += eSSL.tls_version === 'TLSv1.3' ? 10 : eSSL.tls_version === 'TLSv1.2' ? 5 : eSSL.tls_version ? 0 : 0; if (eSSL.tls_version && !['TLSv1.3', 'TLSv1.2'].includes(eSSL.tls_version)) suspicious += 10;
    safe += eSSL.certificate_chain_complete ? 10 : 0; suspicious += !eSSL.certificate_chain_complete ? 15 : 0;

    const sh = h.security_headers || {};
    const normalizedHeaders = Object.entries(sh).reduce((acc, [key, value]) => {
      acc[key.toLowerCase()] = value;
      return acc;
    }, {});
    const hc = Object.values(sh).filter(Boolean).length;
    safe += hc >= 3 ? 20 : hc >= 1 ? 10 : 0; suspicious += hc < 1 ? 15 : 0;

    const whoisAgeMonths = (() => { if (!whois.creation_date) return 0; try { const d = new Date(whois.creation_date), c = new Date(); let m = (c.getFullYear() - d.getFullYear()) * 12 + c.getMonth() - d.getMonth(); if (c.getDate() < d.getDate()) m--; return Math.max(0, m); } catch (e) { return whois.age_days ? Math.round(whois.age_days / 30.44) : 0; } })();
    safe += whoisAgeMonths > 12 ? 25 : whoisAgeMonths > 3 ? 10 : 0; suspicious += whoisAgeMonths <= 3 ? 20 : 0;

    suspicious += rules.has_suspicious_words || rules.has_brand_words_in_host ? 25 : 0;
    suspicious += idn.is_idn || idn.mixed_confusable_scripts ? 15 : 0;

    const mlData = backendData.ml || null;
    const heuristicData = backendData.heuristic || {};
    const mlScore = typeof (mlData?.score) === "number" ? mlData.score : null;
    const heuristicScore = typeof (heuristicData?.risk_score) === "number" ? heuristicData.risk_score : null;
    const fallbackScores = [mlScore, heuristicScore].filter(score => typeof score === "number");
    const computedAverage = fallbackScores.length
      ? Math.round(fallbackScores.reduce((sum, score) => sum + score, 0) / fallbackScores.length)
      : (typeof backendData.risk_score === "number" ? backendData.risk_score : 0);

    const weightages = backendData.weightages || {
      ml_score: mlScore,
      checks_score: heuristicScore,
      average_score: computedAverage,
    };

    const backendRisk = typeof weightages.average_score === "number"
      ? weightages.average_score
      : (typeof backendData.risk_score === "number"
        ? backendData.risk_score
        : (mlScore ?? heuristicScore ?? 0));
    if (backendRisk >= 70) { dangerous += Math.max(40, dangerous); suspicious = Math.max(suspicious, 30); safe = Math.max(10, safe - 20); }
    else if (backendRisk >= 40) { suspicious += Math.max(25, suspicious); dangerous = Math.max(10, dangerous); safe = Math.max(20, safe - 10); }
    else {
      safe += 30;
      suspicious = Math.max(0, suspicious - 10);
      dangerous = Math.max(0, dangerous - 15);
    }

    if (rules.has_suspicious_words && rules.has_brand_words_in_host) { dangerous += 20; safe = Math.max(0, safe - 15); }
    if (idn.is_idn && idn.mixed_confusable_scripts) { dangerous += 15; suspicious += 10; }
    if (eSSL.expired && !eSSL.https_ok) { dangerous += 25; safe = Math.max(0, safe - 20); }

    safe = Math.max(0, safe); suspicious = Math.max(0, suspicious); dangerous = Math.max(0, dangerous);
    const total = Math.max(safe + suspicious + dangerous, 100);
    let nSafe = Math.round((safe / total) * 100), nSusp = Math.round((suspicious / total) * 100), nDanger = 100 - nSafe - nSusp;

    if (backendRisk >= 70 && nDanger < 50) { nDanger = Math.max(50, nDanger); let r = 100 - nDanger; nSusp = Math.round(r * 0.7); nSafe = r - nSusp; }
    else if (backendRisk >= 40 && nSusp < 40) { nSusp = Math.max(40, nSusp); let r = 100 - nSusp; nDanger = Math.round(r * 0.3); nSafe = r - nDanger; }

    const classification = backendData.label
      ? backendData.label
      : (mlData ? mlData.label : (backendRisk >= 70 ? "High Risk" : backendRisk >= 40 ? "Medium Risk" : "Low Risk"));

    const presentHeaders = [];
    if (normalizedHeaders["strict-transport-security"]) presentHeaders.push("HSTS");
    if (normalizedHeaders["content-security-policy"]) presentHeaders.push("CSP");
    if (normalizedHeaders["x-content-type-options"]) presentHeaders.push("X-Content-Type-Options");
    if (normalizedHeaders["x-frame-options"]) presentHeaders.push("X-Frame-Options");
    if (normalizedHeaders["referrer-policy"]) presentHeaders.push("Referrer-Policy");

    // Only show actual suspicious keywords — NOT brand matches
    // Brand matches (google, paypal etc.) are not phishing keywords by themselves
    const keywords = [...(rules.matched_suspicious || [])];
    const keywordInfo = r.keyword || { keywords_found: keywords, risk_score: 0, risk_factors: [], url: backendData.url };
    const mlPhishingScore = mlData ? mlData.score : 0;

    return {
      url: backendData.url,
      riskScore: backendRisk,
      classification,
      weightages,
      pie: {
        series: [nSafe, nSusp, nDanger],
        labels: ['Safe', 'Suspicious', 'Dangerous'],
        colors: ['#344F1F', '#FAB12F', '#DD0303']
      },
      details: {
        sslValid: (eSSL.https_ok && !eSSL.is_http_only) || false,
        sslExpired: eSSL.expired || false,
        sslSelfSigned: eSSL.self_signed_hint || eSSL.self_signed || false,
        sslData: { ...eSSL },
        whoisAgeMonths,
        openPorts: [],
        securityHeaders: presentHeaders,
        keywords,
        keywordInfo,
        mlPhishingScore,
        mlData,
        httpStatus: h.status || null,
        redirects: h.redirects || 0,
        httpsRedirect: h.https_redirect,
        domainAge: whois.age_days || 0,
        registrar: whois.registrar || "Unknown",
        whoisData: whois,
        headersData: h,
        idnData: idn,
        errors: {
          ssl: eSSL.errors || [],
          headers: h.errors || [],
          whois: whois.errors || [],
          idn: idn.errors || [],
          rules: rules.errors || []
        },
        scanTime: new Date().toISOString()
      }
    };
  };

  const onScan = async () => {
    if (!url.trim()) return setError('Please enter a URL to scan');
    setLoading(true); 
    setError(null);
    setResult(null);
    setHeaderResult(null);
    
    try {
      const fullScan = await analyzeUrl(url.trim());
      
      // The backend /analyze includes headers information. 
      // We extract it here to keep ResultsPage compatible.
      const headersFromScan = fullScan?.results?.headers || {};
      setHeaderResult(headersFromScan);
      
      const res = transformBackendResponse(fullScan);
      setResult(res); 
      recordScan?.(res);
      setIsShowingResults(true);
      setCurrentPage('results');
    } catch (err) {
      console.error('Scan Error:', err);
      setError(`Analysis failed: ${err.message || 'Unknown error'}. Please verify the URL and try again.`);
    } finally { 
      setLoading(false); 
    }
  };

  const onNewScan = () => setShowNewScanModal(true);
  const confirmNewScan = () => {
    setIsShowingResults(false);
    setCurrentPage('input'); setUrl(""); setResult(null); setHeaderResult(null);
    setError(null); setExpandedRows({}); setShowNewScanModal(false); setShowScanner(false);
  };

  if (currentPage === 'results' && result) {
    return (
      <ResultsPage
        result={result}
        headerResult={headerResult}
        onNewScan={onNewScan}
        expandedRows={expandedRows}
        setExpandedRows={setExpandedRows}
        showNewScanModal={showNewScanModal}
        setShowNewScanModal={setShowNewScanModal}
        confirmNewScan={confirmNewScan}
      />
    );
  }

  return (
    <div className="relative flex-1 flex flex-col items-center justify-center px-4 overflow-hidden transition-colors duration-300">
      <div className="w-full max-w-5xl flex flex-col items-center relative z-10 transition-all duration-500">
        <div className="mb-8 transform hover:scale-105 transition-transform duration-500">
          <img src="/bluecheck_mascot.png" alt="CYBERSHIELD" className="h-32 w-32 object-contain" />
        </div>

        <div className="text-center mb-12">
          <h2 className="text-[var(--text-primary)] text-2xl md:text-3xl font-black mb-3 flex items-center justify-center gap-2">
            Meet, <span className="text-[#00e5ff]">CYBERSHIELD</span>
          </h2>
          <p className="text-[var(--text-secondary)] text-lg md:text-xl font-bold tracking-tight">Detect Phishing Protect Every Click</p>
        </div>

        {!showScanner ? (
          <div className="flex flex-wrap justify-center gap-6 w-full max-w-5xl animate-in fade-in zoom-in duration-300">
            {[
              {
                id: 'guest',
                name: isAuthenticated ? "Full Scanner" : "Limited Scanner",
                desc: isAuthenticated ? "Deep Analysis ?" : "Basic Scan ?",
                icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>,
                color: "text-blue-400",
                handler: () => setShowScanner(true),
                visible: true
              },
              {
                id: 'user',
                name: "User Login",
                desc: "Member Login ?",
                icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>,
                color: "text-orange-400",
                handler: () => navigate('/login'),
                visible: !isAuthenticated
              },
              {
                id: 'admin',
                name: "Admin Access",
                desc: isAdmin ? "Admin Panel ?" : "System Entry ?",
                icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02(003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>,
                color: "text-purple-400",
                handler: () => navigate(isAdmin ? '/admin' : '/login'),
                visible: !isAuthenticated || isAdmin
              },
              {
                id: 'archive',
                name: "Scan Archive",
                desc: "Your History ?",
                icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>,
                color: "text-green-400",
                handler: () => navigate('/history'),
                visible: isAuthenticated
              },
              {
                id: 'stats',
                name: "Statistics",
                desc: "Global Intel ?",
                icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>,
                color: "text-cyan-400",
                handler: () => navigate('/statistics'),
                visible: isAuthenticated
              },
              {
                id: 'bulk',
                name: "Bulk Scanner",
                desc: "Dataset Control ?",
                icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" /></svg>,
                color: "text-red-400",
                handler: () => navigate('/bulk-scan'),
                visible: isAuthenticated
              },
              {
                id: 'soc',
                name: "SOC Dashboard",
                desc: "Phishing Reports ?",
                icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>,
                color: "text-amber-400",
                handler: () => navigate('/soc'),
                visible: isAdmin
              }
            ].filter(box => box.visible).map((box) => (
              <button key={box.id} onClick={box.handler} className="group flex flex-col items-center justify-center p-6 md:p-8 bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-[2rem] md:rounded-[2.5rem] hover:border-gray-300 dark:hover:border-[#444] hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-all duration-300 text-center w-full sm:w-[calc(50%-1.5rem)] lg:w-[calc(25%-1.5rem)] min-w-[160px] md:min-w-[240px] min-h-[140px] md:min-h-[180px] shadow-sm hover:shadow-xl dark:shadow-black/20">
                <div className={`${box.color} mb-3 md:mb-4 transition-transform duration-300 group-hover:-translate-y-2`}>{box.icon}</div>
                <div className="text-[var(--text-primary)] text-[10px] md:text-xs font-black uppercase tracking-widest mb-1 md:mb-2 opacity-60 group-hover:opacity-100">{box.name}</div>
                <div className="text-[var(--text-secondary)] text-xs md:text-sm font-bold group-hover:text-[var(--text-primary)] transition-colors">{box.desc}</div>
              </button>
            ))}
            {error && (
              <div className="w-full mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-2xl flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300">
                <div className="bg-red-500/20 p-2 rounded-full">
                  <svg className="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                </div>
                <p className="text-red-500 text-sm font-bold truncate">{error}</p>
              </div>
            )}
          </div>
        ) : (
          <div className="w-full max-w-2xl animate-in fade-in slide-in-from-bottom-8 duration-500 px-2 sm:px-0">
            <div className="relative flex flex-col md:flex-row items-stretch md:items-center bg-white dark:bg-[#181818] border border-[#00e5ff]/30 hover:border-[#00e5ff]/50 rounded-[2rem] md:rounded-full p-2 md:pl-6 transition-all shadow-2xl group ring-1 ring-[#00e5ff]/20 gap-2 md:gap-0">
              <div className="hidden md:flex items-center">
                <svg className="w-6 h-6 text-[#555] group-focus-within:text-[#00e5ff] mr-4 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
              </div>
              <input
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="Paste the suspicious URL here..."
                className="flex-1 text-base md:text-lg bg-transparent text-[var(--text-primary)] placeholder-gray-400 dark:placeholder-gray-600 outline-none py-3 px-4 md:px-0"
                onKeyPress={e => e.key === 'Enter' && onScan()}
                disabled={loading}
                autoFocus
              />
              <button
                onClick={onScan}
                disabled={loading || !url.trim()}
                className="px-6 md:px-10 py-3.5 md:py-4 bg-[#00e5ff] hover:bg-[#00ccf0] disabled:bg-[#1a3d3c] disabled:text-[#006e66] text-[#0e0e0e] font-black rounded-3xl md:rounded-full transition-all duration-300 shadow-lg hover:shadow-[#00e5ff]/30 disabled:cursor-not-allowed uppercase tracking-widest text-[10px] md:text-xs"
              >
                {loading ? 'Analyzing...' : 'Secure Scan'}
              </button>
            </div>
            <button onClick={() => setShowScanner(false)} className="mt-8 text-[#555] hover:text-[#00e5ff] text-[10px] md:text-xs font-bold uppercase tracking-widest flex items-center gap-2 transition-colors mx-auto">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" /></svg> Back to Portal
            </button>
          </div>
        )}
      </div>

    </div>
  );
}

export default Scanner;
