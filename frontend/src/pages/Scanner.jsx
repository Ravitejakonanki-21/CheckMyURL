import { useState } from "react";
import { useScan } from "../context/ScanContext";
import ResultsPage from "./results/ResultsPage.jsx";

// Helper to call your backend header check API
const checkHeadersUrl = async (inputUrl) => {
  try {
    const res = await fetch('http://127.0.0.1:5001/api/check-headers', {
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
  const [currentPage, setCurrentPage] = useState('input');
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [headerResult, setHeaderResult] = useState(null);
  const [error, setError] = useState(null);
  const [expandedRows, setExpandedRows] = useState({});
  const [showNewScanModal, setShowNewScanModal] = useState(false);

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
      const res = await fetch('http://127.0.0.1:5001/analyze', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }, 
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
    let safe=0, suspicious=0, dangerous=0;

    if(eSSL.https_ok && !eSSL.expired && !eSSL.self_signed) safe+=45;
    else { if(eSSL.expired)dangerous+=30; if(eSSL.self_signed)suspicious+=20; if(!eSSL.https_ok)suspicious+=25; }
    safe += eSSL.tls_version==='TLSv1.3'?10:eSSL.tls_version==='TLSv1.2'?5: eSSL.tls_version?0:0; if(eSSL.tls_version && !['TLSv1.3','TLSv1.2'].includes(eSSL.tls_version)) suspicious+=10;
    safe += eSSL.certificate_chain_complete?10:0; suspicious += !eSSL.certificate_chain_complete?15:0;

    const sh = h.security_headers || {}, hc = Object.values(sh).filter(Boolean).length;
    safe += hc>=3?20:hc>=1?10:0; suspicious += hc<1?15:0;

    const whoisAgeMonths = (()=>{if(!whois.creation_date)return 0; try{const d=new Date(whois.creation_date),c=new Date(); let m=(c.getFullYear()-d.getFullYear())*12+c.getMonth()-d.getMonth(); if(c.getDate()<d.getDate())m--; return Math.max(0,m);}catch(e){return whois.age_days?Math.round(whois.age_days/30.44):0;}})();
    safe += whoisAgeMonths>12?25:whoisAgeMonths>3?10:0; suspicious += whoisAgeMonths<=3?20:0;

    suspicious += rules.has_suspicious_words||rules.has_brand_words_in_host?25:0;
    suspicious += idn.is_idn||idn.mixed_confusable_scripts?15:0;

    // Get ML data from backend response
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
    if(backendRisk>=70){dangerous+=Math.max(40,dangerous); suspicious=Math.max(suspicious,30); safe=Math.max(10,safe-20);}
    else if(backendRisk>=40){suspicious+=Math.max(25,suspicious); dangerous=Math.max(10,dangerous); safe=Math.max(20,safe-10);}
    else{safe+=Math.max(20,safe); suspicious=Math.max(5,suspicious); dangerous=Math.max(0,dangerous-10);}

    if(rules.has_suspicious_words && rules.has_brand_words_in_host){dangerous+=20; safe=Math.max(0,safe-15);}
    if(idn.is_idn && idn.mixed_confusable_scripts){dangerous+=15; suspicious+=10;}
    if(eSSL.expired && !eSSL.https_ok){dangerous+=25; safe=Math.max(0,safe-20);}

    safe=Math.max(0,safe); suspicious=Math.max(0,suspicious); dangerous=Math.max(0,dangerous);
    const total=Math.max(safe+suspicious+dangerous,100);
    let nSafe=Math.round((safe/total)*100), nSusp=Math.round((suspicious/total)*100), nDanger=100-nSafe-nSusp;

    if(backendRisk>=70 && nDanger<50){nDanger=Math.max(50,nDanger); let r=100-nDanger; nSusp=Math.round(r*0.7); nSafe=r-nSusp;}
    else if(backendRisk>=40 && nSusp<40){nSusp=Math.max(40,nSusp); let r=100-nSusp; nDanger=Math.round(r*0.3); nSafe=r-nDanger;}

    const fTotal=nSafe+nSusp+nDanger; if(fTotal!==100){const d=100-fTotal; if(nDanger>=nSusp && nDanger>=nSafe) nDanger+=d; else if(nSusp>=nSafe) nSusp+=d; else nSafe+=d;}

    // Use ML label if available, otherwise derive from risk score
    const classification = backendData.label
      ? backendData.label
      : (mlData ? mlData.label : (backendRisk>=70?"High Risk":backendRisk>=40?"Medium Risk":"Low Risk"));

    const presentHeaders=[];
    if(sh.strict_transport_security)presentHeaders.push("HSTS");
    if(sh.content_security_policy)presentHeaders.push("CSP");
    if(sh.x_content_type_options)presentHeaders.push("X-Content-Type-Options");
    if(sh.x_frame_options)presentHeaders.push("X-Frame-Options");
    if(sh.referrer_policy)presentHeaders.push("Referrer-Policy");

    const keywords=[...(rules.matched_suspicious||[]),...(rules.matched_brands||[])];
    const keywordInfo = r.keyword || { keywords_found: keywords, risk_score: 0, risk_factors: [], url: backendData.url };

    // Use actual ML score from backend, fallback to calculated if not available
    const mlPhishingScore = mlData ? mlData.score : Math.min(Math.round(((rules.has_suspicious_words?0.3:0)+(rules.has_brand_words_in_host?0.4:0)+(idn.is_idn?0.2:0)+(!eSSL.https_ok?0.1:0))*100),100);

    return {
      url:backendData.url,
      riskScore:backendRisk,
      classification,
      weightages,
      pie:{
        series:[nSafe,nSusp,nDanger],
        labels:['Safe','Suspicious','Dangerous'],
        colors:['#344F1F','#FAB12F','#DD0303']
      },
      details:{
        sslValid:eSSL.https_ok||false,
        sslExpired:eSSL.expired||false,
        sslSelfSigned:eSSL.self_signed_hint||eSSL.self_signed||false,
        sslData:{
          ...eSSL,
          certificate_valid:eSSL.certificate_valid,
          hostname_match:eSSL.hostname_match,
          serial_number:eSSL.serial_number,
          issuer_org:eSSL.issuer_org,
          subject_org:eSSL.subject_org,
          key_algorithm:eSSL.key_algorithm,
          key_size:eSSL.key_size,
          signature_algorithm:eSSL.signature_algorithm,
          san_domains:eSSL.san_domains||[],
          wildcard_cert:eSSL.wildcard_cert,
          chain_length:eSSL.chain_length,
          full_chain:eSSL.full_chain||[]
        },
        whoisAgeMonths,
        openPorts:[],
        securityHeaders:presentHeaders,
        keywords,
        keywordInfo,
        mlPhishingScore,
        mlData,
        httpStatus:h.status||null,
        redirects:h.redirects||0,
        httpsRedirect:h.https_redirect,
        domainAge:whois.age_days||0,
        registrar:whois.registrar||"Unknown",
        whoisData:whois,
        headersData:h,
        idnData:idn,
        weightages,
        errors:{
          ssl:eSSL.errors||[],
          headers:h.errors||[],
          whois:whois.errors||[],
          idn:idn.errors||[],
          rules:rules.errors||[]
        },
        scanTime:new Date().toISOString()
      }
    };
  };

  const onScan = async () => {
    if(!url.trim()) return setError('Please enter a URL to scan');
    setLoading(true); setError(null);
    try {
      const [fullScan, headerScan] = await Promise.all([
        analyzeUrl(url.trim()),
        checkHeadersUrl(url.trim())
      ]);
      if (fullScan && fullScan.results && fullScan.results.headers) {
        fullScan.results.headers.headers_check_api = headerScan;
      }
      setHeaderResult(headerScan);
      const res = transformBackendResponse(fullScan);
      console.log('Transformed result:', { riskScore: res.riskScore, classification: res.classification, mlData: res.details.mlData });
      setResult(res); recordScan?.(res); setCurrentPage('results');
    } catch(err) {
      setError(`Analysis failed: ${err.message}. Make sure your Flask backend is running on http://127.0.0.1:5001`);
      console.error('Scan error:',err);
    } finally { setLoading(false); }
  };

  const onNewScan = () => setShowNewScanModal(true);

  const confirmNewScan = () => {
    setCurrentPage('input');
    setUrl("");
    setResult(null);
    setHeaderResult(null);
    setError(null);
    setExpandedRows({});
    setShowNewScanModal(false);
  };

  const onClear = () => {
    setUrl("");
    setError(null);
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
    <div className="min-h-screen bg-white dark:bg-black flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-2xl text-center mb-12">
        <h1 className="text-6xl md:text-5xl font-bold mb-5">
          <span className="text-gray-900 dark:text-white">URL </span>
          <span className="text-cyan-500 dark:text-cyan-400">Scanner</span>
        </h1>
        <p className="text-gray-600 dark:text-gray-400 text-lg">Enter a URL to scan and analyze</p>
      </div>

      <div className="relative mb-10 flex items-center bg-gradient-to-r from-cyan-500/10 to-blue-500/10 dark:from-cyan-500/10 dark:to-blue-500/10 border border-cyan-500/40 dark:border-cyan-500/30 rounded-full px-20 py-5 backdrop-blur-sm">
        <svg className="w-6 h-6 text-cyan-500 dark:text-cyan-400 mr-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input 
          value={url} 
          onChange={e=>setUrl(e.target.value)} 
          placeholder="Enter URL to scan..." 
          className="flex-1 text-lg bg-transparent text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-500 outline-none"
          onKeyPress={e=>e.key==='Enter'&&onScan()} 
          disabled={loading} 
          autoFocus 
        />
        <button 
          onClick={onScan} 
          disabled={loading||!url.trim()} 
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
          ) : 'Scan'}
        </button>
      </div>

      <div className="flex items-center justify-center gap-10 mb-20">
        {['Quick Scan','Deep Analysis'].map((label,i)=>
          <button 
            key={i} 
            onClick={onScan} 
            disabled={loading||!url.trim()} 
            className="px-8 py-3 bg-gray-200 hover:bg-gray-300 dark:bg-black disabled:bg-gray-200 dark:disabled:bg-gray-900 disabled:opacity-50 text-gray-700 dark:text-gray-300 rounded-lg transition-all duration-200 border border-gray-400 dark:border-gray-700 disabled:cursor-not-allowed"
          >
            {label}
          </button>
        )}
      </div>

      <div className="max-w-4xl mx-auto px-4 mb-12 flex flex-wrap justify-center gap-6">
        {[{name:"SSL/TLS Check",icon:<svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>},
          {name:"WHOIS Lookup",icon:<svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>},
          {name:"ML Analysis",icon:<svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" /></svg>},
          {name:"Keyword Detection",icon:<svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>}].map((f,i)=>
          <div key={i} className="text-center px-4 py-2">
            <div className="text-gray-600 dark:text-gray-400 mb-1 flex justify-center">{f.icon}</div>
            <div className="text-sm font-medium text-gray-700 dark:text-blue-300">{f.name}</div>
          </div>
        )}
      </div>

      {error && (
        <div className="mt-6 p-4 bg-red-100 dark:bg-red-500/10 border border-red-400 dark:border-red-500/30 rounded-lg backdrop-blur-sm">
          <div className="flex items-start justify-between">
            <p className="text-red-600 dark:text-red-400 text-sm flex-1">{error}</p>
            <button onClick={()=>setError(null)} className="ml-4 text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default Scanner;
