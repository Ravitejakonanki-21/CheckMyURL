import { useState } from "react";
import PieCard from "../components/PieCard";
import { explain } from "../utils/riskExplain";
import { useScan } from "../context/ScanContext";

// PDF deps: npm i jspdf jspdf-autotable (then restart dev server)
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

function Scanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const { recordScan } = useScan();

  // Zero-state series used before first scan (tiny epsilon so labels can render)
  const ZERO_SERIES = [0.0001, 0.0001, 0.0001];

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

  // Transform backend response to frontend format
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

    // Normalize scores to 100%
    const total = Math.max(safeScore + suspiciousScore + dangerousScore, 100);
    const normalizedSafe = Math.round((safeScore / total) * 100);
    const normalizedSuspicious = Math.round((suspiciousScore / total) * 100);
    const normalizedDangerous = 100 - normalizedSafe - normalizedSuspicious;

    // Determine classification
    let classification = "Low Risk";
    if (backendData.risk_score >= 70) classification = "High Risk";
    else if (backendData.risk_score >= 40) classification = "Medium Risk";

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
      riskScore: backendData.risk_score,
      classification: classification,
      pie: {
        series: [normalizedSafe, normalizedSuspicious, normalizedDangerous],
        labels: ["Safe", "Suspicious", "Dangerous"]
      },
      details: {
        sslValid: ssl.https_ok || false,
        sslExpired: ssl.expired || false,
        sslSelfSigned: ssl.self_signed_hint || false,
        whoisAgeMonths: whoisAgeMonths, // CORRECTED CALCULATION
        openPorts: [], // Your backend doesn't include port scan yet
        securityHeaders: presentHeaders,
        keywords: keywords,
        mlPhishingScore: mlPhishingScore,
        httpStatus: headers.status || null,
        redirects: headers.redirects || 0,
        httpsRedirect: headers.https_redirect,
        domainAge: whois.age_days || 0,
        registrar: whois.registrar || "Unknown",
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
    if (!url.trim()) return;
    
    setLoading(true);
    setError(null);
    
    try {
      // Call your Flask backend
      const backendResponse = await analyzeUrl(url.trim());
      
      // Transform backend response to frontend format
      const transformedResult = transformBackendResponse(backendResponse);
      
      setResult(transformedResult);
      recordScan(transformedResult);
    } catch (err) {
      setError(`Analysis failed: ${err.message}. Make sure your Flask backend is running on http://127.0.0.1:5000`);
      console.error('Scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  const onClear = () => {
    setUrl("");
    setResult(null);
    setError(null);
    setLoading(false);
  };

  // Fallback function for simple PDF without tables
  const createSimplePdf = (doc, result) => {
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

    let yPosition = 140;
    const d = result.details || {};
    const details = [
      `SSL Valid: ${d.sslValid ? "Yes" : "No"}`,
      `WHOIS Age: ${d.whoisAgeMonths ?? ""} months`,
      `Open Ports: ${Array.isArray(d.openPorts) ? d.openPorts.join(", ") || "None" : "None"}`,
      `Security Headers: ${Array.isArray(d.securityHeaders) ? d.securityHeaders.join(", ") || "None" : "None"}`,
      `Keywords: ${Array.isArray(d.keywords) ? d.keywords.join(", ") || "None" : "None"}`,
      `ML Phishing Score: ${d.mlPhishingScore ?? ""}`
    ];

    details.forEach(detail => {
      if (yPosition < 700) { // Prevent going off page
        doc.text(detail, 40, yPosition);
        yPosition += 20;
      }
    });

    // Add risk composition
    const comp = (result.pie?.labels || ["Safe", "Suspicious", "Dangerous"])
      .map((l, i) => `${l}: ${result.pie?.series?.[i] ?? ""}%`)
      .join(" | ");

    if (yPosition < 700) {
      doc.text(`Risk Composition: ${comp}`, 40, yPosition + 20);
    }

    const filename = `url-safety-report-${Date.now()}.pdf`;
    doc.save(filename);
    console.log("Simple PDF exported successfully:", filename);
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

      const comp = (result.pie?.labels || ["Safe", "Suspicious", "Dangerous"])
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
    <div className="min-h-[calc(100vh-4rem)] flex flex-col space-y-6">
      <div className="grid gap-6 md:grid-cols-2 flex-1">
        {/* URL input card */}
        <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-800 dark:bg-gray-900 h-full">
          <div className="mb-3 text-sm font-medium text-gray-800 dark:text-gray-200">URL Scanner</div>
          <div className="flex gap-3">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:border-gray-700 dark:bg-gray-950 dark:text-gray-100"
              onKeyPress={(e) => e.key === 'Enter' && onScan()}
            />
            <button
              onClick={onScan}
              disabled={loading || !url.trim()}
              className="rounded-md bg-indigo-600 px-4 py-2 text-sm text-white hover:bg-indigo-500 disabled:opacity-50"
            >
              {loading ? "Scanning..." : "Scan"}
            </button>
            <button
              type="button"
              onClick={onClear}
              className="rounded-md border border-gray-300 bg-white px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300 dark:hover:bg-gray-800"
              title="Clear current input and results"
            >
              Clear
            </button>
          </div>

          {/* Error display */}
          {error && (
            <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-md">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          )}

          <div className="mt-4 flex flex-wrap gap-2 text-xs">
            <span className="rounded-full bg-emerald-100 px-2 py-1 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">HTTPS/SSL</span>
            <span className="rounded-full bg-sky-100 px-2 py-1 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300">WHOIS</span>
            <span className="rounded-full bg-amber-100 px-2 py-1 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300">Security Headers</span>
            <span className="rounded-full bg-fuchsia-100 px-2 py-1 text-fuchsia-700 dark:bg-fuchsia-900/30 dark:text-fuchsia-300">Keyword Analysis</span>
            <span className="rounded-full bg-rose-100 px-2 py-1 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300">ML Phishing</span>
            <span className="rounded-full bg-slate-100 px-2 py-1 text-slate-700 dark:bg-slate-900/30 dark:text-slate-300">IDN Check</span>
          </div>
        </div>

        {/* Pie + explanation */}
        <div className="space-y-3 h-full">
          <PieCard
            title="URL Risk Assessment"
            series={result ? result.pie?.series : ZERO_SERIES}
            labels={["Safe", "Suspicious", "Dangerous"]}
            zeroMode={!result}
          />
          <div className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-700 shadow-sm dark:border-gray-800 dark:bg-gray-900 dark:text-gray-300">
            {result ? explain(result) : "Enter a URL and run scan to see analysis and risk details."}
          </div>
        </div>
      </div>

      {/* Details + Export */}
      <div className="rounded-lg border border-gray-200 bg-white shadow-sm dark:border-gray-800 dark:bg-gray-900">
        <div className="flex items-center justify-between border-b px-4 py-3 dark:border-gray-800">
          <div className="text-sm font-medium text-gray-800 dark:text-gray-200">Scan Details</div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={exportPdf}
              disabled={!result}
              className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-1.5 text-xs text-white hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export PDF
            </button>
          </div>
        </div>
        <div className="max-h-[50vh] overflow-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-800">
            <thead className="bg-gray-50 dark:bg-gray-950">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Field</th>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Value</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
              <tr><td className="px-4 py-2">URL</td><td className="px-4 py-2">{result?.url || "-"}</td></tr>
              <tr><td className="px-4 py-2">Risk Score</td><td className="px-4 py-2">{result?.riskScore ?? "-"}</td></tr>
              <tr><td className="px-4 py-2">Classification</td><td className="px-4 py-2">{result?.classification || "-"}</td></tr>
              <tr><td className="px-4 py-2">SSL Valid</td><td className="px-4 py-2">{result ? (result.details.sslValid ? "Yes" : "No") : "-"}</td></tr>
              <tr><td className="px-4 py-2">WHOIS Age (months)</td><td className="px-4 py-2">{result?.details?.whoisAgeMonths ?? "-"}</td></tr>
              <tr><td className="px-4 py-2">Open Ports</td><td className="px-4 py-2">{result ? (result.details.openPorts.join(", ") || "None") : "-"}</td></tr>
              <tr><td className="px-4 py-2">Security Headers</td><td className="px-4 py-2">{result ? (result.details.securityHeaders.join(", ") || "None") : "-"}</td></tr>
              <tr><td className="px-4 py-2">Keywords</td><td className="px-4 py-2">{result ? (result.details.keywords.join(", ") || "None") : "-"}</td></tr>
              <tr><td className="px-4 py-2">ML Phishing Score</td><td className="px-4 py-2">{result?.details?.mlPhishingScore ?? "-"}</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default Scanner;
