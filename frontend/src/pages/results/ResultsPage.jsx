import { useState } from "react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import ResultsTable from "./ResultsTable.jsx";
import InteractivePieChart from "../../components/InteractivePieChart.jsx";
import NewScanModal from "../../components/NewScanModal.jsx";
import { calculateSecurityScores, formatLastUpdated } from "../../utils/securityCalculations.js";

function ResultsPage({
  result,
  onNewScan,
  expandedRows,
  setExpandedRows,
  showNewScanModal,
  setShowNewScanModal,
  confirmNewScan,
}) {
  const securityScores = calculateSecurityScores(result);
  const lastUpdated = formatLastUpdated(result.details.scanTime);
  const updatedResult = {
    ...result,
    pie: { ...result.pie, series: securityScores.pieData, total: securityScores.overall },
  };
  const weightages = result.weightages || {};
  const mlWeightScore = Number.isFinite(weightages.ml_score)
    ? weightages.ml_score
    : (result.details?.mlData?.score ?? null);
  const checksWeightScore = Number.isFinite(weightages.checks_score)
    ? weightages.checks_score
    : (result.heuristic?.risk_score ?? securityScores.overall ?? null);
  const averageWeightScore = Number.isFinite(weightages.average_score)
    ? weightages.average_score
    : result.riskScore;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] transition-colors duration-300">
      <NewScanModal
        isOpen={showNewScanModal}
        onClose={() => setShowNewScanModal(false)}
        onConfirm={confirmNewScan}
      />

      {/* Header */}
      <div className="border-b border-gray-300 dark:border-gray-700 bg-[var(--bg-primary)] flex flex-col sm:flex-row items-center justify-between gap-4 px-4 sm:px-6 py-4 sm:py-3 transition-colors duration-300">
        <button
          onClick={onNewScan}
          className="w-full sm:w-auto inline-flex items-center justify-center gap-2 text-[#00e5ff] hover:text-[#00ccf0] transition-colors duration-200 px-4 py-2 sm:py-1.5 rounded-lg hover:bg-[#00e5ff]/10 text-sm border border-[#00e5ff]/30 sm:border-[#00e5ff]/50 hover:border-[#00e5ff]/60"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          New Scan
        </button>

        <h1 className="text-sm sm:text-lg font-black text-gray-900 dark:text-gray-100 text-center uppercase tracking-tight">
          SCAN <span className="text-[#00e5ff]">RESULTS</span>
        </h1>

        <button
          onClick={() => exportPdf(result, securityScores)}
          className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-lg bg-[#00e5ff] px-4 py-2 sm:py-1.5 text-sm text-[#0e0e0e] font-black hover:bg-[#00ccf0] transition-colors duration-200 border border-[#00e5ff] shadow-lg shadow-[#00e5ff]/20 uppercase tracking-widest text-[10px] sm:text-xs"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          Export PDF
        </button>
      </div>

      {/* Summary Cards */}
      <div className="w-full px-6 py-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Card 1 */}
        <div className="lg:col-span-1 bg-[var(--bg-secondary)] rounded-lg border border-gray-300 dark:border-gray-700 p-4 shadow-sm transition-colors duration-300">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
            {result.url}
          </h2>

          <div className="space-y-3 mb-6">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-400">Risk Score</span>
              <div className="flex items-center gap-2">
                <span className={`font-bold ${result.riskScore >= 70 ? "text-red-600 dark:text-red-400" : result.riskScore >= 40 ? "text-yellow-600 dark:text-yellow-400" : "text-green-600 dark:text-green-400"}`}>
                  {result.riskScore}
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${result.riskScore >= 70 ? "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" : result.riskScore >= 40 ? "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400" : "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"}`}>
                  ({result.classification})
                </span>
                <span className="text-xs text-gray-400 italic">← risk of being phishing</span>
              </div>
            </div>

            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-400">Security Score</span>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-green-600 dark:text-green-400">{securityScores.overall}%</span>
                <span className="text-xs text-gray-400 italic">← how many checks passed</span>
              </div>
            </div>

            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-400">Classification</span>
              <span className={`font-semibold ${result.classification === "High Risk" ? "text-red-600 dark:text-red-400" : result.classification === "Medium Risk" ? "text-yellow-600 dark:text-yellow-400" : "text-green-600 dark:text-green-400"}`}>
                {result.classification}
              </span>
            </div>

            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-400">Keywords</span>
              <span className="text-right font-medium text-gray-900 dark:text-gray-100">
                {(() => {
                  const suspiciousOnly = (result.details.keywords || []).filter(k =>
                    !["google", "microsoft", "apple", "amazon", "facebook",
                      "twitter", "linkedin", "github", "netflix", "youtube",
                      "instagram", "reddit", "wikipedia"].includes(k.toLowerCase())
                  );
                  return suspiciousOnly.length > 0
                    ? `Detected: ${suspiciousOnly.join(", ")}`
                    : "No suspicious keywords detected";
                })()}
              </span>
            </div>
          </div>

          {/* Score explanation */}
          <div className="mt-2 text-xs text-gray-500 dark:text-gray-400 space-y-1">
            <p>
              <span className="font-medium">Risk Score</span> — 
              0–39 = Low Risk, 40–69 = Medium Risk, 70+ = High Risk
            </p>
            <p>
              <span className="font-medium">Security Score</span> — 
              how many security checks passed (higher = better)
            </p>
          </div>


        </div>

        {/* Card 2 */}
        <div className="lg:col-span-2 bg-[var(--bg-secondary)] rounded-lg border border-gray-300 dark:border-gray-700 p-4 shadow-sm transition-colors duration-300">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
            Risk Composition
          </h3>
          {updatedResult.pie && <InteractivePieChart data={updatedResult.pie} />}
        </div>
      </div>

      {/* Results Table */}
      <ResultsTable
        result={result}
        securityScores={securityScores}
        lastUpdated={lastUpdated}
        expandedRows={expandedRows}
        setExpandedRows={setExpandedRows}
      />
    </div>
  );
}

// PDF Export Function
const exportPdf = (result, securityScores) => {
  try {
    if (!result) return;
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("CYBERSHIELD — Security Scan Report", 40, 40);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    const ts = new Date().toLocaleString();
    doc.text(`Generated: ${ts}`, 40, 60);
    doc.text(`URL: ${result.url || ""}`, 40, 76);
    doc.text(`Risk Score: ${result.riskScore || ""}`, 40, 92);
    doc.text(`Classification: ${result.classification || ""}`, 40, 108);

    const d = result.details || {},
      ssl = d.sslData || {};
    const rows = [
      ["SSL Valid", d.sslValid ? "Yes" : "No", securityScores.ssl, `${securityScores.weights.ssl}%`],
      ["TLS Version", ssl.tls_version || "N/A", ssl.cipher_suite ? "Secure" : "Unknown", "Protocol"],
      ["WHOIS Age (months)", d.whoisAgeMonths || "", securityScores.domainAge, `${securityScores.weights.domainAge}%`],
      ["WHOIS", d.whoisData?.domain || "N/A", securityScores.whois, `${securityScores.weights.whois}%`],
      ["Open Ports", Array.isArray(d.openPorts) ? d.openPorts.join(", ") || "None" : "None", securityScores.ports, `${securityScores.weights.ports}%`],
      ["Security Headers", Array.isArray(d.securityHeaders) ? d.securityHeaders.join(", ") || "None" : "None", securityScores.headers, `${securityScores.weights.headers}%`],
      ["Keywords", Array.isArray(d.keywords) ? d.keywords.join(", ") || "None" : "None", securityScores.keywords, `${securityScores.weights.keywords}%`],
      ["ASCII/IDN", d.idnData?.is_idn ? 'Non-ASCII (IDN)' : 'ASCII Only', securityScores.ascii, `${securityScores.weights.ascii}%`],
      ["ML Phishing Score", d.mlPhishingScore || "", securityScores.mlPhishing, `${securityScores.weights.mlPhishing}%`],
    ];

    autoTable(doc, {
      startY: 130,
      head: [["Field", "Value", "Score", "Weight"]],
      body: rows,
      styles: { fontSize: 10, cellPadding: 6 },
      headStyles: { fillColor: [0, 229, 255] },
      theme: "grid",
      margin: { left: 40, right: 40 },
    });

    const comp = ["Safe", "Suspicious", "Dangerous"]
      .map((l, i) => `${l}: ${securityScores.pieData?.[i] || ""}%`)
      .join(" |");
    const finalY = doc.lastAutoTable?.finalY || 130;
    doc.text(`Risk Composition: ${comp}`, 40, finalY + 24);
    doc.text(`Overall Security Score: ${securityScores.overall}%`, 40, finalY + 44);
    doc.save(`enhanced-url-security-report-${Date.now()}.pdf`);
  } catch (e) {
    console.error("Export error:", e);
  }
};

export default ResultsPage;
