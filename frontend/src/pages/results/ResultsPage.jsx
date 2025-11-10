import { useState } from "react";
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
    pie: { ...result.pie, series: securityScores.pieData },
  };

  return (
    <div className="min-h-screen bg-white dark:bg-black transition-colors duration-300">
      <NewScanModal
        isOpen={showNewScanModal}
        onClose={() => setShowNewScanModal(false)}
        onConfirm={confirmNewScan}
      />

      {/* Header */}
      <div className="border-b border-gray-300 dark:border-gray-700 bg-white dark:bg-black flex justify-between px-6 py-3">
        <button
          onClick={onNewScan}
          className="inline-flex items-center gap-2 text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200 px-3 py-1.5 rounded-lg hover:bg-blue-50 dark:hover:bg-gray-900 text-sm border border-blue-300 dark:border-blue-600 hover:border-blue-400 dark:hover:border-blue-500"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M10 19l-7-7m0 0l7-7m-7 7h18"
            />
          </svg>
          New Scan
        </button>

        <h1 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
          Enhanced Security Scan Results
        </h1>

        <button
          onClick={() => window.jsPDF && exportPdf(result, securityScores)}
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700 transition-colors duration-200 dark:bg-blue-500 dark:hover:bg-blue-600 border border-blue-700 dark:border-blue-400"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          Export PDF
        </button>
      </div>

      {/* Summary Cards */}
      <div className="w-full px-6 py-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Card 1 */}
        <div className="lg:col-span-1 bg-white dark:bg-black rounded-lg border border-gray-300 dark:border-gray-700 p-4 shadow-sm transition-colors duration-300">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
            {result.url}
          </h2>

          <div className="flex items-center space-x-4 mb-2">
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Risk Score:
            </span>
            <span
              className={`text-2xl font-bold ${
                result.riskScore >= 70
                  ? "text-red-600 dark:text-red-400"
                  : result.riskScore >= 40
                  ? "text-yellow-600 dark:text-yellow-400"
                  : "text-green-600 dark:text-green-400"
              }`}
            >
              {result.riskScore}
            </span>
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Total Score:
            </span>
            <span className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              {securityScores.overall}%
            </span>
          </div>

          <div className="flex items-center space-x-4 mb-4">
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Classification:
            </span>
            <span
              className={`text-lg font-semibold ${
                result.classification === "High Risk"
                  ? "text-red-600 dark:text-red-400"
                  : result.classification === "Medium Risk"
                  ? "text-yellow-600 dark:text-yellow-400"
                  : "text-green-600 dark:text-green-400"
              }`}
            >
              {result.classification}
            </span>
          </div>

          <div className="border-t border-gray-300 dark:border-gray-700 pt-3">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">
              Risk Analysis
            </h3>
            <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
              Overall risk score is {result.riskScore} classifying as{" "}
              {result.classification}.{" "}
              {result.details.keywords?.length > 0
                ? `Detected risky keywords: ${result.details.keywords.join(", ")}.`
                : "No suspicious keywords detected."}
            </p>
          </div>
        </div>

        {/* Card 2 */}
        <div className="lg:col-span-2 bg-white dark:bg-black rounded-lg border border-gray-300 dark:border-gray-700 p-4 shadow-sm transition-colors duration-300">
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
    doc.text("Enhanced URL Security Report", 40, 40);
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
      ["ASCII/IDN", d.idnData?.is_idn ? 'Non-ASCII (IDN)' : 'ASCII Only', securityScores.ascii >= 80 ? 'Matched' : 'Not Matched', `${securityScores.weights.ascii}%`],
      ["ML Phishing Score", d.mlPhishingScore || "", securityScores.mlPhishing, `${securityScores.weights.mlPhishing}%`],
    ];

    autoTable(doc, {
      startY: 130,
      head: [["Field", "Value", "Score", "Weight"]],
      body: rows,
      styles: { fontSize: 10, cellPadding: 6 },
      headStyles: { fillColor: [67, 56, 202] },
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
