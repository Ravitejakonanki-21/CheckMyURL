import { useState } from "react";
import PieCard from "../components/PieCard";
import { mockScan } from "../utils/mockScan";
import { explain } from "../utils/riskExplain";
import { useScan } from "../context/ScanContext";

// PDF deps: npm i jspdf jspdf-autotable (then restart dev server)
import jsPDF from "jspdf";
import "jspdf-autotable";

function Scanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const { recordScan } = useScan();

  // Zero-state series used before first scan (tiny epsilon so labels can render)
  const ZERO_SERIES = [0.0001, 0.0001, 0.0001];

  const onScan = async () => {
    if (!url) return;
    setLoading(true);
    await new Promise((r) => setTimeout(r, 600)); // simulate async latency
    const r = mockScan(url);
    setResult(r);
    recordScan(r);
    setLoading(false);
  };

  const onClear = () => {
    setUrl("");
    setResult(null);
    setLoading(false);
  };

  const exportPdf = () => {
    try {
      if (!result) throw new Error("No scan result available");
      if (typeof jsPDF !== "function" && typeof jsPDF !== "object") throw new Error("jsPDF not loaded");
      const doc = new jsPDF({ unit: "pt", format: "a4" });
      if (typeof doc.autoTable !== "function") throw new Error('autoTable plugin not attached. `import "jspdf-autotable"` is required.');

      // Title
      doc.setFont("helvetica", "bold");
      doc.setFontSize(16);
      doc.text("URL Safety Report", 40, 40);

      // Meta
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

      doc.autoTable({
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
      doc.text(`Risk Composition: ${comp}`, 40, doc.lastAutoTable.finalY + 24);

      doc.save("url-safety-report.pdf");
    } catch (e) {
      console.error("Export error:", e);
      alert("PDF export failed. Check console for details.");
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
            />
            <button
              onClick={onScan}
              disabled={loading || !url}
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

          <div className="mt-4 flex flex-wrap gap-2 text-xs">
            <span className="rounded-full bg-emerald-100 px-2 py-1 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">HTTPS/SSL</span>
            <span className="rounded-full bg-sky-100 px-2 py-1 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300">WHOIS</span>
            <span className="rounded-full bg-amber-100 px-2 py-1 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300">Security Headers</span>
            <span className="rounded-full bg-fuchsia-100 px-2 py-1 text-fuchsia-700 dark:bg-fuchsia-900/30 dark:text-fuchsia-300">Keyword Analysis</span>
            <span className="rounded-full bg-rose-100 px-2 py-1 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300">ML Phishing</span>
            <span className="rounded-full bg-slate-100 px-2 py-1 text-slate-700 dark:bg-slate-900/30 dark:text-slate-300">Open Ports</span>
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
              className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-1.5 text-xs text-white hover:bg-indigo-500 disabled:opacity-50"
            >
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
