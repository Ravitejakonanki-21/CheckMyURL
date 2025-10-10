import { useRef } from 'react';
import { CheckCircle, XCircle, AlertTriangle, Shield, Download, Info } from 'lucide-react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

function Results({ scanResult }) {
  const resultsRef = useRef();

  // Fallback if scanResult not provided
  const resultData = scanResult || {
    url: 'https://example.com',
    classification: 'Safe',
    riskScore: 15,
    details: {
      sslValid: true,
      sslExpired: false,
      sslSelfSigned: false,
      whoisAgeMonths: 36,
      securityHeaders: ['HSTS', 'CSP', 'X-Frame-Options'],
      keywords: ['login', 'secure'],
      mlPhishingScore: 12,
      portScan: [80, 443],
      actionableInsights: [
        'Website uses HTTPS and valid SSL certificate.',
        'WHOIS age indicates domain is well-established.',
        'No suspicious keywords detected.',
      ],
    },
  };

  const exportPDF = () => {
    const doc = new jsPDF();

    doc.setFontSize(18);
    doc.text('Automated URL Threat Evaluation Report', 14, 20);
    doc.setFontSize(12);
    doc.text(`URL: ${resultData.url}`, 14, 28);
    doc.text(`Classification: ${resultData.classification}`, 14, 34);
    doc.text(`Risk Score: ${resultData.riskScore}`, 14, 40);

    let startY = 50;

    // SSL & HTTPS
    autoTable(doc, {
      startY,
      head: [['SSL/HTTPS Checks', 'Status']],
      body: [
        ['SSL Valid', resultData.details.sslValid ? '✅ Pass' : '❌ Fail'],
        ['SSL Expired', resultData.details.sslExpired ? '❌ Expired' : '✅ Valid'],
        ['Self-Signed Certificate', resultData.details.sslSelfSigned ? '⚠️ Self-Signed' : '✅ Trusted'],
      ],
      theme: 'grid',
      headStyles: { fillColor: [0, 212, 255] },
      styles: { fontSize: 10 },
    });

    startY = doc.lastAutoTable.finalY + 10;

    // WHOIS
    autoTable(doc, {
      startY,
      head: [['WHOIS Info', 'Value']],
      body: [
        ['Domain Age (Months)', resultData.details.whoisAgeMonths],
      ],
      theme: 'grid',
      headStyles: { fillColor: [0, 212, 255] },
      styles: { fontSize: 10 },
    });

    startY = doc.lastAutoTable.finalY + 10;

    // Security Headers
    autoTable(doc, {
      startY,
      head: [['Security Headers Present']],
      body: resultData.details.securityHeaders.map((h) => [h]),
      theme: 'grid',
      headStyles: { fillColor: [0, 212, 255] },
      styles: { fontSize: 10 },
    });

    startY = doc.lastAutoTable.finalY + 10;

    // Phishing Score
    doc.text(`Machine Learning Phishing Score: ${resultData.details.mlPhishingScore}`, 14, startY);
    startY += 6;

    // Port Scan
    autoTable(doc, {
      startY,
      head: [['Open Ports']],
      body: resultData.details.portScan.map((p) => [p]),
      theme: 'grid',
      headStyles: { fillColor: [0, 212, 255] },
      styles: { fontSize: 10 },
    });

    startY = doc.lastAutoTable.finalY + 10;

    // Actionable Insights
    autoTable(doc, {
      startY,
      head: [['Actionable Insights']],
      body: resultData.details.actionableInsights.map((i) => [i]),
      theme: 'grid',
      headStyles: { fillColor: [0, 212, 255] },
      styles: { fontSize: 10 },
    });

    doc.save('url-threat-evaluation.pdf');
  };

  return (
    <div className="min-h-screen bg-white dark:bg-black transition-colors py-20 px-6">
      <div className="max-w-5xl mx-auto">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
          {/* Left Side - Title & Classification */}
          <div>
            <h1 className="text-5xl font-bold text-gray-900 dark:text-white mb-2 drop-shadow-md shadow-[#00d4ff]/60">
              Scan Results
            </h1>
            <p className="text-gray-700 dark:text-gray-300 text-lg drop-shadow-sm shadow-[#00d4ff]/40">
              Comprehensive evaluation of the scanned URL
            </p>
            {resultData && (
              <p className="mt-2 text-lg font-semibold text-gray-900 dark:text-white drop-shadow-sm shadow-[#00d4ff]/50">
                Classification:{' '}
                <span
                  className={
                    resultData.classification === 'Safe'
                      ? 'text-green-500 dark:text-green-400'
                      : resultData.classification === 'Suspicious'
                      ? 'text-yellow-400'
                      : 'text-red-500'
                  }
                >
                  {resultData.classification}
                </span>{' '}
                | Risk Score: {resultData.riskScore}
              </p>
            )}
          </div>

          {/* Right Side - Export PDF Button */}
          <button
            onClick={exportPDF}
            className="flex items-center gap-2 px-5 py-2 bg-blue-600 dark:bg-[#00d4ff] text-white dark:text-black rounded-lg hover:bg-blue-700 dark:hover:bg-[#00bbff] transition-colors"
          >
            <Download size={18} />
            Export PDF
          </button>
        </div>

        {/* Detailed Report */}
        <div className="space-y-6" ref={resultsRef}>
          {/* SSL Section */}
          <div className="bg-white dark:bg-gray-900 p-6 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <div className="flex items-center gap-3 mb-4">
              <Shield className="text-[#00d4ff]" size={28} />
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">SSL / HTTPS</h2>
            </div>
            <ul className="space-y-2 text-gray-700 dark:text-gray-300">
              <li>{resultData.details.sslValid ? '✅ SSL Certificate Valid' : '❌ SSL Certificate Invalid'}</li>
              <li>{!resultData.details.sslExpired ? '✅ SSL Not Expired' : '❌ SSL Expired'}</li>
              <li>{!resultData.details.sslSelfSigned ? '✅ Trusted Certificate' : '⚠️ Self-Signed Certificate'}</li>
            </ul>
          </div>

          {/* WHOIS Section */}
          <div className="bg-white dark:bg-gray-900 p-6 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <div className="flex items-center gap-3 mb-4">
              <Info className="text-[#00d4ff]" size={28} />
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">WHOIS</h2>
            </div>
            <p className="text-gray-700 dark:text-gray-300">Domain Age: {resultData.details.whoisAgeMonths} months</p>
          </div>

          {/* Security Headers Section */}
          <div className="bg-white dark:bg-gray-900 p-6 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <div className="flex items-center gap-3 mb-4">
              <Shield className="text-[#00d4ff]" size={28} />
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Security Headers</h2>
            </div>
            <ul className="space-y-2 text-gray-700 dark:text-gray-300">
              {resultData.details.securityHeaders.map((h, i) => (
                <li key={i}>✅ {h}</li>
              ))}
            </ul>
          </div>

          {/* Port Scan Section */}
          <div className="bg-white dark:bg-gray-900 p-6 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <div className="flex items-center gap-3 mb-4">
              <Shield className="text-[#00d4ff]" size={28} />
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Port Scan</h2>
            </div>
            <p className="text-gray-700 dark:text-gray-300">Open Ports: {resultData.details.portScan.join(', ')}</p>
          </div>

          {/* Phishing Detection */}
          <div className="bg-white dark:bg-gray-900 p-6 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="text-[#00d4ff]" size={28} />
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Phishing Detection</h2>
            </div>
            <p className="text-gray-700 dark:text-gray-300">
              ML-Based Score: {resultData.details.mlPhishingScore} {resultData.details.mlPhishingScore > 50 ? '⚠️ Suspicious' : '✅ Safe'}
            </p>
          </div>

          {/* Actionable Insights */}
          <div className="bg-white dark:bg-gray-900 p-6 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <div className="flex items-center gap-3 mb-4">
              <Info className="text-[#00d4ff]" size={28} />
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Actionable Insights</h2>
            </div>
            <ul className="list-disc pl-6 text-gray-700 dark:text-gray-300 space-y-2">
              {resultData.details.actionableInsights.map((i, index) => (
                <li key={index}>{i}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Results;