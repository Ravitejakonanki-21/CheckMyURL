import { useState } from "react";
import PEMModal from "../../components/PEMModal.jsx";

const TechnicalSSLDetailsColumn2 = ({ sslData }) => {
  const [showPEMModal, setShowPEMModal] = useState(false);

  const technicalData2 = [
    {
      name: "Signature Algorithm",
      value: sslData?.signature_algorithm || "Not available",
      description: "Algorithm used to sign the certificate",
      icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
    },
    {
      name: "Certificate Chain Length",
      value: sslData?.chain_length || "Not available",
      description: "Number of certificates in the trust chain",
      icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
    },
    { name: "Key Curve", value: sslData?.key_curve || "Not available", description: "Elliptic curve name (for EC keys)", icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z"/></svg> },
    { name: "Cipher Suite", value: sslData?.cipher_suite || "Not available", description: "Encryption algorithm suite being used", icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4.871 4A17.926 17.926 0 003 12c0 2.874.673 5.59 1.871 8m14.13 0a17.926 17.926 0 001.87-8c0-2.874-.673-5.59-1.87-8M9 9h1.246a1 1 0 01.961.725l1.586 5.55a1 1 0 00.961.725H15"/></svg> },
    { name: "Wildcard Certificate", value: sslData?.wildcard_cert ? "Yes" : "No", description: "Whether this is a wildcard certificate", icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"/></svg> },
    { name: "Certificate Version", value: sslData?.version ? `v${sslData.version}` : "Not available", description: "X.509 certificate version", icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 4V2a1 1 0 011-1h8a1 1 0 011 1v2m-9 0h10m-10 0a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V6a2 2 0 00-2-2M8 9h8M8 13h8"/></svg> },
    { name: "Extensions Present", value: sslData?.extensions_count || "Not available", description: "Number of certificate extensions", icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg> },
    { name: "Certificate Fingerprint", value: sslData?.fingerprint_sha256 ? `${sslData.fingerprint_sha256.substring(0, 16)}...` : "Not available", description: "SHA-256 fingerprint of the certificate", icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4"/></svg> }
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-3">
        <h5 className="font-medium text-sm text-gray-900 dark:text-gray-100 flex items-center border-b border-blue-300 dark:border-blue-500/30 pb-2 w-full">
          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
          Advanced Technical Details
          <span className="ml-2 text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded">Part 2</span>
        </h5>
      </div>

      <div className="space-y-2">{technicalData2.map((item, i) => (
        <div key={i} className="bg-gray-50 dark:bg-gray-800 rounded border border-gray-300 dark:border-gray-600 p-3">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center mb-1"><div className="text-gray-600 dark:text-gray-400 mr-2">{item.icon}</div><div className="font-medium text-xs text-gray-900 dark:text-gray-100 uppercase tracking-wide">{item.name}</div></div>
              <div className="text-sm text-gray-700 dark:text-gray-300 font-mono break-all">{item.value}</div>
              <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">{item.description}</div>
            </div>
            <button onClick={() => navigator.clipboard?.writeText(String(item.value))} className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 ml-2 text-xs" title="Copy Value">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
            </button>
          </div>
        </div>
      ))}</div>

      {sslData?.certificate_pem && (
        <div className="mt-4 border-t border-gray-300 dark:border-gray-600 pt-4">
          <div className="flex items-center justify-between mb-2">
            <h6 className="font-medium text-xs text-gray-900 dark:text-gray-100 uppercase tracking-wide flex items-center">
              <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
              Raw Certificate Data (PEM)
            </h6>
            <button onClick={() => setShowPEMModal(true)} className="text-xs text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200 px-2 py-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900 border border-blue-300 dark:border-blue-600">
              Show PEM
              <svg className="w-3 h-3 inline ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            </button>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 rounded p-2 border border-gray-300 dark:border-gray-600">
            Certificate data available in PEM format. Click "Show PEM" to view in modal.
          </div>
          <PEMModal isOpen={showPEMModal} onClose={() => setShowPEMModal(false)} pemData={sslData.certificate_pem} />
        </div>
      )}
    </div>
  );
};

export default TechnicalSSLDetailsColumn2;