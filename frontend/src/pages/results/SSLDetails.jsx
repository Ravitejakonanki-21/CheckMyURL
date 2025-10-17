import { useState } from "react";
import PEMModal from "../../components/PEMModal.jsx";
import TechnicalSSLDetailsColumn1 from "./TechnicalSSLDetailsColumn1.jsx";
import TechnicalSSLDetailsColumn2 from "./TechnicalSSLDetailsColumn2.jsx";

const EnhancedSSLDetails = ({ sslData, securityScores, lastUpdated, onHide }) => {
  const [showDetails, setShowDetails] = useState(true);

  const formatDate = (d) => {
    if (!d) return "Not available";
    try {
      return (
        new Date(d).toLocaleDateString() +
        " " +
        new Date(d).toLocaleTimeString()
      );
    } catch {
      return d;
    }
  };

  const getDaysUntilExpiry = (d) => {
    if (!d) return null;
    try {
      const e = new Date(d),
        n = new Date();
      return Math.ceil((e - n) / (1000 * 60 * 60 * 24));
    } catch {
      return null;
    }
  };

  const daysUntilExpiry = getDaysUntilExpiry(sslData?.expires_on);

  const enhancedChecks = [
    {
      name: "HTTPS Connection",
      description: "SSL/TLS connection established successfully",
      value: sslData?.https_ok,
      status: sslData?.https_ok ? "good" : "bad",
      details: sslData?.https_ok
        ? "Secure HTTPS connection established"
        : "Failed to establish HTTPS connection",
      icon: (
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
            d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
          />
        </svg>
      ),
    },
    {
      name: "Certificate Validity",
      description: "Certificate is currently valid and not expired",
      value: sslData?.certificate_valid,
      status: sslData?.certificate_valid
        ? "good"
        : sslData?.expired === true
        ? "bad"
        : "warning",
      details: sslData?.certificate_valid
        ? "Certificate is currently valid"
        : sslData?.expired === true
        ? "Certificate has expired"
        : "Certificate validity unknown",
      icon: (
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
            d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      ),
    },
    {
      name: "Certificate Chain",
      description: "Complete certificate chain validation",
      value: sslData?.certificate_chain_complete,
      status: sslData?.certificate_chain_complete ? "good" : "warning",
      details: sslData?.certificate_chain_complete
        ? `Complete chain (${sslData.chain_length || "unknown"} levels)`
        : "Incomplete certificate chain",
      icon: (
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
            d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"
          />
        </svg>
      ),
    },
    {
      name: "Hostname Match",
      description: "Certificate matches the requested hostname",
      value: sslData?.hostname_match,
      status: sslData?.hostname_match ? "good" : "bad",
      details: sslData?.hostname_match
        ? "Hostname verified"
        : "Hostname mismatch detected",
      icon: (
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
            d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
          />
        </svg>
      ),
    },
    {
      name: "TLS Version",
      description: "The TLS protocol version being used",
      value: sslData?.tls_version,
      status:
        sslData?.tls_version === "TLSv1.3" ||
        sslData?.tls_version === "TLSv1.2"
          ? "good"
          : sslData?.tls_version
          ? "warning"
          : "bad",
      details: sslData?.tls_version
        ? `Using ${sslData.tls_version}`
        : "TLS version information not available",
      icon: (
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
            d="M4.871 4A17.926 17.926 0 003 12c0 2.874.673 5.59 1.871 8m14.13 0a17.926 17.926 0 001.87-8c0-2.874-.673-5.59-1.87-8M9 9h1.246a1 1 0 01.961.725l1.586 5.55a1 1 0 00.961.725H15"
          />
        </svg>
      ),
    },
  ];

  if (!showDetails) return null;

  return (
    <div className="w-full p-6 bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-500/30 rounded-lg">
      <h4 className="font-medium text-sm text-gray-900 dark:text-blue-300 flex items-center mb-4">
        <svg
          className="w-5 h-5 mr-2"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
          />
        </svg>
        Enhanced SSL/TLS Security Analysis
      </h4>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Checks */}
        <div className="space-y-3 lg:col-span-1">
          {enhancedChecks.map((c, i) => (
            <div
              key={i}
              className="flex items-center justify-between py-2 px-3 bg-white dark:bg-black rounded border border-gray-300 dark:border-gray-600"
            >
              <div className="flex items-center space-x-3">
                <div
                  className={`w-3 h-3 rounded-full ${
                    c.status === "good"
                      ? "bg-green-500"
                      : c.status === "warning"
                      ? "bg-yellow-500"
                      : "bg-red-500"
                  }`}
                ></div>
                <div className="text-gray-600 dark:text-gray-400">{c.icon}</div>
                <div>
                  <div className="font-medium text-sm text-gray-900 dark:text-gray-100">{c.name}</div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">{c.description}</div>
                </div>
              </div>
              <div className="text-right">
                <div
                  className={`text-sm font-medium ${
                    c.status === "good"
                      ? "text-green-600 dark:text-green-400"
                      : c.status === "warning"
                      ? "text-yellow-600 dark:text-yellow-400"
                      : "text-red-600 dark:text-red-400"
                  }`}
                >
                  {c.status === "good"
                    ? "✓"
                    : c.status === "warning"
                    ? "⚠"
                    : "✗"}
                </div>
                <div className="text-xs text-gray-600 dark:text-gray-300 max-w-48 text-right">
                  {c.details}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Columns */}
        <div className="space-y-3">
          <TechnicalSSLDetailsColumn1
            sslData={sslData}
            securityScores={securityScores}
            lastUpdated={lastUpdated}
          />
        </div>
        <div className="space-y-3">
          <TechnicalSSLDetailsColumn2 sslData={sslData} />
        </div>

        {/* Summary */}
        <div className="space-y-4">
          <h5 className="font-medium text-sm text-gray-900 dark:text-gray-100 mb-3 flex items-center border-b border-blue-300 dark:border-blue-500/30 pb-2">
            <svg
              className="w-5 h-5 mr-2"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
              />
            </svg>
            Summary Details
          </h5>

          <div className="space-y-3">
            <div className="bg-gray-50 dark:bg-black rounded p-3 border border-gray-300 dark:border-gray-600">
              <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase mb-1">
                Details:
              </div>
              <div className="text-sm text-gray-700 dark:text-gray-300">
                Professional SSL/TLS certificate validation
              </div>
            </div>

            <div className="bg-gray-50 dark:bg-black rounded p-3 border border-gray-300 dark:border-gray-600">
              <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase mb-1">
                Total Score:
              </div>
              <div className="text-sm font-bold text-green-600 dark:text-green-400">
                {securityScores?.ssl || 100}
              </div>
            </div>

            <div className="bg-gray-50 dark:bg-black rounded p-3 border border-gray-300 dark:border-gray-600">
              <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase mb-1">
                Weight:
              </div>
              <div className="text-sm text-gray-700 dark:text-gray-300">
                {securityScores?.weights?.ssl || 30}%
              </div>
            </div>

            <div className="bg-gray-50 dark:bg-black rounded p-3 border border-gray-300 dark:border-gray-600">
              <div className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase mb-1">
                Last Updated:
              </div>
              <div className="text-sm text-gray-700 dark:text-gray-300">
                {lastUpdated}
              </div>
            </div>
          </div>

          {/* Hide Button */}
          <div className="flex justify-center mt-4">
            <button
              onClick={() => onHide()}
              className="ml-2 text-lg text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 font-medium"
            >
              Hide Details ▼
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EnhancedSSLDetails;
