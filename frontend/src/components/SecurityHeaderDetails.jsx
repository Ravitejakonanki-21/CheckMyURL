import React, { useState } from "react";
import { copyToClipboard } from "../utils/quickActions.js"; // Adjust path if needed

const MAIN_HEADERS = [
  {
    key: "strict-transport-security",
    title: "HSTS",
    desc: "Prevents protocol downgrade attacks and cookie hijacking.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
  },
  {
    key: "content-security-policy",
    title: "Content-Security-Policy",
    desc: "Mitigates XSS and data injection attacks.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
  },
  {
    key: "content-security-policy-report-only",
    title: "CSP Report-Only",
    desc: "Non-enforced CSP for testing and audits.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only"
  },
  {
    key: "x-frame-options",
    title: "X-Frame-Options",
    desc: "Avoids clickjacking by restricting frame embedding.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
  },
  {
    key: "x-content-type-options",
    title: "X-Content-Type-Options",
    desc: "Blocks MIME type sniffing security risk.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
  },
  {
    key: "referrer-policy",
    title: "Referrer-Policy",
    desc: "Controls amount of referrer info sent.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
  },
  {
    key: "permissions-policy",
    title: "Permissions-Policy",
    desc: "Controls which browser features can be used.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
  },
  {
    key: "cross-origin-opener-policy",
    title: "Cross-Origin-Opener-Policy",
    desc: "Isolates browsing context for advanced cross-origin protection.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
  },
  {
    key: "cross-origin-embedder-policy",
    title: "Cross-Origin-Embedder-Policy",
    desc: "Secures resource embedding from cross origins.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
  },
  {
    key: "cross-origin-resource-policy",
    title: "Cross-Origin-Resource-Policy",
    desc: "Restricts resource loading across origins.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
  },
  {
    key: "expect-ct",
    title: "Expect-CT",
    desc: "Enforces Certificate Transparency for detecting misissued TLS certificates.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"
  },
  {
    key: "report-to",
    title: "Report-To",
    desc: "Configures browser reporting endpoints for network and security issues.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Report-To"
  },
  {
    key: "x-xss-protection",
    title: "X-XSS-Protection",
    desc: "Enables or disables legacy XSS filtering in browsers.",
    docs: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
  }
];

function ClipboardButton({ value, copied, onCopy }) {
  return (
    <button
      onClick={onCopy}
      className="absolute top-3 right-3 text-blue-400 hover:text-blue-200 transition"
      title="Copy to clipboard"
    >
      {copied ? (
        <svg className="w-5 h-5 inline" fill="none" stroke="green" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      ) : (
        <svg className="w-5 h-5 inline" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <rect x={9} y={9} width={13} height={13} rx={2} ry={2} />
          <path d="M5 15V5a2 2 0 012-2h10a2 2 0 012 2v10" />
        </svg>
      )}
    </button>
  );
}

function SecurityHeaderDetails({ securityHeadersData, onHide }) {
  const [copied, setCopied] = useState({});

  if (
    !securityHeadersData ||
    Object.keys(securityHeadersData.security_headers || {}).length === 0
  ) {
    return <p className="text-gray-600">No security headers found.</p>;
  }

  const { security_headers, all_headers } = securityHeadersData;
  const normalizedHeaders = Object.keys(security_headers).reduce((acc, key) => {
    acc[key.toLowerCase()] = security_headers[key];
    return acc;
  }, {});

  const renderValue = (value) =>
    value !== null && value !== undefined && value !== ""
      ? String(value)
      : <span className="text-gray-500">—</span>;

  const handleCopy = (text, key) => {
    copyToClipboard(text);
    setCopied(prev => ({ ...prev, [key]: true }));
    setTimeout(() => setCopied(prev => ({ ...prev, [key]: false })), 1200);
  };

  return (
    <div className="relative w-full px-3 sm:px-6">
      <div className="flex flex-col md:flex-row gap-6 mb-6">
        {/* Security Headers Status - left half */}
        <div className="w-full md:w-1/2">
          <h4 className="text-lg font-semibold mb-2 mt-3 text-cyan-500">
            Security Headers Status
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {MAIN_HEADERS.map((h) => {
              const value = normalizedHeaders[h.key];
              const isSet = value !== undefined && value !== null && value !== "";
              const copyVal = isSet ? value : "Missing";
              return (
                <div
                  key={h.key}
                  className={`relative flex flex-col border rounded-xl px-4 py-3 bg-black/60 ${
                    isSet
                      ? "border-green-700 bg-green-950/50"
                      : "border-gray-700 bg-gray-900"
                  }`}
                >
                  <ClipboardButton
                    value={copyVal}
                    copied={!!copied[h.key]}
                    onCopy={() => handleCopy(copyVal, h.key)}
                  />
                  <div className="flex items-center mb-1">
                    {isSet ? (
                      <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-green-600 text-white mr-3">✓</span>
                    ) : (
                      <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-gray-600 text-white mr-3">!</span>
                    )}
                    <span className="font-semibold text-base text-white">{h.title}</span>
                    <a
                      href={h.docs}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-2 text-blue-400 underline text-xs"
                      tabIndex={-1}
                    >
                      docs
                    </a>
                  </div>
                  <div className="text-xs text-gray-300 mb-1">{h.desc}</div>
                  <div className={`text-xs ${isSet ? "text-green-300" : "text-gray-500"} font-mono break-all`}>
                    {isSet ? renderValue(value) : "Missing"}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
        {/* Advanced Technical Details - right half */}
        <div className="w-full md:w-1/2">
          <h4 className="text-lg font-semibold mb-2 mt-3 text-cyan-500">Advanced Technical Details</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pb-2">
            {all_headers &&
              Object.entries(all_headers).map(([header, value], idx, arr) => (
                <React.Fragment key={header}>
                  <div
                    className="relative flex flex-col bg-gray-900 border border-gray-700 rounded-xl px-4 py-3 mb-2"
                  >
                    <ClipboardButton
                      value={value}
                      copied={!!copied[header]}
                      onCopy={() => handleCopy(value, header)}
                    />
                    <div className="font-mono text-xs text-cyan-200 mb-1 uppercase tracking-wide">{header}</div>
                    <div className="text-xs text-gray-200 break-all font-mono">{renderValue(value)}</div>
                  </div>
                  {idx === arr.length - 1 && onHide && (
                    <div className="col-span-full flex justify-end">
                      <button
                        onClick={onHide}
                        className="mt-2 mb-2 px-4 py-2 bg-transparent border border-blue-600 text-blue-400 rounded-md font-semibold text-base hover:bg-blue-900 hover:text-blue-100 shadow transition-colors duration-200"
                      >
                        <svg className="inline w-5 h-5 mr-1" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/>
                        </svg>
                        Hide Details
                      </button>
                    </div>
                  )}
                </React.Fragment>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default SecurityHeaderDetails;
