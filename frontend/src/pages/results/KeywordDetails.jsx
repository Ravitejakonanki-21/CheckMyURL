import React from "react";

function KeywordDetails({ keywords, keywordInfo, onHide }) {
  // If you pass an array (new style)
  if (Array.isArray(keywords)) {
    return (
      <div className="p-6 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
            Keyword Details
          </h4>
          <button
            className="text-blue-600 hover:underline text-sm"
            onClick={onHide}
          >
            Hide Details
          </button>
        </div>
        <div className="mb-3">
          <span className="font-semibold text-gray-800 dark:text-gray-200">Matched Keywords:</span>
          {keywords.length > 0 ? (
            <ul className="ml-4 mt-1 list-disc text-gray-700 dark:text-gray-300">
              {keywords.map((kw, idx) => (
                <li key={idx} className="mb-1">
                  <span className="px-2 py-1 rounded bg-yellow-100 dark:bg-yellow-800 text-yellow-800 dark:text-yellow-100 font-mono">{kw}</span>
                </li>
              ))}
            </ul>
          ) : (
            <span className="ml-2 italic text-gray-500 dark:text-gray-400">None detected</span>
          )}
        </div>
        <div className="mt-4 p-4 bg-blue-100 dark:bg-blue-900/60 border border-blue-200 dark:border-blue-700 rounded-md text-blue-800 dark:text-blue-200">
          <div className="mb-2 font-semibold">How to interpret keyword results:</div>
          <ul className="text-sm ml-4 list-disc">
            <li>Not all flagged keywords mean the URL is unsafe — consider context and other checks too.</li>
            <li>Generic terms (like "login") by themselves are not a definitive risk unless in suspicious combinations.</li>
            <li>Multiple high-risk keywords or uncommon phishing-related words increase overall risk.</li>
          </ul>
        </div>
      </div>
    );
  }

  // If you pass an object (legacy/object style)
  if (!keywordInfo) return null;

  const { keywords_found = [], risk_score = 0, risk_factors = [], url } = keywordInfo;

  return (
    <div className="p-6 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
          Keyword Analysis Details
        </h4>
        <button
          className="text-blue-600 hover:underline text-sm"
          onClick={onHide}
        >
          Hide Details
        </button>
      </div>

      <div className="mb-3">
        <span className="font-semibold text-gray-800 dark:text-gray-200">URL:</span>
        <span className="ml-2 text-gray-700 dark:text-gray-300">{url}</span>
      </div>

      <div className="mb-3">
        <span className="font-semibold text-gray-800 dark:text-gray-200">Matched Keywords:</span>
        {keywords_found.length > 0 ? (
          <ul className="ml-4 mt-1 list-disc text-gray-700 dark:text-gray-300">
            {keywords_found.map((kw, idx) => (
              <li key={idx} className="mb-1">
                <span className="px-2 py-1 rounded bg-yellow-100 dark:bg-yellow-800 text-yellow-800 dark:text-yellow-100 font-mono">{kw}</span>
              </li>
            ))}
          </ul>
        ) : (
          <span className="ml-2 italic text-gray-500 dark:text-gray-400">None detected</span>
        )}
      </div>

      <div className="mb-3">
        <span className="font-semibold text-gray-800 dark:text-gray-200">Keyword Risk Score:</span>
        <span className={`ml-2 font-bold ${
          risk_score >= 20 ? "text-red-600 dark:text-red-400" :
          risk_score > 0 ? "text-yellow-600 dark:text-yellow-300" :
          "text-green-700 dark:text-green-300"
        }`}>
          {risk_score}
        </span>
        <span className="ml-1 text-gray-500 dark:text-gray-300">(higher means more risk)</span>
      </div>

      {risk_factors && risk_factors.length > 0 && (
        <div className="mb-3">
          <span className="font-semibold text-gray-800 dark:text-gray-200">Risk Factors:</span>
          <ul className="list-disc ml-6 text-gray-700 dark:text-gray-300">
            {risk_factors.map((factor, idx) => (
              <li key={idx}>{factor}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-4 p-4 bg-blue-100 dark:bg-blue-900/60 border border-blue-200 dark:border-blue-700 rounded-md text-blue-800 dark:text-blue-200">
        <div className="mb-2 font-semibold">How to interpret keyword results:</div>
        <ul className="text-sm ml-4 list-disc">
          <li>Not all flagged keywords mean the URL is unsafe — consider the risk score in context with other checks.</li>
          <li>Generic terms (like "login") by themselves are not a definitive risk unless in suspicious combinations.</li>
          <li>Multiple high-risk keywords or presence of uncommon phishing-related words (like "verify-account", "reset-password") raise overall risk.</li>
        </ul>
      </div>
    </div>
  );
}

export default KeywordDetails;
