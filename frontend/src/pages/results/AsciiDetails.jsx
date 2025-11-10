import React from "react";

function AsciiDetails({ idnData, onHide }) {
  if (!idnData) {
    return (
      <div className="p-6 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
        <p className="text-gray-500 dark:text-gray-400">No ASCII/IDN data available</p>
      </div>
    );
  }

  const checks = [
    {
      name: "Character Set Validation",
      description: "Ensures all characters are standard ASCII (0-127 range)",
      result: idnData.character_set_validation?.all_ascii 
        ? "All ASCII characters" 
        : `Found ${idnData.character_set_validation?.non_ascii_count || 0} non-ASCII characters`,
      status: idnData.character_set_validation?.all_ascii ? "pass" : "fail",
      example: idnData.character_set_validation?.all_ascii ? "All ASCII characters" : "Non-ASCII detected"
    },
    {
      name: "Unicode / Non-ASCII Detection",
      description: "Detects non-ASCII (Unicode, Cyrillic, Arabic, etc.) characters in URL",
      result: idnData.unicode_detection?.found 
        ? `Found ${idnData.unicode_detection?.count || 0} Unicode characters` 
        : "No Unicode characters found",
      status: !idnData.unicode_detection?.found ? "pass" : "warning",
      example: idnData.unicode_detection?.found ? "Found Unicode characters" : "No Unicode characters",
      details: idnData.unicode_detection?.characters?.slice(0, 5).map((c, i) => (
        <div key={i} className="text-xs text-gray-600 dark:text-gray-400 ml-4">
          {c.char} ({c.script}) - {c.name}
        </div>
      ))
    },
    {
      name: "Punycode Domain Check",
      description: "Detects encoded Unicode domains using xn-- prefix",
      result: idnData.punycode_check?.found 
        ? `Punycode found: ${idnData.punycode_check?.labels?.join(", ") || "N/A"}` 
        : "No Punycode found",
      status: !idnData.punycode_check?.found ? "pass" : "warning",
      example: idnData.punycode_check?.found ? "Punycode detected" : "No Punycode found"
    },
    {
      name: "Homograph Detection",
      description: "Flags visually deceptive characters like а for a or е for e",
      result: idnData.homograph_detection?.found 
        ? `Possible homograph pattern (${idnData.homograph_detection?.count || 0} found)` 
        : "No homograph patterns detected",
      status: !idnData.homograph_detection?.found ? "pass" : "warning",
      example: idnData.homograph_detection?.found ? "Possible homograph pattern" : "No homograph patterns",
      details: idnData.homograph_detection?.patterns?.slice(0, 5).map((p, i) => (
        <div key={i} className="text-xs text-gray-600 dark:text-gray-400 ml-4">
          Position {p.position}: '{p.char}' looks like '{p.looks_like}' ({p.unicode_name})
        </div>
      ))
    },
    {
      name: "Encoded Character Detection",
      description: "Checks for percent-encoded strings (%20, %2E, etc.)",
      result: idnData.encoded_characters?.found 
        ? `Found ${idnData.encoded_characters?.count || 0} encoded characters` 
        : "Clean URL - no encoded parts",
      status: !idnData.encoded_characters?.found ? "pass" : "warning",
      example: idnData.encoded_characters?.found ? "Encoded parts found" : "Clean URL - no encoded parts",
      details: idnData.encoded_characters?.decoded?.slice(0, 5).map((e, i) => (
        <div key={i} className="text-xs text-gray-600 dark:text-gray-400 ml-4">
          {e.encoded} → {e.decoded}
        </div>
      ))
    },
    {
      name: "Invisible Character Detection",
      description: "Detects hidden or zero-width characters",
      result: idnData.invisible_characters?.found 
        ? `Found ${idnData.invisible_characters?.count || 0} invisible characters` 
        : "No invisible characters found",
      status: !idnData.invisible_characters?.found ? "pass" : "warning",
      example: idnData.invisible_characters?.found ? "Invisible chars found" : "No invisible characters found"
    },
    {
      name: "Entropy Check",
      description: "Calculates randomness of strings to detect obfuscation",
      result: idnData.entropy_check?.level 
        ? `${idnData.entropy_check?.level} entropy detected (${idnData.entropy_check?.entropy || 0})` 
        : "No entropy data",
      status: idnData.entropy_check?.level === "Low" || idnData.entropy_check?.level === "Moderate" ? "pass" : "warning",
      example: idnData.entropy_check?.level ? `${idnData.entropy_check.level} entropy detected` : "No entropy data"
    },
    {
      name: "Overall URL Legibility",
      description: "Evaluates readability and predictability of URL text",
      result: idnData.url_legibility?.readability || "Not analyzed",
      status: idnData.url_legibility?.readability?.includes("Readable") ? "pass" : "warning",
      example: idnData.url_legibility?.readability || "Readable and structured"
    }
  ];

  const getStatusColor = (status) => {
    if (status === "pass") return "text-green-600 dark:text-green-400";
    if (status === "warning") return "text-yellow-600 dark:text-yellow-400";
    return "text-red-600 dark:text-red-400";
  };

  const getStatusIcon = (status) => {
    if (status === "pass") return "✓";
    if (status === "warning") return "⚠";
    return "✗";
  };

  return (
    <div className="p-6 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
          Detailed ASCII/IDN Analysis
        </h4>
        <button
          className="text-blue-600 hover:underline text-sm"
          onClick={onHide}
        >
          Hide Details
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-100 dark:bg-gray-800">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Check</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Description</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Result Example</th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
            {checks.map((check, index) => (
              <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                <td className="px-4 py-3 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <span className={`font-semibold text-lg ${getStatusColor(check.status)}`}>
                      {getStatusIcon(check.status)}
                    </span>
                    <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                      {check.name}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {check.description}
                  </p>
                  {check.details && (
                    <div className="mt-2 text-xs text-gray-500 dark:text-gray-500">
                      {check.details}
                    </div>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className={`text-sm font-medium ${getStatusColor(check.status)}`}>
                    {check.example || check.result}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mt-4 p-4 bg-blue-100 dark:bg-blue-900/60 border border-blue-200 dark:border-blue-700 rounded-md text-blue-800 dark:text-blue-200">
        <div className="mb-2 font-semibold">Understanding ASCII Checks:</div>
        <ul className="text-sm ml-4 list-disc space-y-1">
          <li>ASCII-only URLs are safer and less prone to homograph attacks</li>
          <li>Punycode domains (xn-- prefix) indicate Unicode encoding</li>
          <li>Homograph characters can make malicious URLs look legitimate</li>
          <li>High entropy suggests random/obfuscated strings</li>
          <li>Encoded characters may hide malicious content</li>
        </ul>
      </div>
    </div>
  );
}

export default AsciiDetails;

