const WhoisDetails = ({ whoisData }) => {
  const formatDate = (dateString) => {
    if (!dateString) return "Not available";
    try {
      return new Date(dateString).toLocaleDateString();
    } catch {
      return dateString;
    }
  };

  return (
    <div className="mt-3 p-3 bg-green-50 dark:bg-green-900/20 border border-green-300 dark:border-green-500/30 rounded-lg">
      <h4 className="font-medium text-sm mb-2 text-gray-900 dark:text-green-300 flex items-center">
        <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        WHOIS Information
      </h4>
      <div className="grid grid-cols-2 gap-4 text-xs">
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Creation Date:</div>
          <div className="text-gray-600 dark:text-gray-400">{formatDate(whoisData.creation_date)}</div>
        </div>
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Expiration Date:</div>
          <div className="text-gray-600 dark:text-gray-400">{formatDate(whoisData.expiration_date)}</div>
        </div>
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Registrar:</div>
          <div className="text-gray-600 dark:text-gray-400">{whoisData.registrar || "Not available"}</div>
        </div>
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Status:</div>
          <div className="text-gray-600 dark:text-gray-400">{whoisData.status || "Not available"}</div>
        </div>
      </div>
      {whoisData.errors && whoisData.errors.length > 0 && (
        <div className="mt-2 text-xs text-red-600 dark:text-red-400">
          <div className="font-medium">Errors:</div>
          {whoisData.errors.map((error, index) => (
            <div key={index}>• {error}</div>
          ))}
        </div>
      )}
    </div>
  );
};

export default WhoisDetails;