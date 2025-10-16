import { useState } from "react";

const PEMModal = ({ isOpen, onClose, pemData }) => {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-900 rounded-lg max-w-4xl max-h-[90vh] w-full mx-4 flex flex-col border border-gray-400 dark:border-gray-600">

        <div className="flex items-center justify-between p-4 border-b border-gray-300 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Raw Certificate Data (PEM)</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4">
          <div className="bg-black dark:bg-gray-800 rounded p-4 relative border border-gray-400 dark:border-gray-600">
            <pre className="text-sm text-green-400 font-mono overflow-x-auto whitespace-pre-wrap break-all">{pemData}</pre>
            <button onClick={() => navigator.clipboard?.writeText(pemData)} className="absolute top-2 right-2 text-green-400 hover:text-green-200 text-xs px-3 py-1 bg-black/50 rounded border border-green-500" title="Copy PEM Certificate">
              <svg className="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>Copy PEM
            </button>
          </div>
        </div>

        <div className="p-4 border-t border-gray-300 dark:border-gray-700 flex justify-end">
          <button onClick={onClose} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors duration-200">Close</button>
        </div>

      </div>
    </div>
  );
};

export default PEMModal;