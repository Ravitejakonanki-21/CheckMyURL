import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search } from 'lucide-react';
import { useScan } from '../context/ScanContext';

export default function Scanner() {
  const [url, setUrl] = useState('');
  const { setHasScanned } = useScan();
  const navigate = useNavigate();

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      console.log('Scanning URL:', url);
      setHasScanned(true);
      navigate('/results');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-white dark:bg-black transition-colors">
      <div className="w-full max-w-3xl px-6">
        <div className="text-center mb-12">
          <h1 className="text-6xl font-bold mb-4 text-gray-900 dark:text-white">
            URL <span className="text-blue-600 dark:text-[#00d4ff]">Scanner</span>
          </h1>
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            Enter a URL to scan and analyze
          </p>
        </div>

        <form onSubmit={handleSubmit} className="relative">
          <div className="flex items-center bg-white dark:bg-gray-900 rounded-full shadow-lg dark:shadow-[#00d4ff]/20 border-2 border-gray-200 dark:border-[#00d4ff]/30 overflow-hidden hover:shadow-xl dark:hover:shadow-[#00d4ff]/40 transition-all duration-300">
            <Search className="ml-6 text-gray-400 dark:text-[#00d4ff]" size={24} />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan..."
              className="flex-1 px-6 py-5 text-lg bg-transparent outline-none text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
            />
            <button
              type="submit"
              className="mx-2 px-8 py-3 bg-blue-600 dark:bg-[#00d4ff] text-white dark:text-black font-semibold rounded-full hover:bg-blue-700 dark:hover:bg-[#00bbff] transition-colors"
            >
              Scan
            </button>
          </div>
        </form>

        <div className="mt-8 flex justify-center gap-4">
          <button className="px-6 py-2 bg-gray-100 dark:bg-gray-900 text-gray-700 dark:text-gray-300 rounded-full hover:bg-gray-200 dark:hover:bg-gray-800 border border-gray-300 dark:border-[#00d4ff]/20 transition-colors">
            Quick Scan
          </button>
          <button className="px-6 py-2 bg-gray-100 dark:bg-gray-900 text-gray-700 dark:text-gray-300 rounded-full hover:bg-gray-200 dark:hover:bg-gray-800 border border-gray-300 dark:border-[#00d4ff]/20 transition-colors">
            Deep Analysis
          </button>
        </div>
      </div>
    </div>
  );
}