import { CheckCircle, XCircle, AlertTriangle, Shield } from 'lucide-react';

function Results() {
  const results = [
    {
      category: 'Security',
      status: 'success',
      icon: Shield,
      items: ['SSL Certificate Valid', 'HTTPS Enabled', 'No Known Vulnerabilities'],
    },
    {
      category: 'Performance',
      status: 'warning',
      icon: AlertTriangle,
      items: ['Load Time: 2.3s', 'Image Optimization Needed', 'Caching Enabled'],
    },
  ];

  return (
    <div className="min-h-screen bg-white dark:bg-black transition-colors py-20 px-6">
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-16">
          <h1 className="text-5xl font-bold text-gray-900 dark:text-white mb-4">
            Scan Results
          </h1>
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            Detailed analysis of your scanned URLs
          </p>
        </div>

        <div className="space-y-6">
          {results.map((result, index) => (
            <div
              key={index}
              className="bg-white dark:bg-gray-900 p-8 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30"
            >
              <div className="flex items-center gap-3 mb-6">
                <result.icon className="text-[#00d4ff]" size={28} />
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                  {result.category}
                </h2>
              </div>
              <div className="space-y-3">
                {result.items.map((item, i) => (
                  <div key={i} className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                    {result.status === 'success' ? (
                      <CheckCircle className="text-green-500 dark:text-[#00d4ff]" size={20} />
                    ) : result.status === 'warning' ? (
                      <AlertTriangle className="text-yellow-500 dark:text-[#00d4ff]" size={20} />
                    ) : (
                      <XCircle className="text-red-500" size={20} />
                    )}
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
export default Results;