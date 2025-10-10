import { BarChart3, TrendingUp, Activity, Globe } from 'lucide-react';

function Statistics() {
  const stats = [
    { label: 'Total Scans', value: '1,234', icon: Activity, color: 'text-[#00d4ff]' },
    { label: 'Active URLs', value: '856', icon: Globe, color: 'text-[#00d4ff]' },
    { label: 'Success Rate', value: '94.2%', icon: TrendingUp, color: 'text-[#00d4ff]' },
    { label: 'Avg Response', value: '1.2s', icon: BarChart3, color: 'text-[#00d4ff]' },
  ];

  return (
    <div className="min-h-screen bg-white dark:bg-black transition-colors py-20 px-6">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <h1 className="text-5xl font-bold text-gray-900 dark:text-white mb-4">
            Statistics
          </h1>
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            Track your scanning activity and performance metrics
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {stats.map((stat, index) => (
            <div
              key={index}
              className="bg-white dark:bg-gray-900 p-8 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30 hover:shadow-xl dark:hover:shadow-[#00d4ff]/20 transition-all duration-300"
            >
              <stat.icon className={`${stat.color} mb-4`} size={32} />
              <h3 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                {stat.value}
              </h3>
              <p className="text-gray-600 dark:text-gray-400">{stat.label}</p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white dark:bg-gray-900 p-8 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">
              Recent Activity
            </h2>
            <div className="space-y-4">
              {[1, 2, 3, 4, 5].map((item) => (
                <div
                  key={item}
                  className="flex items-center justify-between p-4 bg-gray-50 dark:bg-black rounded-lg border border-gray-200 dark:border-[#00d4ff]/20"
                >
                  <div>
                    <p className="text-gray-900 dark:text-white font-medium">
                      example-url-{item}.com
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Scanned 2 hours ago
                    </p>
                  </div>
                  <span className="px-3 py-1 bg-green-100 dark:bg-[#00d4ff]/20 text-green-700 dark:text-[#00d4ff] rounded-full text-sm font-medium">
                    Success
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white dark:bg-gray-900 p-8 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">
              Performance Trends
            </h2>
            <div className="space-y-6">
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-gray-600 dark:text-gray-400">Security Score</span>
                  <span className="text-gray-900 dark:text-white font-semibold">92%</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-800 rounded-full h-3">
                  <div className="bg-[#00d4ff] h-3 rounded-full" style={{ width: '92%' }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-gray-600 dark:text-gray-400">Performance</span>
                  <span className="text-gray-900 dark:text-white font-semibold">87%</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-800 rounded-full h-3">
                  <div className="bg-[#00d4ff] h-3 rounded-full" style={{ width: '87%' }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-gray-600 dark:text-gray-400">Reliability</span>
                  <span className="text-gray-900 dark:text-white font-semibold">95%</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-800 rounded-full h-3">
                  <div className="bg-[#00d4ff] h-3 rounded-full" style={{ width: '95%' }}></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
export default Statistics;