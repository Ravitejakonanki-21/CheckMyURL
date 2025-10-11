import { useMemo } from "react";
import LineCard from "../components/LineCard";
import BarCard from "../components/BarCard";
import ToolsPanel from "../components/ToolsPanel";
import { useScan } from "../context/ScanContext";

function Statistics() {
  const { history = [] } = useScan?.() ?? { history: [] };

  // last 12 scans; ensure at least one point for initial render
  const last = useMemo(() => (history.length ? history.slice(-12) : [{ riskScore: 0 }]), [history]);
  const labels = useMemo(
    () => (history.length ? last.map((_, i) => `#${history.length - last.length + i + 1}`) : ["1"]),
    [last, history.length]
  );

  // Risk trend line - Updated colors for new primary color
  const riskSeries = useMemo(
    () => [{ name: "Risk", data: last.map((e) => (Number.isFinite(e.riskScore) ? e.riskScore : 0)) }],
    [last]
  );
  const riskOptions = useMemo(
    () => ({
      chart: { 
        toolbar: { show: false }, 
        animations: { enabled: true, speed: 800, easing: 'easeout' },
        background: 'transparent',
        foreColor: '#6B7280'
      },
      stroke: { curve: "smooth", width: 4, colors: ['#8B5CF6'] },
      dataLabels: { enabled: false },
      grid: { 
        borderColor: 'rgba(139, 92, 246, 0.1)',
        strokeDashArray: 4,
        xaxis: { lines: { show: true } },
        yaxis: { lines: { show: true } }
      },
      xaxis: { 
        categories: labels, 
        tickPlacement: "on",
        labels: { 
          style: { colors: '#6B7280', fontSize: '12px' }
        },
        axisBorder: { show: false },
        axisTicks: { show: false }
      },
      yaxis: { 
        min: 0, 
        max: 100, 
        forceNiceScale: true,
        labels: { 
          style: { colors: '#6B7280', fontSize: '12px' }
        }
      },
      colors: ["#8B5CF6"], // New primary purple
      tooltip: {
        theme: 'dark',
        style: {
          fontSize: '12px'
        }
      },
      markers: {
        size: 5,
        colors: ['#8B5CF6'],
        strokeColors: '#fff',
        strokeWidth: 2,
        hover: {
          size: 7
        }
      }
    }),
    [labels]
  );

  // Tool totals
  const toolOrder = ["SSL", "WHOIS", "Headers", "Keywords", "Ports", "ML"];
  const toolTotals = useMemo(() => {
    if (!history.length) return [0, 0, 0, 0, 0, 0];
    const acc = { SSL: 0, WHOIS: 0, Headers: 0, Keywords: 0, Ports: 0, ML: 0 };
    history.forEach((e) => {
      if (!e?.tools) return;
      Object.entries(e.tools).forEach(([k, v]) => (acc[k] = (acc[k] ?? 0) + (Number(v) || 0)));
    });
    return toolOrder.map((k) => acc[k] ?? 0);
  }, [history]);

  const toolsSeries = useMemo(() => [{ name: "Findings", data: toolTotals }], [toolTotals]);
  const toolsOptions = useMemo(
    () => ({
      chart: { 
        toolbar: { show: false }, 
        animations: { enabled: true, speed: 800, easing: 'easeout' },
        background: 'transparent',
        foreColor: '#6B7280'
      },
      plotOptions: { 
        bar: { 
          borderRadius: 8, 
          columnWidth: "55%",
          distributed: false
        } 
      },
      xaxis: { 
        categories: toolOrder,
        labels: { 
          style: { colors: '#6B7280', fontSize: '12px' }
        },
        axisBorder: { show: false },
        axisTicks: { show: false }
      },
      yaxis: {
        labels: { 
          style: { colors: '#6B7280', fontSize: '12px' }
        }
      },
      colors: ["#8B5CF6"], // New primary purple
      dataLabels: { enabled: false },
      grid: { 
        borderColor: 'rgba(139, 92, 246, 0.1)',
        strokeDashArray: 4 
      },
      tooltip: {
        theme: 'dark',
        style: {
          fontSize: '12px'
        }
      }
    }),
    []
  );

  // Risk score distribution buckets
  const bucketLabels = ["0-20", "21-40", "41-60", "61-80", "81-100"];
  const riskDist = useMemo(() => {
    if (!history.length) return [0, 0, 0, 0, 0];
    const b = [0, 0, 0, 0, 0];
    history.forEach(({ riskScore = 0 }) => {
      const v = Number(riskScore) || 0;
      const i = v <= 20 ? 0 : v <= 40 ? 1 : v <= 60 ? 2 : v <= 80 ? 3 : 4;
      b[i] += 1;
    });
    return b;
  }, [history]);

  const riskDistSeries = useMemo(() => [{ name: "URLs", data: riskDist }], [riskDist]);
  const riskDistOptions = useMemo(
    () => ({
      chart: { 
        toolbar: { show: false }, 
        animations: { enabled: true, speed: 800, easing: 'easeout' },
        background: 'transparent',
        foreColor: '#6B7280'
      },
      plotOptions: { 
        bar: { 
          borderRadius: 8, 
          columnWidth: "60%",
          distributed: true
        } 
      },
      xaxis: { 
        categories: bucketLabels,
        labels: { 
          style: { colors: '#6B7280', fontSize: '12px' }
        },
        axisBorder: { show: false },
        axisTicks: { show: false }
      },
      yaxis: {
        labels: { 
          style: { colors: '#6B7280', fontSize: '12px' }
        }
      },
      colors: ["#10B981", "#8B5CF6", "#F59E0B", "#F97316", "#EF4444"], // Purple included in gradient
      dataLabels: { enabled: false },
      grid: { 
        borderColor: 'rgba(139, 92, 246, 0.1)',
        strokeDashArray: 4 
      },
      legend: { show: false },
      tooltip: {
        theme: 'dark',
        style: {
          fontSize: '12px'
        }
      }
    }),
    []
  );

  // Calculate stats
  const totalScans = history.length;
  const avgRisk = history.length 
    ? Math.round(history.reduce((sum, e) => sum + (e.riskScore || 0), 0) / history.length)
    : 0;
  const highRiskCount = history.filter(e => (e.riskScore || 0) >= 70).length;
  const safeCount = history.filter(e => (e.riskScore || 0) < 40).length;

  return (
    <div className="min-h-screen bg-gradient-to-br from-white via-violet-50 to-purple-100 dark:from-gray-950 dark:via-gray-900 dark:to-purple-950/20 p-6 transition-all duration-500 ease-in-out">
      {/* Header Section */}
      <div className="mb-8 transition-all duration-500">
        <div className="flex items-center gap-3 mb-2">
          <svg className="w-8 h-8 text-purple-600 dark:text-purple-400 transition-colors duration-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white transition-colors duration-500">
            Security <span className="text-purple-600 dark:text-purple-400 transition-colors duration-500">Analytics</span>
          </h1>
        </div>
        <p className="text-gray-600 dark:text-gray-400 transition-colors duration-500">Comprehensive insights into your URL security scans</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {/* Total Scans */}
        <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-xl border border-purple-200 dark:border-purple-500/30 rounded-xl p-5 shadow-lg dark:shadow-purple-500/10 hover:shadow-xl dark:hover:shadow-purple-500/20 transition-all duration-500 hover:scale-105 hover:border-purple-300 dark:hover:border-purple-400/50">
          <div className="flex items-center justify-between mb-2">
            <div className="p-2 bg-purple-100 dark:bg-purple-500/20 rounded-lg transition-colors duration-500">
              <svg className="w-5 h-5 text-purple-600 dark:text-purple-400 transition-colors duration-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
          </div>
          <div className="text-3xl font-bold text-gray-900 dark:text-white mb-1 transition-colors duration-500">{totalScans}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400 transition-colors duration-500">Total Scans</div>
        </div>

        {/* Average Risk */}
        <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-xl border border-purple-200 dark:border-purple-500/30 rounded-xl p-5 shadow-lg dark:shadow-purple-500/10 hover:shadow-xl dark:hover:shadow-purple-500/20 transition-all duration-500 hover:scale-105 hover:border-purple-300 dark:hover:border-purple-400/50">
          <div className="flex items-center justify-between mb-2">
            <div className="p-2 bg-yellow-100 dark:bg-yellow-500/20 rounded-lg transition-colors duration-500">
              <svg className="w-5 h-5 text-yellow-600 dark:text-yellow-400 transition-colors duration-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
          </div>
          <div className="text-3xl font-bold text-gray-900 dark:text-white mb-1 transition-colors duration-500">{avgRisk}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400 transition-colors duration-500">Average Risk Score</div>
        </div>

        {/* High Risk URLs */}
        <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-xl border border-purple-200 dark:border-purple-500/30 rounded-xl p-5 shadow-lg dark:shadow-purple-500/10 hover:shadow-xl dark:hover:shadow-purple-500/20 transition-all duration-500 hover:scale-105 hover:border-purple-300 dark:hover:border-purple-400/50">
          <div className="flex items-center justify-between mb-2">
            <div className="p-2 bg-red-100 dark:bg-red-500/20 rounded-lg transition-colors duration-500">
              <svg className="w-5 h-5 text-red-600 dark:text-red-400 transition-colors duration-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
          <div className="text-3xl font-bold text-gray-900 dark:text-white mb-1 transition-colors duration-500">{highRiskCount}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400 transition-colors duration-500">High Risk URLs</div>
        </div>

        {/* Safe URLs */}
        <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-xl border border-purple-200 dark:border-purple-500/30 rounded-xl p-5 shadow-lg dark:shadow-purple-500/10 hover:shadow-xl dark:hover:shadow-purple-500/20 transition-all duration-500 hover:scale-105 hover:border-purple-300 dark:hover:border-purple-400/50">
          <div className="flex items-center justify-between mb-2">
            <div className="p-2 bg-green-100 dark:bg-green-500/20 rounded-lg transition-colors duration-500">
              <svg className="w-5 h-5 text-green-600 dark:text-green-400 transition-colors duration-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
          <div className="text-3xl font-bold text-gray-900 dark:text-white mb-1 transition-colors duration-500">{safeCount}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400 transition-colors duration-500">Safe URLs</div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Tools Panel - Left Column */}
        <div className="lg:col-span-1">
          <ToolsPanel />
        </div>

        {/* Charts - Right Column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Risk Trend Line Chart */}
          <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-xl border border-purple-200 dark:border-purple-500/30 rounded-xl shadow-lg dark:shadow-purple-500/10 overflow-hidden hover:shadow-xl dark:hover:shadow-purple-500/20 transition-all duration-500 hover:border-purple-300 dark:hover:border-purple-400/50">
            <div className="p-5 border-b border-purple-200 dark:border-purple-500/30 transition-colors duration-500">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-purple-500 dark:bg-purple-400 animate-pulse transition-colors duration-500"></div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white transition-colors duration-500">Risk Trend</h3>
              </div>
              <p className="text-xs text-gray-600 dark:text-gray-400 mt-1 transition-colors duration-500">Last {last.length} scans</p>
            </div>
            <div className="p-5">
              <LineCard
                key={`risk-${labels.join("-")}`}
                title=""
                series={riskSeries}
                options={riskOptions}
                height={320}
              />
            </div>
          </div>

          {/* Tool Findings Bar Chart */}
          <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-xl border border-purple-200 dark:border-purple-500/30 rounded-xl shadow-lg dark:shadow-purple-500/10 overflow-hidden hover:shadow-xl dark:hover:shadow-purple-500/20 transition-all duration-500 hover:border-purple-300 dark:hover:border-purple-400/50">
            <div className="p-5 border-b border-purple-200 dark:border-purple-500/30 transition-colors duration-500">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-purple-500 dark:bg-purple-400 animate-pulse transition-colors duration-500"></div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white transition-colors duration-500">Tool Findings Distribution</h3>
              </div>
              <p className="text-xs text-gray-600 dark:text-gray-400 mt-1 transition-colors duration-500">Cumulative findings across all scans</p>
            </div>
            <div className="p-5">
              <BarCard
                key={`tools-${history.length}`}
                title=""
                series={toolsSeries}
                options={toolsOptions}
                height={320}
              />
            </div>
          </div>

          {/* Risk Distribution Bar Chart */}
          <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-xl border border-purple-200 dark:border-purple-500/30 rounded-xl shadow-lg dark:shadow-purple-500/10 overflow-hidden hover:shadow-xl dark:hover:shadow-purple-500/20 transition-all duration-500 hover:border-purple-300 dark:hover:border-purple-400/50">
            <div className="p-5 border-b border-purple-200 dark:border-purple-500/30 transition-colors duration-500">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-purple-500 dark:bg-purple-400 animate-pulse transition-colors duration-500"></div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white transition-colors duration-500">Risk Score Distribution</h3>
              </div>
              <p className="text-xs text-gray-600 dark:text-gray-400 mt-1 transition-colors duration-500">URLs categorized by risk level</p>
            </div>
            <div className="p-5">
              <BarCard
                key={`dist-${history.length}`}
                title=""
                series={riskDistSeries}
                options={riskDistOptions}
                height={320}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Statistics;