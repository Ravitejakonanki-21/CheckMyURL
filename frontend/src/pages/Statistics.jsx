import { useMemo, useState, useEffect } from "react";
import LineCard from "../components/LineCard";
import BarCard from "../components/BarCard";
import ToolsPanel from "../components/ToolsPanel";
import { useScan } from "../context/ScanContext";

function authHeader() {
  const token = localStorage.getItem('access_token') || localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function classColor(cls = '') {
  const c = cls.toUpperCase();
  if (c.includes('HIGH') || c.includes('CRITICAL') || c.includes('PHISH')) return 'text-red-500';
  if (c.includes('MEDIUM') || c.includes('SUSPICIOUS')) return 'text-yellow-500';
  return 'text-[#00e5ff]';
}

function badge(cls = '') {
  const c = cls.toUpperCase();
  if (c.includes('HIGH') || c.includes('CRITICAL') || c.includes('PHISH'))
    return 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300';
  if (c.includes('MEDIUM') || c.includes('SUSPICIOUS'))
    return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300';
  return 'bg-[#00e5ff]/10 text-[#00e5ff] border border-[#00e5ff]/20';
}

function Statistics() {
  const { history: localHistory = [] } = useScan?.() ?? { history: [] };
  const [serverHistory, setServerHistory] = useState([]);
  const [urlSearch, setUrlSearch] = useState('');

  // Fetch server history for richer data
  useEffect(() => {
    const isAuth = localStorage.getItem('isAuthenticated') === 'true';
    if (!isAuth) return;
    fetch('/api/history', { headers: authHeader() })
      .then(r => r.ok ? r.json() : [])
      .then(items => setServerHistory(items))
      .catch(() => {});
  }, []);

  // Merge local + server history, prefer server data
  const history = useMemo(() => {
    if (serverHistory.length > 0) {
      const merged = [...serverHistory];
      const serverUrls = new Set(serverHistory.map(i => i.url + '|' + i.scannedAt));
      for (const loc of localHistory) {
        const key = loc.url + '|' + (loc.scannedAt || '');
        if (!serverUrls.has(key)) merged.push(loc);
      }
      return merged.sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
    }
    return localHistory;
  }, [localHistory, serverHistory]);

  // last 12 scans; ensure at least one point for initial render
  const last = useMemo(() => (history.length ? history.slice(-12) : [{ riskScore: 0 }]), [history]);
  const labels = useMemo(
    () => (history.length
      ? last.map((e, i) => {
          // Show truncated URL as label, fallback to scan number
          if (e.url) {
            try {
              const u = new URL(e.url.startsWith('http') ? e.url : 'https://' + e.url);
              return u.hostname.length > 18 ? u.hostname.slice(0, 16) + '…' : u.hostname;
            } catch { return e.url.slice(0, 18); }
          }
          return `#${history.length - last.length + i + 1}`;
        })
      : ["—"]),
    [last, history.length]
  );

  // Risk trend line
  const riskSeries = useMemo(
    () => [{ name: "Risk", data: last.map((e) => (Number.isFinite(e.riskScore) ? e.riskScore : 0)) }],
    [last]
  );
  const riskOptions = useMemo(
    () => ({
      chart: { 
        toolbar: { show: false }, 
        animations: { enabled: true, speed: 400 },
        background: 'transparent'
      },
      stroke: { curve: "smooth", width: 3 },
      dataLabels: { enabled: false },
      grid: { 
        borderColor: '#00e5ff22',
        strokeDashArray: 4,
        xaxis: { lines: { show: true } },
        yaxis: { lines: { show: true } }
      },
      xaxis: { 
        categories: labels, 
        tickPlacement: "on",
        labels: { 
          style: { colors: '#00e5ff' }
        }
      },
      yaxis: { 
        min: 0, 
        max: 100, 
        forceNiceScale: true,
        labels: { 
          style: { colors: '#00e5ff' }
        }
      },
      colors: ["#00e5ff"],
      tooltip: {
        theme: 'dark',
        style: {
          fontSize: '12px'
        },
        x: {
          formatter: (val, { dataPointIndex }) => {
            const item = last[dataPointIndex];
            return item?.url || val;
          }
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
        animations: { enabled: true, speed: 400 },
        background: 'transparent'
      },
      plotOptions: { 
        bar: { 
          borderRadius: 6, 
          columnWidth: "45%",
          distributed: false
        } 
      },
      xaxis: { 
        categories: toolOrder,
        labels: { 
          style: { colors: '#00e5ff' }
        }
      },
      yaxis: {
        labels: { 
          style: { colors: '#00e5ff' }
        }
      },
      colors: ["#00e5ff"],
      dataLabels: { enabled: false },
      grid: { 
        borderColor: '#00e5ff22',
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
        animations: { enabled: true, speed: 400 },
        background: 'transparent'
      },
      plotOptions: { 
        bar: { 
          borderRadius: 6, 
          columnWidth: "50%",
          distributed: true
        } 
      },
      xaxis: { 
        categories: bucketLabels,
        labels: { 
          style: { colors: '#00e5ff' }
        }
      },
      yaxis: {
        labels: { 
          style: { colors: '#00e5ff' }
        }
      },
      colors: ["#22c55e", "#84cc16", "#eab308", "#f97316", "#ef4444"],
      dataLabels: { enabled: false },
      grid: { 
        borderColor: '#00e5ff22',
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

  // Filtered URLs for the table
  const filteredUrls = history.filter(h =>
    !urlSearch || h.url?.toLowerCase().includes(urlSearch.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] p-6 transition-colors duration-300">
      {/* Header Section */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <svg className="w-8 h-8 text-[#00e5ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          <h1 className="text-3xl font-bold text-[var(--text-primary)]">
            Security <span className="text-[#00e5ff]">Analytics</span>
          </h1>
        </div>
        <p className="text-gray-600 dark:text-[#00e5ff]/80">Comprehensive insights into your URL security scans</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {/* Total Scans */}
        <div className="bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-xl p-5 shadow-lg transition-all duration-300">
          <div className="flex items-center justify-between mb-2">
            <div className="p-2 bg-[#00e5ff]/10 rounded-lg">
              <svg className="w-5 h-5 text-[#00e5ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
          </div>
          <div className="text-3xl font-bold text-[var(--text-primary)] mb-1">{totalScans}</div>
          <div className="text-sm text-[var(--text-secondary)]">Total Scans</div>
        </div>

        {/* Average Risk */}
        <div className="bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-xl p-5 shadow-lg transition-all duration-300">
          <div className="flex items-center justify-between mb-2">
            <div className="p-2 bg-yellow-100 dark:bg-yellow-500/20 rounded-lg">
              <svg className="w-5 h-5 text-yellow-600 dark:text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
          </div>
          <div className="text-3xl font-bold text-[var(--text-primary)] mb-1">{avgRisk}</div>
          <div className="text-sm text-[var(--text-secondary)]">Average Risk Score</div>
        </div>

        {/* High Risk URLs */}
        <div className="bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-xl p-5 shadow-lg transition-all duration-300">
          <div className="flex items-center justify-between mb-2">
            <div className="p-2 bg-red-100 dark:bg-red-500/20 rounded-lg">
              <svg className="w-5 h-5 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
          <div className="text-3xl font-bold text-[var(--text-primary)] mb-1">{highRiskCount}</div>
          <div className="text-sm text-[var(--text-secondary)]">High Risk URLs</div>
        </div>

        {/* Safe URLs */}
        <div className="bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-xl p-5 shadow-lg transition-all duration-300">
          <div className="flex items-center justify-between mb-2">
            <div className="p-2 bg-green-100 dark:bg-green-500/20 rounded-lg">
              <svg className="w-5 h-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
          <div className="text-3xl font-bold text-[var(--text-primary)] mb-1">{safeCount}</div>
          <div className="text-sm text-[var(--text-secondary)]">Safe URLs</div>
        </div>
      </div>

      {/* Scanned URLs Table */}
      <div className="bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-xl shadow-lg overflow-hidden transition-all duration-300 mb-6">
        <div className="p-5 border-b border-gray-200 dark:border-[#333] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-[#00e5ff] animate-pulse"></div>
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">Scanned URLs</h3>
            <span className="text-xs text-[var(--text-secondary)] ml-1">({filteredUrls.length} URLs)</span>
          </div>
          <input
            type="text"
            value={urlSearch}
            onChange={e => setUrlSearch(e.target.value)}
            placeholder="Search URLs…"
            className="px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-[#0e0e0e] text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-[#00e5ff] focus:outline-none w-full sm:w-64"
          />
        </div>
        <div className="overflow-x-auto">
          {filteredUrls.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-32 text-gray-400">
              <span className="text-2xl mb-1">🔍</span>
              <p className="text-sm">{urlSearch ? 'No URLs match your search.' : 'No scans yet — run your first scan!'}</p>
            </div>
          ) : (
            <table className="w-full min-w-max">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">URL</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Risk</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Class</th>
                  <th className="hidden sm:table-cell px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Scanned</th>
                </tr>
              </thead>
              <tbody>
                {filteredUrls.slice(0, 50).map((h, i) => (
                  <tr key={i} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors">
                    <td className="px-4 py-2.5 max-w-[200px]">
                      <span className="font-mono text-xs text-gray-900 dark:text-white truncate block" title={h.url}>{h.url}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-lg font-bold ${classColor(h.classification)}`}>{h.riskScore ?? '—'}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-semibold ${badge(h.classification)} uppercase tracking-widest`}>
                        {h.classification ?? '—'}
                      </span>
                    </td>
                    <td className="hidden sm:table-cell px-4 py-2.5 text-xs text-gray-500 dark:text-gray-400">
                      {h.scannedAt ? new Date(h.scannedAt).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
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
          <div className="bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-xl shadow-lg overflow-hidden transition-all duration-300">
            <div className="p-5 border-b border-gray-200 dark:border-[#333]">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-[#00e5ff] animate-pulse"></div>
                <h3 className="text-lg font-semibold text-[var(--text-primary)]">Risk Trend</h3>
              </div>
              <p className="text-xs text-[var(--text-secondary)] mt-1">Last {last.length} scans</p>
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
          <div className="bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-xl shadow-lg overflow-hidden transition-all duration-300">
            <div className="p-5 border-b border-gray-200 dark:border-[#333]">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-[#00e5ff] animate-pulse"></div>
                <h3 className="text-lg font-semibold text-[var(--text-primary)]">Tool Findings Distribution</h3>
              </div>
              <p className="text-xs text-[var(--text-secondary)] mt-1">Cumulative findings across all scans</p>
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
          <div className="bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-xl shadow-lg overflow-hidden transition-all duration-300">
            <div className="p-5 border-b border-gray-200 dark:border-[#333]">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-[#00e5ff] animate-pulse"></div>
                <h3 className="text-lg font-semibold text-[var(--text-primary)]">Risk Score Distribution</h3>
              </div>
              <p className="text-xs text-[var(--text-secondary)] mt-1">URLs categorized by risk level</p>
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