import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

import { API_BASE_URL } from '../config/api';
const API = API_BASE_URL;

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

function exportHistoryPDF(items) {
    const doc = new jsPDF({ unit: 'pt', format: 'a4' });
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.text('CYBERSHIELD — Scan History Report', 40, 40);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 40, 60);

    autoTable(doc, {
        startY: 80,
        head: [['URL', 'Risk Score', 'Classification', 'User', 'Scanned At']],
        body: items.map(h => [
            h.url,
            h.riskScore ?? '—',
            h.classification ?? '—',
            h.userEmail ?? '—',
            h.scannedAt ? new Date(h.scannedAt).toLocaleString() : '—',
        ]),
        styles: { fontSize: 9, cellPadding: 5 },
        headStyles: { fillColor: [0, 229, 255] },
        theme: 'grid',
        margin: { left: 40, right: 40 },
        columnStyles: { 0: { cellWidth: 200 } },
    });

    doc.save(`scan-history-${Date.now()}.pdf`);
}

// Mini stats bar component
function StatsBar({ items }) {
    const totalScans = items.length;
    const avgRisk = totalScans
        ? Math.round(items.reduce((sum, e) => sum + (e.riskScore || 0), 0) / totalScans)
        : 0;
    const highRiskCount = items.filter(e => (e.riskScore || 0) >= 70).length;
    const safeCount = items.filter(e => (e.riskScore || 0) < 40).length;

    const stats = [
        { label: 'Total Scans', value: totalScans, icon: '🔍', color: 'text-[#00e5ff]' },
        { label: 'Avg Risk', value: avgRisk, icon: '⚡', color: avgRisk >= 70 ? 'text-red-500' : avgRisk >= 40 ? 'text-yellow-500' : 'text-green-500' },
        { label: 'High Risk', value: highRiskCount, icon: '⚠️', color: 'text-red-500' },
        { label: 'Safe', value: safeCount, icon: '✅', color: 'text-green-500' },
    ];

    return (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
            {stats.map((s, i) => (
                <div key={i} className="bg-white dark:bg-[#181818] border border-gray-200 dark:border-[#333] rounded-xl p-4 shadow-sm transition-all duration-300 hover:shadow-md">
                    <div className="flex items-center gap-2 mb-1">
                        <span className="text-lg">{s.icon}</span>
                        <span className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wider font-semibold">{s.label}</span>
                    </div>
                    <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                </div>
            ))}
        </div>
    );
}

export default function History() {
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [search, setSearch] = useState('');
    const [allHistory, setAllHistory] = useState([]);
    const [allError, setAllError] = useState('');   // separate error for admin history fetch

    const [userFilter, setUserFilter] = useState('');
    const isAdmin = (localStorage.getItem('role') ?? 'USER').toUpperCase() === 'ADMIN';
    const navigate = useNavigate();
    // Admin defaults to 'all'; regular users default to 'my'
    const [viewMode, setViewMode] = useState(isAdmin ? 'all' : 'my');
    // allLoading starts true for admin to prevent empty-table flash on mount
    const [allLoading, setAllLoading] = useState(isAdmin);

    // Helper to fetch admin history — extracted so we can call it from a Retry button
    const fetchAllHistory = () => {
        setAllError('');
        setAllLoading(true);
        fetch(`${API}/api/admin/history`, { headers: authHeader() })
            .then(r => {
                if (r.status === 401) throw new Error('Session expired — please log out and log back in.');
                if (r.status === 403) throw new Error('Access denied (403) — your JWT has the wrong role. Please log out and log back in to get a fresh token with ADMIN role.');
                if (!r.ok) throw new Error(`Server error ${r.status} — the backend may still be starting up. Click Retry in 30 seconds.`);
                return r.json();
            })
            .then(items => {
                const localHistory = JSON.parse(localStorage.getItem('cmu_scan_history') || '[]');
                const merged = [...items];
                const serverUrls = new Set(items.map(i => i.url + '|' + (i.scannedAt || '')));
                
                for (const loc of localHistory) {
                    const key = loc.url + '|' + (loc.scannedAt || '');
                    if (!serverUrls.has(key)) {
                        const locItem = { ...loc };
                        if (!locItem.userEmail) {
                            locItem.userEmail = 'Anonymous (Local)'; // Mark unassigned local scans clearly
                        }
                        merged.push(locItem);
                    }
                }
                merged.sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
                setAllHistory(merged);
            })
            .catch(e => {
                const msg = e.message || '';
                if (msg.includes('Load failed') || msg.includes('Failed to fetch') || msg.includes('NetworkError')) {
                    setAllError('Cannot reach the backend server. It may still be starting up on Render (free tier takes ~60s). Click Retry in a moment.');
                } else {
                    setAllError(msg);
                }
            })
            .finally(() => setAllLoading(false));
    };


    useEffect(() => {
        const isAuth = localStorage.getItem('isAuthenticated') === 'true';
        if (!isAuth) { setLoading(false); setError('Please log in to view history.'); return; }

        const localHistory = JSON.parse(localStorage.getItem('cmu_scan_history') || '[]');

        // Fetch user's own history from backend
        fetch(`${API}/api/history`, { headers: authHeader() })
            .then(r => r.ok ? r.json() : [])
            .then(serverItems => {
                const merged = [...serverItems];
                const serverUrls = new Set(serverItems.map(i => i.url + '|' + i.scannedAt));
                const currentEmail = localStorage.getItem('email');
                for (const loc of localHistory) {
                    const key = loc.url + '|' + (loc.scannedAt || '');
                    if (!serverUrls.has(key) && (!loc.userEmail || loc.userEmail === currentEmail)) {
                        merged.push(loc);
                    }
                }
                merged.sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
                setHistory(merged);
            })
            .catch(() => {
                const currentEmail = localStorage.getItem('email');
                const filteredLocal = localHistory.filter(loc => !loc.userEmail || loc.userEmail === currentEmail);
                const sorted = [...filteredLocal].sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
                setHistory(sorted);
            })
            .finally(() => setLoading(false));
    }, []);

    // Fetch all users' history (admin only)
    // Runs on mount (admin defaults to 'all') and whenever viewMode flips to 'all'
    // Also clears any stale error from the personal-history fetch
    useEffect(() => {
        if (!isAdmin) return;
        if (viewMode !== 'all') return;
        setError('');   // clear personal-history error
        fetchAllHistory();

    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [viewMode]);

    // 'my' → own scans (history), 'all' → every user's scans (allHistory)
    const activeHistory = viewMode === 'my' ? history : allHistory;
    const activeLoading = viewMode === 'my' ? loading : allLoading;
    const activeError   = viewMode === 'my' ? error   : allError;


    // Get unique users from all history
    const uniqueUsers = [...new Set(allHistory.map(h => h.userEmail).filter(Boolean))];

    const filtered = activeHistory.filter(h => {
        const matchSearch = !search || h.url?.toLowerCase().includes(search.toLowerCase());
        const matchUser = !userFilter || h.userEmail === userFilter;
        return matchSearch && matchUser;
    });

    return (
        <div className="min-h-screen bg-[var(--bg-primary)] px-4 py-10 transition-colors duration-300">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
                    <div>
                        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                            📋 {isAdmin ? "All User " : "Scan "}<span className="text-[#00e5ff]">History</span>
                        </h1>
                        <p className="text-gray-500 dark:text-gray-400 mt-1">
                            {filtered.length} scan{filtered.length !== 1 ? 's' : ''} recorded
                            {viewMode === 'all' && ' (all users)'}
                        </p>
                    </div>
                    <div className="flex gap-3 flex-wrap">
                        {/* Admin view toggle removed; admins permanently see all user history */}
                        <button
                            onClick={() => exportHistoryPDF(filtered)}
                            disabled={filtered.length === 0}
                            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#00e5ff] hover:bg-[#00ccf0] disabled:opacity-50 text-[#0e0e0e] text-sm font-semibold"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                            Export PDF
                        </button>
                        <button
                            onClick={() => {
                                localStorage.removeItem('cmu_scan_history');
                                if (viewMode === 'my') {
                                    setHistory(prev => prev.filter(h => h.scanId));
                                } else {
                                    setAllHistory(prev => prev.filter(h => h.scanId));
                                }
                            }}
                            disabled={activeHistory.length === 0}
                            title="Clear local browser history"
                            className="px-4 py-2 rounded-lg border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                            Clear History
                        </button>
                        <button
                            onClick={() => navigate('/statistics')}
                            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#00e5ff] text-[#00e5ff] text-sm font-semibold hover:bg-[#00e5ff]/10 transition-colors"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                            </svg>
                            📊 View Statistics
                        </button>
                    </div>
                </div>

                {/* Stats Bar */}
                <StatsBar items={filtered} />

                {/* Search + User Filter */}
                <div className="flex flex-wrap gap-3 mb-4">
                    <input
                        type="text"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        placeholder="Search by URL…"
                        className="flex-1 min-w-[200px] max-w-sm px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-[#00e5ff] focus:outline-none"
                    />
                    {viewMode === 'all' && uniqueUsers.length > 0 && (
                        <select
                            value={userFilter}
                            onChange={e => setUserFilter(e.target.value)}
                            className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-[#00e5ff] focus:outline-none"
                        >
                            <option value="">All Users</option>
                            {uniqueUsers.map(u => (
                                <option key={u} value={u}>{u}</option>
                            ))}
                        </select>
                    )}
                </div>

                {/* Table */}
                <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl overflow-x-auto shadow-sm">
                    {activeLoading ? (
                        <div className="flex items-center justify-center h-48 text-gray-400">Loading history…</div>
                    ) : activeError ? (
                        <div className="flex flex-col items-center justify-center h-48 gap-4 px-6 text-center">
                            <span className="text-3xl">⚠️</span>
                            <p className="text-red-500 text-sm max-w-md">{activeError}</p>
                            <button
                                onClick={viewMode === 'all' ? fetchAllHistory : undefined}
                                className="px-4 py-2 rounded-lg bg-[#00e5ff]/10 text-[#00e5ff] hover:bg-[#00e5ff]/20 text-sm font-medium"
                            >
                                🔄 Retry
                            </button>
                        </div>

                    ) : filtered.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                            <span className="text-4xl mb-2">🔍</span>
                            <p>{search ? 'No results match your search.' : 'No scans yet — run your first URL check!'}</p>
                        </div>
                    ) : (
                        <table className="w-full min-w-max">
                            <thead>
                                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">URL</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Risk Score</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Classification</th>
                                    {viewMode === 'all' && (
                                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">User</th>
                                    )}
                                    <th className="hidden sm:table-cell px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Scanned At</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map((h, i) => (
                                    <tr key={i} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors">
                                        <td className="px-4 py-3 max-w-[120px] sm:max-w-xs">
                                            <span className="font-mono text-xs sm:text-sm text-gray-900 dark:text-white truncate block" title={h.url}>{h.url}</span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`text-xl sm:text-2xl font-bold ${classColor(h.classification)}`}>
                                                {h.riskScore ?? '—'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`inline-block px-2 py-0.5 rounded-full text-[10px] sm:text-xs font-semibold ${badge(h.classification)} uppercase tracking-widest`}>
                                                {h.classification ?? '—'}
                                            </span>
                                        </td>
                                        {viewMode === 'all' && (
                                            <td className="px-4 py-3">
                                                <span className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 truncate block max-w-[150px]" title={h.userEmail}>
                                                    {h.userEmail ?? '—'}
                                                </span>
                                            </td>
                                        )}
                                        <td className="hidden sm:table-cell px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                                            {h.scannedAt ? new Date(h.scannedAt).toLocaleString() : '—'}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </div>
        </div>
    );
}
