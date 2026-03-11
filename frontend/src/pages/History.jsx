import { useState, useEffect } from 'react';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

const API = 'http://127.0.0.1:5001';

function authHeader() {
    const token = localStorage.getItem('access_token') || localStorage.getItem('token');
    return token ? { Authorization: `Bearer ${token}` } : {};
}

function classColor(cls = '') {
    const c = cls.toUpperCase();
    if (c.includes('HIGH') || c.includes('CRITICAL') || c.includes('PHISH')) return 'text-red-500';
    if (c.includes('MEDIUM') || c.includes('SUSPICIOUS')) return 'text-yellow-500';
    return 'text-green-500';
}

function badge(cls = '') {
    const c = cls.toUpperCase();
    if (c.includes('HIGH') || c.includes('CRITICAL') || c.includes('PHISH'))
        return 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300';
    if (c.includes('MEDIUM') || c.includes('SUSPICIOUS'))
        return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300';
    return 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300';
}

function exportHistoryPDF(items) {
    const doc = new jsPDF({ unit: 'pt', format: 'a4' });
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.text('CheckMyURL — Scan History Report', 40, 40);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 40, 60);

    autoTable(doc, {
        startY: 80,
        head: [['URL', 'Risk Score', 'Classification', 'Scanned At']],
        body: items.map(h => [
            h.url,
            h.riskScore ?? '—',
            h.classification ?? '—',
            h.scannedAt ? new Date(h.scannedAt).toLocaleString() : '—',
        ]),
        styles: { fontSize: 9, cellPadding: 5 },
        headStyles: { fillColor: [8, 145, 178] },
        theme: 'grid',
        margin: { left: 40, right: 40 },
        columnStyles: { 0: { cellWidth: 240 } },
    });

    doc.save(`scan-history-${Date.now()}.pdf`);
}

export default function History() {
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [search, setSearch] = useState('');

    useEffect(() => {
        const isAuth = localStorage.getItem('isAuthenticated') === 'true';
        if (!isAuth) { setLoading(false); setError('Please log in to view history.'); return; }

        const localHistory = JSON.parse(localStorage.getItem('cmu_scan_history') || '[]');

        // Try to also fetch from backend
        fetch(`${API}/api/history`, { headers: authHeader() })
            .then(r => r.ok ? r.json() : [])
            .then(serverItems => {
                // Merge: server items take precedence; de-dup by url+scannedAt
                const merged = [...serverItems];
                const serverUrls = new Set(serverItems.map(i => i.url + '|' + i.scannedAt));
                for (const loc of localHistory) {
                    const key = loc.url + '|' + (loc.scannedAt || '');
                    if (!serverUrls.has(key)) merged.push(loc);
                }
                merged.sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
                setHistory(merged);
            })
            .catch(() => {
                // Fall back to localStorage only
                const sorted = [...localHistory].sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
                setHistory(sorted);
            })
            .finally(() => setLoading(false));
    }, []);

    const filtered = history.filter(h =>
        !search || h.url?.toLowerCase().includes(search.toLowerCase())
    );

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-950 px-4 py-10">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-8 flex-wrap gap-4">
                    <div>
                        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                            📋 Scan <span className="text-cyan-500">History</span>
                        </h1>
                        <p className="text-gray-500 dark:text-gray-400 mt-1">
                            {history.length} scan{history.length !== 1 ? 's' : ''} recorded
                        </p>
                    </div>
                    <div className="flex gap-3">
                        <button
                            onClick={() => exportHistoryPDF(filtered)}
                            disabled={filtered.length === 0}
                            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-white text-sm font-semibold"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                            Export PDF
                        </button>
                        <button
                            onClick={() => { localStorage.removeItem('scanHistory'); setHistory([]); }}
                            disabled={history.length === 0}
                            className="px-4 py-2 rounded-lg border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 text-sm font-medium disabled:opacity-40"
                        >
                            Clear History
                        </button>
                    </div>
                </div>

                {/* Search */}
                <div className="mb-4">
                    <input
                        type="text"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        placeholder="Search by URL…"
                        className="w-full max-w-sm px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-cyan-500 focus:outline-none"
                    />
                </div>

                {/* Table */}
                <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl overflow-hidden shadow-sm">
                    {loading ? (
                        <div className="flex items-center justify-center h-48 text-gray-400">Loading history…</div>
                    ) : error ? (
                        <div className="flex items-center justify-center h-48 text-red-500">{error}</div>
                    ) : filtered.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                            <span className="text-4xl mb-2">🔍</span>
                            <p>{search ? 'No results match your search.' : 'No scans yet — run your first URL check!'}</p>
                        </div>
                    ) : (
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                                    {['URL', 'Risk Score', 'Classification', 'Scanned At'].map(h => (
                                        <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map((h, i) => (
                                    <tr key={i} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors">
                                        <td className="px-4 py-3 max-w-xs">
                                            <span className="font-mono text-sm text-gray-900 dark:text-white truncate block" title={h.url}>{h.url}</span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`text-2xl font-bold ${classColor(h.classification)}`}>
                                                {h.riskScore ?? '—'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold ${badge(h.classification)}`}>
                                                {h.classification ?? '—'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
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
