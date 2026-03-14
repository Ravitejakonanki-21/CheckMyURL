import { useState, useRef } from 'react';

const API = '/';

function authHeader() {
    const token = localStorage.getItem('access_token') || localStorage.getItem('token');
    return token ? { Authorization: `Bearer ${token}` } : {};
}

const CLASSIFICATION_STYLES = {
    safe: { text: 'Safe', color: 'text-[#00e5ff]', badge: 'bg-[#00e5ff]/10 text-[#00e5ff] border border-[#00e5ff]/20' },
    low: { text: 'Low Risk', color: 'text-[#00e5ff]', badge: 'bg-[#00e5ff]/10 text-[#00e5ff] border border-[#00e5ff]/20' },
    medium: { text: 'Medium Risk', color: 'text-yellow-500', badge: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300' },
    suspicious: { text: 'Suspicious', color: 'text-yellow-500', badge: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300' },
    high: { text: 'High Risk', color: 'text-red-500', badge: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' },
    critical: { text: 'Critical', color: 'text-red-600', badge: 'bg-red-200 text-red-800 dark:bg-red-900/60 dark:text-red-200' },
};

function getStyle(label = '') {
    const key = label.toLowerCase().replace(/\s+/g, '');
    return Object.entries(CLASSIFICATION_STYLES).find(([k]) => key.includes(k))?.[1]
        ?? { text: label, color: 'text-gray-500', badge: 'bg-gray-100 text-gray-600' };
}

function ResultRow({ item, index }) {
    const style = getStyle(item.label || '');
    const score = item.score ?? '—';
    return (
        <tr className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/40">
            <td className="px-4 py-3 text-sm font-mono text-gray-600 dark:text-gray-400">{index + 1}</td>
            <td className="px-4 py-3 max-w-xs">
                <span className="text-sm text-gray-900 dark:text-white truncate block font-mono" title={item.url}>{item.url}</span>
            </td>
            <td className="px-4 py-3 text-center">
                {item.status === 'scanning' ? (
                    <span className="inline-flex items-center gap-1 text-xs text-cyan-500">
                        <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                        </svg>
                        Scanning…
                    </span>
                ) : item.status === 'error' ? (
                    <span className="text-xs text-red-500">{item.error || 'Error'}</span>
                ) : (
                    <span className={`text-xl font-bold ${style.color}`}>{score}</span>
                )}
            </td>
            <td className="px-4 py-3 text-center">
                {item.status === 'done' && (
                    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold ${style.badge}`}>
                        {item.label}
                    </span>
                )}
            </td>
            <td className="px-4 py-3 text-xs text-gray-500 dark:text-gray-400 max-w-xs">
                {item.status === 'done' && (item.reasons || []).slice(0, 2).map((r, i) => (
                    <div key={i} className="truncate">• {r}</div>
                ))}
            </td>
        </tr>
    );
}

export default function BulkScan() {
    const [input, setInput] = useState('');
    const [results, setResults] = useState([]);
    const [scanning, setScanning] = useState(false);
    const [progress, setProgress] = useState(0);
    const abortRef = useRef(false);

    const parseUrls = (text) =>
        text.split(/[\n,]+/)
            .map(u => u.trim())
            .filter(u => u.length > 0);

    const startScan = async () => {
        const urls = parseUrls(input);
        if (urls.length === 0) return;
        if (urls.length > 50) { alert('Maximum 50 URLs per bulk scan.'); return; }

        abortRef.current = false;
        setScanning(true);
        setProgress(0);

        const initial = urls.map(url => ({ url, status: 'scanning', score: null, label: '', reasons: [], error: '' }));
        setResults(initial);

        for (let i = 0; i < urls.length; i++) {
            if (abortRef.current) break;
            const url = urls[i];
            try {
                const res = await fetch(`${API}/analyze`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', ...authHeader() },
                    body: JSON.stringify({ url }),
                });
                const data = await res.json();
                setResults(prev => prev.map((r, idx) =>
                    idx === i
                        ? {
                            ...r,
                            status: 'done',
                            score: data.riskScore ?? data.score ?? 0,
                            label: data.classification ?? data.label ?? 'Unknown',
                            reasons: data.reasons || data.explanation || [],
                        }
                        : r
                ));
            } catch (e) {
                setResults(prev => prev.map((r, idx) =>
                    idx === i ? { ...r, status: 'error', error: e.message } : r
                ));
            }
            setProgress(Math.round(((i + 1) / urls.length) * 100));
        }

        setScanning(false);
    };

    const stop = () => { abortRef.current = true; };

    const done = results.filter(r => r.status === 'done');
    const safe = done.filter(r => (r.score ?? 0) < 40).length;
    const medium = done.filter(r => (r.score ?? 0) >= 40 && (r.score ?? 0) < 70).length;
    const high = done.filter(r => (r.score ?? 0) >= 70).length;

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-950 px-4 py-10">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                        🔍 Bulk <span className="text-[#00e5ff]">URL Scanner</span>
                    </h1>
                    <p className="text-gray-500 dark:text-gray-400 mt-1">
                        Scan up to 50 URLs at once — paste one per line or comma-separated
                    </p>
                </div>

                {/* Input area */}
                <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-6 mb-6 shadow-sm">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        URLs to scan <span className="text-gray-400 font-normal">(one per line or comma-separated)</span>
                    </label>
                    <textarea
                        value={input}
                        onChange={e => setInput(e.target.value)}
                        rows={6}
                        placeholder={'https://example.com\nhttps://suspicious-site.xyz\nhttps://anotherurl.com'}
                        className="w-full rounded-xl border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white px-4 py-3 font-mono text-sm focus:ring-2 focus:ring-[#00e5ff] focus:outline-none resize-vertical"
                        disabled={scanning}
                    />
                    <div className="flex items-center justify-between mt-4 flex-wrap gap-3">
                        <span className="text-sm text-gray-400">{parseUrls(input).length} URL{parseUrls(input).length !== 1 ? 's' : ''} detected</span>
                        <div className="flex gap-3">
                            {scanning && (
                                <button
                                    onClick={stop}
                                    className="px-4 py-2 rounded-lg border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 hover:bg-red-50 text-sm font-medium"
                                >
                                    Stop
                                </button>
                            )}
                            <button
                                onClick={scanning ? undefined : startScan}
                                disabled={scanning || parseUrls(input).length === 0}
                                className="px-6 py-2 rounded-lg bg-[#00e5ff] hover:bg-[#00ccf0] text-[#0e0e0e] text-sm font-semibold disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                            >
                                {scanning ? (
                                    <>
                                        <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                                        </svg>
                                        Scanning {progress}%
                                    </>
                                ) : '🚀 Start Bulk Scan'}
                            </button>
                        </div>
                    </div>

                    {/* Progress bar */}
                    {scanning && (
                        <div className="mt-4 w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div
                                className="bg-[#00e5ff] h-2 rounded-full transition-all duration-300"
                                style={{ width: `${progress}%` }}
                            />
                        </div>
                    )}
                </div>

                {/* Summary cards */}
                {results.length > 0 && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                        {[
                            { label: 'Total', value: results.length, color: 'text-blue-500' },
                            { label: 'Safe', value: safe, color: 'text-[#00e5ff]' },
                            { label: 'Medium', value: medium, color: 'text-yellow-500' },
                            { label: 'High Risk', value: high, color: 'text-red-500' },
                        ].map((c, i) => (
                            <div key={i} className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
                                <p className={`text-3xl font-bold ${c.color}`}>{c.value}</p>
                                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{c.label}</p>
                            </div>
                        ))}
                    </div>
                )}

                {/* Results table */}
                {results.length > 0 && (
                    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl overflow-hidden shadow-sm">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                                    {['#', 'URL', 'Risk Score', 'Classification', 'Key Findings'].map(h => (
                                        <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {results.map((item, i) => <ResultRow key={i} item={item} index={i} />)}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}
