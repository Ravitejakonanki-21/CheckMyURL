import { useState, useEffect, useCallback } from 'react';

const API = '';

const SEVERITY_COLORS = {
    CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
    HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
    MEDIUM: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
    LOW: 'bg-[#00e5ff]/10 text-[#00e5ff] dark:bg-[#00e5ff]/20 dark:text-[#00e5ff]',
};

const STATE_COLORS = {
    SCANNED: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
    UNDER_REVIEW: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
    ESCALATED: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
    CLOSED: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
    CONFIRMED_PHISHING: 'bg-red-200 text-red-800 dark:bg-red-900/60 dark:text-red-200',
    FALSE_POSITIVE: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
};

function authHeader() {
    const token = localStorage.getItem('access_token') || localStorage.getItem('token');
    return token ? { Authorization: `Bearer ${token}` } : {};
}

async function socApi(method, path, body) {
    const res = await fetch(`/api/soc${path}`, {
        method,
        headers: { 'Content-Type': 'application/json', ...authHeader() },
        body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || errData.reason || `${res.status} ${res.statusText}`);
    }
    return res.json();
}

// ---------- Report Modal ----------
function ReportModal({ scan, onClose, onDone }) {
    const [verdict, setVerdict] = useState('CONFIRMED_PHISHING');
    const [notes, setNotes] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const submit = async () => {
        setLoading(true); setError('');
        try {
            await socApi('POST', `/scans/${scan._id}/report`, { verdict, notes });
            onDone();
        } catch (e) { setError(e.message); }
        finally { setLoading(false); }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-2xl shadow-2xl p-8 w-full max-w-md">
                <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-1">Submit Threat Report</h3>
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-6 truncate">{scan.url}</p>

                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Verdict</label>
                <select
                    value={verdict}
                    onChange={e => setVerdict(e.target.value)}
                    className="w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white px-3 py-2 mb-4 text-sm"
                >
                    <option value="CONFIRMED_PHISHING">Confirmed Phishing</option>
                    <option value="FALSE_POSITIVE">False Positive</option>
                </select>

                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Notes</label>
                <textarea
                    rows={3}
                    value={notes}
                    onChange={e => setNotes(e.target.value)}
                    placeholder="Evidence, analysis notes…"
                    className="w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white px-3 py-2 mb-4 text-sm resize-none"
                />

                {error && <p className="text-red-500 text-sm mb-3">{error}</p>}

                <div className="flex gap-3 justify-end">
                    <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800">Cancel</button>
                    <button
                        onClick={submit}
                        disabled={loading}
                        className="px-5 py-2 rounded-lg bg-[#00e5ff] hover:bg-[#00ccf0] text-[#0e0e0e] text-sm font-semibold disabled:opacity-60"
                    >
                        {loading ? 'Submitting…' : 'Submit Report'}
                    </button>
                </div>
            </div>
        </div>
    );
}

// ---------- Queue Row ----------
function QueueRow({ scan, onRefresh }) {
    const [loading, setLoading] = useState('');
    const [actionError, setActionError] = useState('');
    const [reportTarget, setReportTarget] = useState(null);

    const act = async (action) => {
        setLoading(action); setActionError('');
        try {
            await socApi('POST', `/scans/${scan._id}/${action}`, {});
            onRefresh();
        } catch (e) {
            setActionError(e.message || 'Action failed');
        } finally { setLoading(''); }
    };

    const severity = scan.risk?.severity_level ?? '—';
    const score = scan.risk?.total_score ?? '—';
    const state = scan.state ?? '—';

    return (
        <>
            <tr className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                {/* URL */}
                <td className="px-4 py-3 max-w-xs">
                    <span className="text-sm text-gray-900 dark:text-white font-mono truncate block" title={scan.url}>{scan.url}</span>
                    <span className="text-xs text-gray-400">{new Date(scan.submitted_at).toLocaleString()}</span>
                </td>
                {/* Score */}
                <td className="px-4 py-3 text-center">
                    <span className="text-2xl font-bold" style={{ color: score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#22c55e' }}>
                        {score}
                    </span>
                </td>
                {/* Severity */}
                <td className="px-4 py-3 text-center">
                    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold ${SEVERITY_COLORS[severity] ?? 'bg-gray-100 text-gray-600'}`}>
                        {severity}
                    </span>
                </td>
                {/* State */}
                <td className="px-4 py-3 text-center">
                    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold ${STATE_COLORS[state] ?? 'bg-gray-100 text-gray-600'}`}>
                        {state.replace('_', ' ')}
                    </span>
                </td>
                {/* Actions */}
                <td className="px-4 py-3">
                    <div className="flex items-center gap-2 flex-wrap">
                        {state === 'SCANNED' && (
                            <button
                                onClick={() => act('review')}
                                disabled={!!loading}
                                className="px-3 py-1 text-xs rounded-lg bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300 hover:bg-purple-200 disabled:opacity-50 font-medium"
                            >
                                {loading === 'review' ? '…' : 'Review'}
                            </button>
                        )}
                        {state === 'UNDER_REVIEW' && (
                            <button
                                onClick={() => act('escalate')}
                                disabled={!!loading}
                                className="px-3 py-1 text-xs rounded-lg bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300 hover:bg-red-200 disabled:opacity-50 font-medium"
                            >
                                {loading === 'escalate' ? '…' : 'Escalate'}
                            </button>
                        )}
                        <button
                            onClick={() => setReportTarget(scan)}
                            className="px-3 py-1 text-xs rounded-lg bg-[#00e5ff]/10 text-[#00e5ff] dark:bg-[#00e5ff]/20 dark:text-[#00e5ff] hover:bg-[#00e5ff]/30 font-medium"
                        >
                            Report
                        </button>
                        <button
                            onClick={() => act('false-positive')}
                            disabled={!!loading}
                            className="px-3 py-1 text-xs rounded-lg bg-gray-100 text-gray-600 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-400 disabled:opacity-50 font-medium"
                        >
                            {loading === 'false-positive' ? '…' : 'False Positive'}
                        </button>
                    </div>
                </td>
            </tr>
            {actionError && (
                <tr>
                    <td colSpan={5} className="px-4 py-2">
                        <p className="text-xs text-red-500 bg-red-50 dark:bg-red-900/20 rounded-lg px-3 py-1.5">
                            ⚠️ {actionError}
                        </p>
                    </td>
                </tr>
            )}

            {reportTarget && (
                <ReportModal
                    scan={reportTarget}
                    onClose={() => setReportTarget(null)}
                    onDone={() => { setReportTarget(null); onRefresh(); }}
                />
            )}
        </>
    );
}

// ---------- Main Page ----------
export default function SOCDashboard() {
    const [queue, setQueue] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const fetchQueue = useCallback(async () => {
        setLoading(true); setError('');
        try {
            const data = await socApi('GET', '/queue');
            setQueue(data);
        } catch (e) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchQueue(); }, [fetchQueue]);

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-950 px-4 py-10">
            <div className="max-w-7xl mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                            🛡️ SOC <span className="text-[#00e5ff]">Dashboard</span>
                        </h1>
                        <p className="text-gray-500 dark:text-gray-400 mt-1">Review and triage suspicious URL scans</p>
                    </div>
                    <button
                        onClick={fetchQueue}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#00e5ff] hover:bg-[#00ccf0] text-[#0e0e0e] text-sm font-semibold"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                        Refresh
                    </button>
                </div>

                {/* Summary badges */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                    {[
                        { label: 'Total in Queue', value: queue.length, color: 'text-blue-500' },
                        { label: 'Under Review', value: queue.filter(s => s.state === 'UNDER_REVIEW').length, color: 'text-purple-500' },
                        { label: 'Escalated', value: queue.filter(s => s.state === 'ESCALATED').length, color: 'text-red-500' },
                        { label: 'High / Critical', value: queue.filter(s => ['HIGH', 'CRITICAL'].includes(s.risk?.severity_level)).length, color: 'text-orange-500' },
                    ].map((c, i) => (
                        <div key={i} className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
                            <p className={`text-3xl font-bold ${c.color}`}>{c.value}</p>
                            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{c.label}</p>
                        </div>
                    ))}
                </div>

                {/* Table */}
                <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl overflow-hidden shadow-sm">
                    {loading ? (
                        <div className="flex items-center justify-center h-48 text-gray-400">Loading queue…</div>
                    ) : error ? (
                        <div className="flex items-center justify-center h-48 text-red-500">{error}</div>
                    ) : queue.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                            <span className="text-4xl mb-2">✅</span>
                            <p>Queue is empty — no scans awaiting review</p>
                        </div>
                    ) : (
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">URL</th>
                                    <th className="px-4 py-3 text-center text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Risk</th>
                                    <th className="px-4 py-3 text-center text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Severity</th>
                                    <th className="px-4 py-3 text-center text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">State</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {queue.map(scan => (
                                    <QueueRow key={scan._id} scan={scan} onRefresh={fetchQueue} />
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </div>
        </div>
    );
}
