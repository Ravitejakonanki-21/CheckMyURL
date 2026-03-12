import { useState, useEffect, useCallback } from 'react';

const API = '/';

function authHeader() {
    const token = localStorage.getItem('access_token');
    return token ? { Authorization: `Bearer ${token}` } : {};
}

async function adminApi(method, path, body) {
    const res = await fetch(`${API}/api/admin${path}`, {
        method,
        headers: { 'Content-Type': 'application/json', ...authHeader() },
        body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
}

const ROLES = ['USER', 'ANALYST', 'MANAGER', 'ADMIN'];

// ── Users Tab ────────────────────────────────────────────────────────────────
function UsersTab() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [saving, setSaving] = useState({});

    useEffect(() => {
        setLoading(true);
        adminApi('GET', '/users')
            .then(setUsers)
            .catch(e => setError(e.message))
            .finally(() => setLoading(false));
    }, []);

    const changeRole = async (userId, newRole) => {
        setSaving(s => ({ ...s, [userId]: true }));
        try {
            await adminApi('PATCH', `/users/${userId}/role`, { role: newRole });
            setUsers(prev => prev.map(u => u._id === userId ? { ...u, role: newRole } : u));
        } catch (e) {
            alert(`Failed: ${e.message}`);
        } finally {
            setSaving(s => ({ ...s, [userId]: false }));
        }
    };

    if (loading) return <div className="flex items-center justify-center h-48 text-gray-400">Loading users…</div>;
    if (error) return <div className="text-red-500 p-4">{error}</div>;

    return (
        <div className="overflow-x-auto">
            <table className="w-full">
                <thead>
                    <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                        {['Email', 'Role', 'Credits', 'Status', 'Created'].map(h => (
                            <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">{h}</th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {users.map(u => (
                        <tr key={u._id} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors">
                            <td className="px-4 py-3 text-sm text-gray-900 dark:text-white font-medium">{u.email}</td>
                            <td className="px-4 py-3">
                                <select
                                    value={u.role}
                                    onChange={e => changeRole(u._id, e.target.value)}
                                    disabled={saving[u._id]}
                                    className="text-xs rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white px-2 py-1 disabled:opacity-60"
                                >
                                    {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                                </select>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">{u.credits ?? '—'}</td>
                            <td className="px-4 py-3">
                                <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold ${u.status === 'active' ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-gray-100 text-gray-500'}`}>
                                    {u.status ?? 'active'}
                                </span>
                            </td>
                            <td className="px-4 py-3 text-xs text-gray-500 dark:text-gray-400">
                                {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
            {users.length === 0 && <div className="text-center py-12 text-gray-400">No users found.</div>}
        </div>
    );
}

// ── Audit Logs Tab ───────────────────────────────────────────────────────────
function AuditLogsTab() {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        adminApi('GET', '/logs')
            .then(setLogs)
            .catch(e => setError(e.message))
            .finally(() => setLoading(false));
    }, []);

    if (loading) return <div className="flex items-center justify-center h-48 text-gray-400">Loading logs…</div>;
    if (error) return <div className="text-red-500 p-4">{error}</div>;

    return (
        <div className="overflow-x-auto">
            <table className="w-full">
                <thead>
                    <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                        {['Time', 'Actor', 'Role', 'Action', 'From → To', 'Reason'].map(h => (
                            <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">{h}</th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {logs.map((l, i) => (
                        <tr key={i} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/40">
                            <td className="px-4 py-2 text-xs text-gray-500">{new Date(l.timestamp).toLocaleString()}</td>
                            <td className="px-4 py-2 text-xs text-gray-900 dark:text-white">{l.actor_email ?? l.ip_address ?? '—'}</td>
                            <td className="px-4 py-2 text-xs text-gray-500">{l.actor_role ?? '—'}</td>
                            <td className="px-4 py-2 text-xs font-mono text-cyan-600 dark:text-cyan-400">{l.action}</td>
                            <td className="px-4 py-2 text-xs text-gray-600 dark:text-gray-400">
                                {l.details?.from_state} → {l.details?.to_state}
                            </td>
                            <td className="px-4 py-2 text-xs text-gray-500 max-w-xs truncate">{l.details?.reason ?? '—'}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
            {logs.length === 0 && <div className="text-center py-12 text-gray-400">No audit logs yet.</div>}
        </div>
    );
}

// ── Threat Reports Tab ───────────────────────────────────────────────────────
function ThreatReportsTab() {
    const [reports, setReports] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        adminApi('GET', '/threat-reports')
            .then(setReports)
            .catch(e => setError(e.message))
            .finally(() => setLoading(false));
    }, []);

    if (loading) return <div className="flex items-center justify-center h-48 text-gray-400">Loading reports…</div>;
    if (error) return <div className="text-red-500 p-4">{error}</div>;

    return (
        <div className="overflow-x-auto">
            <table className="w-full">
                <thead>
                    <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                        {['Analyst', 'Verdict', 'Notes', 'Submitted'].map(h => (
                            <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">{h}</th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {reports.map((r, i) => (
                        <tr key={i} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/40">
                            <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">{r.analyst_email}</td>
                            <td className="px-4 py-3">
                                <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold ${r.verdict === 'CONFIRMED_PHISHING'
                                        ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300'
                                        : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
                                    }`}>
                                    {r.verdict?.replace('_', ' ')}
                                </span>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500 max-w-xs truncate">{r.notes || '—'}</td>
                            <td className="px-4 py-3 text-xs text-gray-500">{new Date(r.created_at).toLocaleString()}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
            {reports.length === 0 && <div className="text-center py-12 text-gray-400">No threat reports yet.</div>}
        </div>
    );
}

// ── Stats Bar ────────────────────────────────────────────────────────────────
function StatsBar() {
    const [stats, setStats] = useState(null);
    useEffect(() => {
        adminApi('GET', '/stats').then(setStats).catch(() => { });
    }, []);

    if (!stats) return null;

    const items = [
        { label: 'Total Users', value: stats.total_users, color: 'text-cyan-500' },
        { label: 'Total Scans', value: stats.total_scans, color: 'text-purple-500' },
        ...Object.entries(stats.scans_by_state ?? {}).map(([k, v]) => ({ label: k, value: v, color: 'text-gray-500' })),
    ];

    return (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            {items.map((item, i) => (
                <div key={i} className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
                    <p className={`text-3xl font-bold ${item.color}`}>{item.value}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 uppercase tracking-wide">{item.label}</p>
                </div>
            ))}
        </div>
    );
}

// ── Main Page ────────────────────────────────────────────────────────────────
const TABS = ['Users', 'Audit Logs', 'Threat Reports'];

export default function AdminPanel() {
    const [activeTab, setActiveTab] = useState('Users');

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-950 px-4 py-10">
            <div className="max-w-7xl mx-auto">
                {/* Header */}
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                        ⚙️ Admin <span className="text-cyan-500">Panel</span>
                    </h1>
                    <p className="text-gray-500 dark:text-gray-400 mt-1">Manage users, audit trails, and threat intelligence</p>
                </div>

                {/* Stats */}
                <StatsBar />

                {/* Tab nav */}
                <div className="flex gap-1 mb-6 bg-gray-100 dark:bg-gray-800 rounded-xl p-1 w-fit">
                    {TABS.map(tab => (
                        <button
                            key={tab}
                            onClick={() => setActiveTab(tab)}
                            className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === tab
                                    ? 'bg-white dark:bg-gray-900 text-gray-900 dark:text-white shadow-sm'
                                    : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200'
                                }`}
                        >
                            {tab}
                        </button>
                    ))}
                </div>

                {/* Tab content */}
                <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl overflow-hidden shadow-sm">
                    {activeTab === 'Users' && <UsersTab />}
                    {activeTab === 'Audit Logs' && <AuditLogsTab />}
                    {activeTab === 'Threat Reports' && <ThreatReportsTab />}
                </div>
            </div>
        </div>
    );
}
