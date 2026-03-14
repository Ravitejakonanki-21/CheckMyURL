import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";

function EyeIcon({ open }) {
  return open ? (
    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
    </svg>
  ) : (
    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.477 0-8.268-2.943-9.542-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18" />
    </svg>
  );
}

export default function Login({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [status, setStatus] = useState("");
  const [isSuccess, setIsSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleForgotPassword = () => navigate("/forgot-password");

  const handleLogin = async (e) => {
    e.preventDefault();
    setStatus(""); setIsSuccess(false); setLoading(true);
    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
      if (response.ok) {
        setIsSuccess(true);
        setStatus("Login successful!");
        localStorage.setItem("token", data.token || data.access_token || "");
        localStorage.setItem("access_token", data.access_token || data.token || "");
        localStorage.setItem("isAuthenticated", "true");
        localStorage.setItem("userEmail", data.email);
        localStorage.setItem("role", (data.role || "USER").toUpperCase());
        if (rememberMe) localStorage.setItem("rememberMe", "true");
        else localStorage.removeItem("rememberMe");
        if (onLogin) onLogin(data);
        setTimeout(() => { navigate("/"); window.location.reload(); }, 500);
      } else {
        setStatus(data.error || "Login failed");
      }
    } catch {
      setStatus("Network error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen bg-[var(--bg-primary)] flex items-center justify-center px-4 transition-colors duration-300"
    >
      <div className="max-w-md w-full">
        <div className="text-center mb-2">
          <div className="flex items-center justify-center gap-3 mb-2">
            <img src="/logo.png" alt="CheckMyURL logo" className="h-16 w-16" loading="eager" />
            <h1 className="text-3xl font-bold text-[#00e5ff]">BLUECHECK</h1>
          </div>
          <p className="text-[var(--text-secondary)] text-sm">Sign in to your account</p>
        </div>

        <div className="bg-white dark:bg-[#181818] rounded-2xl shadow-lg border border-gray-200 dark:border-[#333] p-8">
          <form onSubmit={handleLogin} className="space-y-6">
            {/* Email */}
            <div>
              <label htmlFor="login-email" className="block text-sm font-medium text-[var(--text-primary)] mb-3">Email</label>
              <input
                id="login-email" type="email" value={email}
                onChange={e => setEmail(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 dark:border-[#333] rounded-lg focus:ring-2 focus:ring-[#00e5ff] focus:border-[#00e5ff] bg-gray-50 dark:bg-[#101010] text-[var(--text-primary)]"
                placeholder="Enter your email" required
              />
            </div>

            {/* Password with show/hide */}
            <div>
              <label htmlFor="login-password" className="block text-sm font-medium text-[var(--text-primary)] mb-3">Password</label>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="w-full px-4 py-3 pr-12 border border-gray-300 dark:border-[#333] rounded-lg focus:ring-2 focus:ring-[#00e5ff] focus:border-[#00e5ff] bg-gray-50 dark:bg-[#101010] text-[var(--text-primary)]"
                  placeholder="Enter your password" required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(p => !p)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  tabIndex={-1}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  <EyeIcon open={showPassword} />
                </button>
              </div>
            </div>

            {/* Remember me + Forgot */}
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input id="rememberMe" type="checkbox" checked={rememberMe}
                  onChange={e => setRememberMe(e.target.checked)}
                  className="h-4 w-4 text-[#00e5ff] border-gray-300 rounded" />
                <label htmlFor="rememberMe" className="ml-2 text-sm text-[var(--text-secondary)]">Remember me</label>
              </div>
              <button type="button" onClick={handleForgotPassword} className="text-sm text-[#00e5ff] hover:text-[#00ccf0] font-medium">
                Forgot password?
              </button>
            </div>

            {/* Status */}
            {status && (
              <div className={`p-3 border rounded-lg ${isSuccess ? "bg-green-50 border-green-200" : "bg-red-50 border-red-200"}`}>
                <p className={`text-sm text-center ${isSuccess ? "text-green-700" : "text-red-600"}`}>{status}</p>
              </div>
            )}

            <button type="submit" disabled={loading}
              className="w-full py-3 bg-[#00e5ff] hover:bg-[#00ccf0] text-[#0e0e0e] font-semibold rounded-lg transition-colors disabled:opacity-50 shadow-md">
              {loading ? "SIGNING IN..." : "SIGN IN"}
            </button>
          </form>
        </div>

        <div className="text-center mt-8">
          <p className="text-sm text-[var(--text-secondary)] mb-2">Students of IBM @ 2025</p>
          <div className="mt-4 text-sm">
            Don't have an account?{" "}
            <Link to="/register" className="text-[#00e5ff] underline">Register here</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
