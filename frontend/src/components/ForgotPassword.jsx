import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState("");
  const [isSuccess, setIsSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus("");
    setIsSuccess(false);
    setLoading(true);
    try {
      const response = await fetch("/api/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (response.ok) {
        setIsSuccess(true);
        setStatus(data.message || "If the email exists, reset instructions have been sent.");
      } else {
        setIsSuccess(false);
        if (response.status === 503) {
          setStatus("Email service is not configured. Please contact the administrator to set up MAIL_USERNAME and MAIL_PASSWORD.");
        } else if (response.status === 500) {
          setStatus(data.error || "Failed to send email. The server mail configuration may be incorrect. Please verify the Gmail App Password.");
        } else {
          setStatus(data.error || "Failed to send reset instructions.");
        }
      }
    } catch {
      setStatus("Network error — make sure the server is running.");
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
            <h1 className="text-3xl font-bold text-[#00e5ff]">CYBERSHIELD</h1>
          </div>
          <p className="text-[var(--text-secondary)] text-sm">Forgot your password?</p>
        </div>
        <div className="bg-white dark:bg-[#181818] rounded-2xl shadow-lg border border-gray-200 dark:border-[#333] p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-[var(--text-primary)] mb-3">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 dark:border-[#333] rounded-lg focus:ring-2 focus:ring-[#00e5ff] focus:border-[#00e5ff] bg-gray-50 dark:bg-[#0e0e0e] text-[var(--text-primary)]"
                placeholder="Enter your email"
                required
              />
            </div>
            {status && (
              <div className={`p-3 border rounded-lg ${isSuccess ? "bg-green-50 border-green-200" : "bg-red-50 border-red-200"}`}>
                <p className={`text-sm text-center ${isSuccess ? "text-green-700" : "text-red-600"}`}>{status}</p>
              </div>
            )}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-[#00e5ff] hover:bg-[#00ccf0] text-[#0e0e0e] font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md"
            >
              {loading ? "Sending..." : "Send Reset Link"}
            </button>
            <button
              type="button"
              onClick={() => navigate("/login")}
              className="w-full mt-2 py-3 bg-gray-100 dark:bg-[#333] hover:bg-gray-200 dark:hover:bg-[#444] text-gray-700 dark:text-gray-200 font-semibold rounded-lg transition-colors shadow"
            >
              Back to Login
            </button>
          </form>
        </div>
        <div className="text-center mt-8">
          <p className="text-sm text-[var(--text-secondary)] mb-2">Students of IBM @ 2025</p>
        </div>
      </div>
    </div>
  );
}
