import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus("");
    setLoading(true);
    try {
      // Replace with your real endpoint if needed:
      const response = await fetch("http://localhost:5001/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (response.ok) {
        setStatus("If the email exists, reset instructions have been sent.");
      } else {
        setStatus(data.error || "Failed to send reset instructions");
      }
    } catch {
      setStatus("Network error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div 
      className="min-h-screen flex items-center justify-center px-4"
      style={{
        backgroundImage: 'url(/bg.jpg)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat'
      }}
    >
      <div className="max-w-md w-full">
        <div className="text-center mb-2">
          <div className="flex items-center justify-center gap-3 mb-2">
            <img src="/logo.png" alt="CheckMyURL logo" className="h-16 w-16" loading="eager" />
            <h1 className="text-3xl font-bold text-blue-500">CheckMyURL</h1>
          </div>
          <p className="text-gray-600 text-sm">Forgot your password?</p>
        </div>
        <div className="bg-white rounded-2xl shadow-lg border border-gray-200 p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-3">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
                placeholder="Enter your email"
                required
              />
            </div>
            {status && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-red-600 text-sm text-center">{status}</p>
              </div>
            )}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md"
            >
              {loading ? "Sending..." : "Send Reset Link"}
            </button>
            <button
              type="button"
              onClick={() => navigate("/login")}
              className="w-full mt-2 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 font-semibold rounded-lg transition-colors shadow"
            >
              Back to Login
            </button>
          </form>
        </div>
        <div className="text-center mt-8">
          <p className="text-sm text-gray-600 mb-2">Students of IBM @ 2025</p>
        </div>
      </div>
    </div>
  );
}
