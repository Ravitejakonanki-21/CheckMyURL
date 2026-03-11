import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";

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

function PasswordField({ id, label, value, onChange, placeholder }) {
  const [show, setShow] = useState(false);
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700 mb-3">{label}</label>
      <div className="relative">
        <input
          id={id}
          type={show ? "text" : "password"}
          value={value}
          onChange={onChange}
          className="w-full px-4 py-3 pr-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
          placeholder={placeholder}
          required
          minLength={6}
        />
        <button
          type="button"
          onClick={() => setShow(p => !p)}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
          tabIndex={-1}
          aria-label={show ? "Hide password" : "Show password"}
        >
          <EyeIcon open={show} />
        </button>
      </div>
    </div>
  );
}

export default function ResetPassword() {
  const { token } = useParams();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [status, setStatus] = useState("");
  const [isSuccess, setIsSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus(""); setIsSuccess(false);

    if (password !== confirmPassword) {
      setStatus("Passwords do not match.");
      return;
    }
    if (password.length < 6) {
      setStatus("Password must be at least 6 characters.");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch("http://localhost:5001/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const data = await response.json();
      if (response.ok) {
        setIsSuccess(true);
        setStatus("Password reset successful! Redirecting to login…");
        setTimeout(() => navigate("/login"), 3000);
      } else {
        setStatus(data.error || "Reset failed");
      }
    } catch {
      setStatus("Network error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center px-4 bg-gray-50"
      style={{ backgroundImage: "url(/bg.jpg)", backgroundSize: "cover", backgroundPosition: "center" }}
    >
      <div className="max-w-md w-full">
        <div className="text-center mb-6">
          <div className="flex items-center justify-center gap-3 mb-2">
            <img src="/logo.png" alt="CheckMyURL logo" className="h-16 w-16" loading="eager" />
            <h1 className="text-3xl font-bold text-blue-500">CheckMyURL</h1>
          </div>
        </div>

        <div className="bg-white rounded-2xl shadow-lg border border-gray-200 p-8">
          <h2 className="text-2xl font-bold text-gray-800 mb-6 text-center">Reset Your Password</h2>
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* New Password */}
            <PasswordField
              id="new-password" label="New Password"
              value={password} onChange={e => setPassword(e.target.value)}
              placeholder="Enter your new password"
            />

            {/* Confirm Password */}
            <PasswordField
              id="confirm-password" label="Confirm New Password"
              value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)}
              placeholder="Re-enter your new password"
            />

            {/* Status message */}
            {status && (
              <div className={`p-3 border rounded-lg ${isSuccess ? "bg-green-50 border-green-200" : "bg-red-50 border-red-200"}`}>
                <p className={`text-sm text-center ${isSuccess ? "text-green-700" : "text-red-600"}`}>{status}</p>
              </div>
            )}

            <button type="submit" disabled={loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50 shadow-md">
              {loading ? "Resetting…" : "Reset Password"}
            </button>
          </form>
        </div>
        <p className="text-sm text-gray-600 mt-8 text-center">Students of IBM @ 2025</p>
      </div>
    </div>
  );
}
