import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";

export default function Login({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setStatus("");
    setLoading(true);
    try {
      const response = await fetch("http://localhost:5000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
      if (response.ok) {
        setStatus("Login successful!");
        localStorage.setItem("token", data.token);
        localStorage.setItem("isAuthenticated", "true");
        localStorage.setItem("userEmail", data.email);
        if (onLogin) onLogin(data);
        setTimeout(() => {
          navigate("/");
          window.location.reload();
        }, 500);
      } else {
        setStatus(data.error || "Login failed");
      }
    } catch (err) {
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
            <img
              src="/logo.png"
              alt="CheckMyURL logo"
              className="h-16 w-16"
              loading="eager"
            />
            <h1 className="text-3xl font-bold text-blue-500">
              CheckMyURL
            </h1>
          </div>
          <p className="text-gray-600 text-sm">
            Sign in to your account
          </p>
        </div>

        <div className="bg-white rounded-2xl shadow-lg border border-gray-200 p-8">
          <form onSubmit={handleLogin} className="space-y-6">
            {/* Email Input */}
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

            {/* Password Input */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-3">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
                placeholder="Enter your password"
                required
              />
            </div>

            {/* Error Message */}
            {status && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-red-600 text-sm text-center">{status}</p>
              </div>
            )}
            
            {/* Sign In Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md"
            >
              {loading ? 'SIGNING IN...' : 'SIGN IN'}
            </button>
          </form>
        </div>

        <div className="text-center mt-8">
          <p className="text-sm text-gray-600 mb-2">
            Students of IBM @ 2025
          </p>
          <div className="mt-4 text-sm">
            Don't have an account?{" "}
            <Link to="/register" className="text-blue-600 underline">
              Register here
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
