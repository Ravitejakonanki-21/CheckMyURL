import { NavLink } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";
import { useState } from "react";

const Navbar = () => {
  const isAuthenticated = localStorage.getItem("isAuthenticated") === "true";
  const userEmail = localStorage.getItem("userEmail");
  const [menuOpen, setMenuOpen] = useState(false);

  const username = userEmail ? userEmail.split("@")[0] : "";

  const handleLogout = () => {
    localStorage.removeItem("isAuthenticated");
    localStorage.removeItem("userEmail");
    localStorage.removeItem("token");
    setMenuOpen(false);
    window.location.href = "/login";
  };

  return (
    <header className="border-b bg-white/90 dark:bg-black border-gray-200 dark:border-gray-800 shadow-md">
      <nav className="mx-auto max-w-7xl px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img
            src="/logo.png"
            alt="CheckMyURL logo"
            className="h-10 w-20 rounded object-cover"
            loading="eager"
            fetchPriority="high"
          />
          <span className="text-lg font-bold text-gray-900 dark:text-gray-100">
            CheckMyURL
          </span>
        </div>
        <div className="flex items-center gap-4">
          <NavLink
            to="/"
            className={({ isActive }) =>
              `text-base px-2 py-1 rounded ${
                isActive
                  ? "text-indigo-600 bg-indigo-100 dark:bg-indigo-800 dark:text-indigo-200"
                  : "text-gray-700 dark:text-gray-300"
              }`
            }
            end
          >
            Scanner
          </NavLink>
          <NavLink
            to="/statistics"
            className={({ isActive }) =>
              `text-base px-2 py-1 rounded ${
                isActive
                  ? "text-indigo-600 bg-indigo-100 dark:bg-indigo-800 dark:text-indigo-200"
                  : "text-gray-700 dark:text-gray-300"
              }`
            }
          >
            Statistics
          </NavLink>
          <ThemeToggle />
          {isAuthenticated && userEmail && (
            <div className="relative ml-2">
              <button
                className="flex items-center gap-2 px-3 py-2 bg-gradient-to-r from-gray-100 to-gray-200 dark:from-gray-800 dark:to-gray-900 border rounded-full shadow hover:ring-1 hover:ring-indigo-200 transition"
                onClick={() => setMenuOpen((prev) => !prev)}
              >
                <span className="flex items-center justify-center h-9 w-9 rounded-full bg-indigo-600 text-white font-bold text-lg">
                  {username.charAt(0).toUpperCase()}
                </span>
                <span className="hidden sm:block font-semibold text-gray-900 dark:text-gray-100">
                  {username}
                </span>
                <svg
                  viewBox="0 0 20 20"
                  fill="currentColor"
                  className={`h-4 w-4 ml-1 transition-transform ${
                    menuOpen ? "rotate-180" : ""
                  }`}
                >
                  <path
                    d="M5.23 7.21a.75.75 0 0 1 1.06.02L10 10.708l3.71-3.477a.75.75 0 1 1 1.045 1.08l-4.25 3.986a.75.75 0 0 1-1.045 0L5.21 8.29a.75.75 0 0 1 .02-1.08z"
                  />
                </svg>
              </button>
              {menuOpen && (
                <div className="absolute right-0 mt-2 w-56 rounded-xl bg-white dark:bg-gray-900 shadow-xl border border-gray-200 dark:border-gray-800 z-30">
                  <div className="p-4 border-b border-gray-100 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 rounded-t-xl">
                    <div className="font-bold text-indigo-700 dark:text-indigo-300">Hey {username}!</div>
                    <div className="text-xs text-gray-500 dark:text-gray-400 break-all">
                      {userEmail}
                    </div>
                  </div>
                  <button
                    onClick={handleLogout}
                    className="w-full px-4 py-3 text-left text-sm text-white bg-red-600 hover:bg-red-700 font-semibold transition rounded-b-xl"
                  >
                    Logout
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </nav>
    </header>
  );
};

export default Navbar;
