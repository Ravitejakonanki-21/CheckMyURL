import { NavLink } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";
import { useState } from "react";

function navClass({ isActive }) {
  return `text-sm font-bold px-4 py-2 rounded-full transition-all duration-300 ${isActive
    ? "text-[#00e5ff]"
    : "text-[#b3b3b3] hover:text-white"
    }`;
}

const Navbar = () => {
  const isAuthenticated = localStorage.getItem("isAuthenticated") === "true";
  const userEmail = localStorage.getItem("userEmail");
  const userRole = (localStorage.getItem("role") ?? "USER").toUpperCase();
  const [menuOpen, setMenuOpen] = useState(false);

  const username = userEmail ? userEmail.split("@")[0] : "";

  const isAdmin = userRole === "ADMIN";

  const handleLogout = () => {
    localStorage.removeItem("isAuthenticated");
    localStorage.removeItem("userEmail");
    localStorage.removeItem("token");
    localStorage.removeItem("access_token");
    localStorage.removeItem("role");
    setMenuOpen(false);
    window.location.href = "/login";
  };

  return (
    <header className="sticky top-0 z-50 bg-white/80 dark:bg-[#0e0e0e]/80 backdrop-blur-xl border-b border-gray-200 dark:border-[#333]">
      <nav className="mx-auto max-w-7xl px-6 py-4 flex items-center justify-between">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div className="h-8 w-8 bg-[#00e5ff] rounded-lg flex items-center justify-center">
             <svg className="w-5 h-5 text-[#0e0e0e]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
             </svg>
          </div>
          <span className="text-xl font-black text-gray-900 dark:text-white tracking-tighter">BLUE<span className="text-[#00e5ff]">CHECK</span></span>
        </div>

        {/* Nav links (Center) */}
        <div className="hidden md:flex items-center gap-6 absolute left-1/2 transform -translate-x-1/2">
          <NavLink to="/scanner" className={navClass}>Explore</NavLink>
          {isAuthenticated && (
            <NavLink to="/history" className={navClass}>History</NavLink>
          )}
          {isAdmin && (
            <>
              <NavLink to="/admin" className={navClass}>Users</NavLink>
              <NavLink to="/statistics" className={navClass}>Statistics</NavLink>
            </>
          )}
        </div>

        {/* Right side */}
        <div className="flex items-center gap-4">
          <ThemeToggle />

          {!isAuthenticated ? (
            <div className="flex items-center gap-3">
              <NavLink
                to="/login"
                className="px-6 py-2 text-sm font-bold text-white bg-[#181818] border border-[#333] hover:border-[#444] rounded-full transition-all"
              >
                Sign In
              </NavLink>
              <NavLink
                to="/register"
                className="px-6 py-2 text-sm font-bold text-[#0e0e0e] bg-[#00e5ff] hover:bg-[#00ccf0] rounded-full shadow-lg shadow-[#00e5ff]/20 transition-all"
              >
                Sign Up
              </NavLink>
            </div>
          ) : (
            /* User avatar */
            <div className="relative ml-2">
              <button
                className="flex items-center gap-2 px-3 py-1.5 bg-[#181818] border border-[#333] rounded-full hover:border-[#00e5ff]/50 transition-all"
                onClick={() => setMenuOpen(prev => !prev)}
              >
                <div className="h-7 w-7 rounded-full bg-[#00e5ff] text-[#0e0e0e] flex items-center justify-center font-bold text-sm">
                  {username.charAt(0).toUpperCase()}
                </div>
                <span className="hidden sm:block text-sm font-bold text-white uppercase tracking-tight">{username}</span>
              </button>

              {menuOpen && (
                <div className="absolute right-0 mt-3 w-64 rounded-2xl bg-white dark:bg-[#181818] shadow-2xl border border-gray-200 dark:border-[#333] z-50 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                  <div className="p-5 border-b border-gray-200 dark:border-[#333] bg-gray-50 dark:bg-[#0e0e0e]">
                    <div className="font-black text-gray-900 dark:text-white uppercase tracking-tighter">Account Info</div>
                    <div className="text-xs text-gray-500 dark:text-[#b3b3b3] truncate mt-1">{userEmail}</div>
                    <div className="mt-3 inline-block px-2 py-0.5 rounded bg-[#00e5ff]/10 text-[#00e5ff] text-[10px] font-black uppercase tracking-widest border border-[#00e5ff]/20">
                      {userRole}
                    </div>
                  </div>
                  <div className="p-2">
                    <button
                      onClick={handleLogout}
                      className="w-full flex items-center justify-center gap-2 px-4 py-3 text-sm font-black text-white bg-red-600/10 hover:bg-red-600 text-red-600 hover:text-white transition-all rounded-xl uppercase tracking-widest"
                    >
                      Logout
                    </button>
                  </div>
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
