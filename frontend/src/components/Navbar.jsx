import { NavLink } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";

const Navbar = () => {
  return (
    <header className="border-b bg-white/70 backdrop-blur dark:bg-gray-900/70 border-gray-200 dark:border-gray-800">
      <nav className="mx-auto max-w-6xl px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          {/* Replace placeholder box with your public/logo.jpg */}
          <img
            src="/logo.jpg"
            alt="CheckMyURL logo"
            className="h-9 w-9 rounded object-cover ring-1 ring-indigo-200 dark:ring-indigo-500/40"
            loading="eager"
            fetchPriority="high"
          />
          <span className="text-lg font-semibold text-gray-900 dark:text-gray-100">CheckMyURL</span>
        </div>

        <div className="flex items-center gap-6">
          <NavLink
            to="/"
            className={({ isActive }) =>
              `text-sm ${isActive ? "text-indigo-600 dark:text-indigo-400" : "text-gray-700 dark:text-gray-300"}`
            }
            end
          >
            Scanner
          </NavLink>
          <NavLink
            to="/statistics"
            className={({ isActive }) =>
              `text-sm ${isActive ? "text-indigo-600 dark:text-indigo-400" : "text-gray-700 dark:text-gray-300"}`
            }
          >
            Statistics
          </NavLink>
          <ThemeToggle />
        </div>
      </nav>
    </header>
  );
};

export default Navbar;
