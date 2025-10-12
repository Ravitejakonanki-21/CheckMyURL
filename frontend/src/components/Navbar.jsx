import { NavLink } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";

const Navbar = () => {
  // Debug: Check authentication status
  const isAuthenticated = localStorage.getItem('isAuthenticated') === 'true';
  console.log('Navbar - isAuthenticated:', isAuthenticated);
  console.log('Navbar - user:', localStorage.getItem('user'));

  const handleLogout = () => {
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('user');
    window.location.href = '/login';
  };

  return (
    <header className="border-b bg-white/70 backdrop-blur dark:bg-black border-gray-200 dark:border-gray-800">
      <nav className="mx-auto max-w-6xl px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img
            src="/logo.png"
            alt="CheckMyURL logo"
            className="h-10 w-20 rounded object-cover"
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

          <button
            onClick={handleLogout}
            className="ml-4 px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-md transition-colors duration-200"
          >
            Logout
          </button>
        </div>
      </nav>
    </header>
  );
};

export default Navbar;