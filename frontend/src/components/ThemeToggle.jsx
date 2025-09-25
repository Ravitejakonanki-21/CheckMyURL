import { useTheme } from "../context/ThemeContext";

const ThemeToggle = () => {
  const { theme, toggle } = useTheme();
  return (
    <button
      onClick={toggle}
      aria-label="Toggle theme"
      className="inline-flex items-center gap-2 rounded-md border border-gray-200 dark:border-gray-700 px-3 py-1.5 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
    >
      <span>{theme === "dark" ? "Dark" : "Light"}</span>
      <span className="h-4 w-4 rounded-full bg-yellow-400 dark:bg-slate-200" />
    </button>
  );
};

export default ThemeToggle;
