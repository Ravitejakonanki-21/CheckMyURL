import { useTheme } from "../context/ThemeContext";

const ThemeToggle = () => {
  const { theme, toggle } = useTheme();
  return (
    <button
      onClick={toggle}
      aria-label="Toggle theme"
      className={`inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm
        ${
          theme === "dark"
            ? "border-black bg-black text-neon-blue hover:bg-gray-900"
            : "border-white bg-white text-blue-500 hover:bg-gray-100"
        }`}
    >
      <span>{theme === "dark" ? "Dark" : "Light"}</span>
      <span
        className={`h-4 w-4 rounded-full ${
          theme === "dark" ? "bg-neon-blue" : "bg-blue-500"
        }`}
      />
    </button>
  );
};

export default ThemeToggle;
