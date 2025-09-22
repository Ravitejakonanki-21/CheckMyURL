import { motion } from "framer-motion";

function Header() {
  return (
    <motion.header
      initial={{ y: -50, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6 }}
      className="w-full bg-primary text-white shadow-md p-4 flex justify-between items-center"
    >
      <h1 className="text-xl font-bold">AI URL Checker 🔗</h1>
      <button className="bg-white text-primary px-4 py-2 rounded-lg font-medium hover:bg-gray-100 transition">
        Logout
      </button>
    </motion.header>
  );
}
export default Header;
