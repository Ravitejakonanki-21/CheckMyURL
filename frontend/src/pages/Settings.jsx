import { Save, Bell, Lock, User } from 'lucide-react';

export default function Settings() {
  return (
    <div className="min-h-screen bg-white dark:bg-black transition-colors py-20 px-6">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-16">
          <h1 className="text-5xl font-bold text-gray-900 dark:text-white mb-4">
            Settings
          </h1>
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            Configure your scanner preferences
          </p>
        </div>

        <div className="space-y-6">
          <div className="bg-white dark:bg-gray-900 p-8 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <div className="flex items-center gap-3 mb-6">
              <User className="text-[#00d4ff]" size={24} />
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Profile</h2>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Username
                </label>
                <input
                  type="text"
                  className="w-full px-4 py-3 rounded-lg bg-gray-50 dark:bg-black border border-gray-300 dark:border-[#00d4ff]/30 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 dark:focus:ring-[#00d4ff] outline-none transition-all"
                  placeholder="Enter username"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Email
                </label>
                <input
                  type="email"
                  className="w-full px-4 py-3 rounded-lg bg-gray-50 dark:bg-black border border-gray-300 dark:border-[#00d4ff]/30 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 dark:focus:ring-[#00d4ff] outline-none transition-all"
                  placeholder="Enter email"
                />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-900 p-8 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <div className="flex items-center gap-3 mb-6">
              <Bell className="text-[#00d4ff]" size={24} />
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Notifications</h2>
            </div>
            <div className="space-y-4">
              <label className="flex items-center justify-between cursor-pointer">
                <span className="text-gray-700 dark:text-gray-300">Email Notifications</span>
                <input type="checkbox" className="w-5 h-5 accent-[#00d4ff]" />
              </label>
              <label className="flex items-center justify-between cursor-pointer">
                <span className="text-gray-700 dark:text-gray-300">Scan Alerts</span>
                <input type="checkbox" className="w-5 h-5 accent-[#00d4ff]" defaultChecked />
              </label>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-900 p-8 rounded-2xl shadow-lg dark:shadow-[#00d4ff]/10 border border-gray-200 dark:border-[#00d4ff]/30">
            <div className="flex items-center gap-3 mb-6">
              <Lock className="text-[#00d4ff]" size={24} />
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Security</h2>
            </div>
            <button className="px-6 py-3 bg-blue-600 dark:bg-[#00d4ff] text-white dark:text-black font-semibold rounded-lg hover:bg-blue-700 dark:hover:bg-[#00bbff] transition-colors">
              Change Password
            </button>
          </div>

          <button className="w-full flex items-center justify-center gap-2 px-6 py-4 bg-blue-600 dark:bg-[#00d4ff] text-white dark:text-black font-semibold rounded-xl hover:bg-blue-700 dark:hover:bg-[#00bbff] transition-colors shadow-lg">
            <Save size={20} />
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
}