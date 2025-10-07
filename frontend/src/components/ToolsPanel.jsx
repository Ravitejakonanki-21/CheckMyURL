// function ToolsPanel() {
//   const items = [
//     { name: "HTTPS/SSL Validation", desc: "Checks protocol and certificate presence for secure transport." },
//     { name: "WHOIS Lookup", desc: "Inspects domain age, registrar, and ownership signals." },
//     { name: "Security Headers", desc: "Detects CSP, XFO, HSTS, and similar protections." },
//     { name: "Keyword Analysis", desc: "Flags risky terms common in phishing content." },
//     { name: "Open Port Scanning", desc: "Notes exposed services surface (simulated UI-only)." },
//     { name: "ML Phishing Detection", desc: "Estimates phishing likelihood via learned patterns." },
//   ];
//   return (
//     <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
//       <div className="mb-4 text-sm font-medium text-gray-800 dark:text-gray-200">Tools Used</div>
//       <ul className="space-y-3">
//         {items.map((it) => (
//           <li key={it.name} className="rounded-md border border-gray-100 p-3 dark:border-gray-800">
//             <div className="text-sm font-semibold">{it.name}</div>
//             <div className="text-xs text-gray-600 dark:text-gray-400">{it.desc}</div>
//           </li>
//         ))}
//       </ul>
//     </div>
//   );
// }
// export default ToolsPanel;
