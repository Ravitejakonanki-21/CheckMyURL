// import React, { useEffect, useState } from "react";
// import Chart from "react-apexcharts";

// const PieCard = ({
//   title = "Risk Composition",
//   series = [0.0001, 0.0001, 0.0001],
//   labels = ["Safe", "Suspicious", "Dangerous"],
//   zeroMode = false,
// }) => {
//   const total = Array.isArray(series)
//     ? series.reduce((a, b) => a + (Number(b) || 0), 0)
//     : 0;

//   const [textColor, setTextColor] = useState("#111827"); // default light

//   useEffect(() => {
//     const updateColor = () => {
//       const isDark = document.documentElement.classList.contains("dark");
//       setTextColor(isDark ? "#e5e7eb" : "#111827");
//     };

//     updateColor(); // initial

//     // Optional: watch for dark mode toggle if using JS-based toggle
//     const observer = new MutationObserver(updateColor);
//     observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
//     return () => observer.disconnect();
//   }, []);

//   const options = {
//     chart: { type: "pie", toolbar: { show: false } },
//     labels,
//     legend: {
//       show: true,
//       labels: { colors: Array(labels.length).fill(textColor) },
//     },
//     dataLabels: {
//       enabled: true,
//       formatter: (val) => {
//         if (zeroMode || total <= 0.001) return "0%";
//         return `${Math.round(val)}%`;
//       },
//       style: { fontSize: "12px", colors: Array(labels.length).fill(textColor) },
//       dropShadow: { enabled: false },
//     },
//     tooltip: {
//       y: {
//         formatter: (val) => {
//           if (zeroMode || total <= 0.001) return "0%";
//           return `${Math.round(val)}%`;
//         },
//       },
//     },
//     colors: ["#16a34a", "#f59e0b", "#dc2626"],
//   };

//   return (
//     <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
//       <div className="mb-3 text-sm font-medium text-gray-800 dark:text-gray-200">
//         {title}
//       </div>
//       <div className="grid place-items-center">
//         <Chart type="pie" height={280} series={series} options={options} />
//       </div>
//     </div>
//   );
// };

// export default PieCard;
