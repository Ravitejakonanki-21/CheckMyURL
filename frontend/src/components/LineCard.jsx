// import Chart from "react-apexcharts";

// const LineCard = ({
//   title = "Line chart",
//   series = [{ name: "Series 1", data: [10, 22, 35, 28, 40, 55, 38] }],
//   options = {},
//   height = 320,
// }) => {
//   const baseOptions = {
//     chart: { type: "line", toolbar: { show: false } },
//     stroke: { curve: "smooth", width: 3 },
//     markers: { size: 0 },
//     dataLabels: { enabled: false },
//     grid: { borderColor: "#e5e7eb", strokeDashArray: 4 },
//     xaxis: { categories: [], labels: { style: { colors: undefined } } },
//     yaxis: { labels: { style: { colors: undefined } } },
//     legend: { labels: { colors: undefined } },
//     tooltip: { theme: "dark" },
//     colors: ["#6366f1", "#22c55e", "#f59e0b"],
//   };

//   const mergedOptions = {
//     ...baseOptions,
//     ...options,
//     chart: { ...baseOptions.chart, ...(options.chart || {}) },
//     stroke: { ...baseOptions.stroke, ...(options.stroke || {}) },
//     grid: { ...baseOptions.grid, ...(options.grid || {}) },
//     xaxis: { ...baseOptions.xaxis, ...(options.xaxis || {}) },
//     yaxis: { ...baseOptions.yaxis, ...(options.yaxis || {}) },
//     legend: { ...baseOptions.legend, ...(options.legend || {}) },
//     tooltip: { ...baseOptions.tooltip, ...(options.tooltip || {}) },
//     colors: options.colors || baseOptions.colors,
//   };

//   return (
//     <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
//       <div className="mb-3 text-sm font-medium text-gray-800 dark:text-gray-200">{title}</div>
//       <Chart type="line" height={height} series={series} options={mergedOptions} />
//     </div>
//   );
// };

// export default LineCard;
