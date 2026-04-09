import Chart from "react-apexcharts";

const BarCard = ({
  title = "Bar chart",
  series = [{ name: "Series 1", data: [12, 18, 30, 22, 27, 35] }],
  options = {},
  height = 320,
  horizontal = false,
}) => {
  const baseOptions = {
    chart: { type: "bar", toolbar: { show: false } },
    plotOptions: {
      bar: {
        horizontal,
        borderRadius: 4,
        columnWidth: "40%",
      },
    },
    dataLabels: { enabled: false },
    grid: { borderColor: "#e5e7eb", strokeDashArray: 4 },
    xaxis: { categories: [], labels: { style: { colors: undefined } } },
    yaxis: { labels: { style: { colors: undefined } } },
    legend: { labels: { colors: undefined } },
    colors: ["#22c55e", "#6366f1", "#f59e0b"],
    tooltip: { theme: "dark" },
  };

  const mergedOptions = {
    ...baseOptions,
    ...options,
    chart: { ...baseOptions.chart, ...(options.chart || {}) },
    plotOptions: {
      ...baseOptions.plotOptions,
      ...(options.plotOptions || {}),
      bar: {
        ...baseOptions.plotOptions.bar,
        ...((options.plotOptions && options.plotOptions.bar) || {}),
        horizontal,
      },
    },
    grid: { ...baseOptions.grid, ...(options.grid || {}) },
    xaxis: { ...baseOptions.xaxis, ...(options.xaxis || {}) },
    yaxis: { ...baseOptions.yaxis, ...(options.yaxis || {}) },
    legend: { ...baseOptions.legend, ...(options.legend || {}) },
    tooltip: { ...baseOptions.tooltip, ...(options.tooltip || {}) },
    colors: options.colors || baseOptions.colors,
  };

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
      <div className="mb-3 text-sm font-medium text-gray-800 dark:text-gray-200">{title}</div>
      <Chart type="bar" height={height} series={series} options={mergedOptions} />
    </div>
  );
};

export default BarCard;
