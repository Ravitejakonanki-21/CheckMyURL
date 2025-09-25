import React from "react";
import Chart from "react-apexcharts";

const PieCard = ({
  title = "Risk Composition",
  series = [0.0001, 0.0001, 0.0001],
  labels = ["Safe","Suspicious","Dangerous"],
  zeroMode = false, // true before first scan
}) => {
  // Total using precise sum
  const total = Array.isArray(series) ? series.reduce((a, b) => a + (Number(b) || 0), 0) : 0;

  const options = {
    chart: { type: "pie", toolbar: { show: false } },
    labels,
    legend: { show: true, labels: { colors: undefined } },
    dataLabels: {
      enabled: true, // always show a label
      formatter: (val, opt) => {
        // When zeroMode, force 0% in labels regardless of internal epsilon
        if (zeroMode || total <= 0.001) return "0%";
        // Otherwise, use ApexCharts-calculated percentage with rounding
        const pct = Math.round(val);
        return `${pct}%`;
      },
      style: { fontSize: "12px" },
      dropShadow: { enabled: false },
    },
    tooltip: {
      y: {
        formatter: (val) => {
          if (zeroMode || total <= 0.001) return "0%";
          return `${Math.round(val)}%`;
        },
      },
    },
    colors: ["#16a34a", "#f59e0b", "#dc2626"],
  };

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
      <div className="mb-3 text-sm font-medium text-gray-800 dark:text-gray-200">{title}</div>
      <div className="grid place-items-center">
        <Chart type="pie" height={280} series={series} options={options} />
      </div>
    </div>
  );
};

export default PieCard;
