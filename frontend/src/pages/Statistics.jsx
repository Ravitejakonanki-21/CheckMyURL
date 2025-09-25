import { useMemo } from "react";
import LineCard from "../components/LineCard";
import BarCard from "../components/BarCard";
import ToolsPanel from "../components/ToolsPanel";
import { useScan } from "../context/ScanContext";

function Statistics() {
  const { history = [] } = useScan?.() ?? { history: [] };

  // last 12 scans; ensure at least one point for initial render
  const last = useMemo(() => (history.length ? history.slice(-12) : [{ riskScore: 0 }]), [history]);
  const labels = useMemo(
    () => (history.length ? last.map((_, i) => `#${history.length - last.length + i + 1}`) : ["1"]),
    [last, history.length]
  );

  // Risk trend line
  const riskSeries = useMemo(
    () => [{ name: "Risk", data: last.map((e) => (Number.isFinite(e.riskScore) ? e.riskScore : 0)) }],
    [last]
  );
  const riskOptions = useMemo(
    () => ({
      chart: { toolbar: { show: false }, animations: { enabled: false } },
      stroke: { curve: "smooth", width: 3 },
      dataLabels: { enabled: false },
      grid: { borderColor: "#e5e7eb", strokeDashArray: 4 },
      xaxis: { categories: labels, tickPlacement: "on" },
      yaxis: { min: 0, max: 100, forceNiceScale: true },
      colors: ["#6366f1"],
    }),
    [labels]
  );

  // Tool totals
  const toolOrder = ["SSL", "WHOIS", "Headers", "Keywords", "Ports", "ML"];
  const toolTotals = useMemo(() => {
    if (!history.length) return [0, 0, 0, 0, 0, 0];
    const acc = { SSL: 0, WHOIS: 0, Headers: 0, Keywords: 0, Ports: 0, ML: 0 };
    history.forEach((e) => {
      if (!e?.tools) return;
      Object.entries(e.tools).forEach(([k, v]) => (acc[k] = (acc[k] ?? 0) + (Number(v) || 0)));
    });
    return toolOrder.map((k) => acc[k] ?? 0);
  }, [history]);

  const toolsSeries = useMemo(() => [{ name: "Findings", data: toolTotals }], [toolTotals]);
  const toolsOptions = useMemo(
    () => ({
      chart: { toolbar: { show: false }, animations: { enabled: false } },
      plotOptions: { bar: { borderRadius: 3, columnWidth: "40%" } },
      xaxis: { categories: toolOrder },
      colors: ["#22c55e"],
      dataLabels: { enabled: false },
      grid: { borderColor: "#e5e7eb", strokeDashArray: 4 },
    }),
    []
  );

  // Risk score distribution buckets
  const bucketLabels = ["0-20", "21-40", "41-60", "61-80", "81-100"];
  const riskDist = useMemo(() => {
    if (!history.length) return [0, 0, 0, 0, 0];
    const b = [0, 0, 0, 0, 0];
    history.forEach(({ riskScore = 0 }) => {
      const v = Number(riskScore) || 0;
      const i = v <= 20 ? 0 : v <= 40 ? 1 : v <= 60 ? 2 : v <= 80 ? 3 : 4;
      b[i] += 1;
    });
    return b;
  }, [history]);

  const riskDistSeries = useMemo(() => [{ name: "URLs", data: riskDist }], [riskDist]);
  const riskDistOptions = useMemo(
    () => ({
      chart: { toolbar: { show: false }, animations: { enabled: false } },
      plotOptions: { bar: { borderRadius: 3, columnWidth: "45%" } },
      xaxis: { categories: bucketLabels },
      colors: ["#ef4444"],
      dataLabels: { enabled: false },
      grid: { borderColor: "#e5e7eb", strokeDashArray: 4 },
    }),
    []
  );

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <div className="lg:col-span-1">
        <ToolsPanel />
      </div>
      <div className="lg:col-span-2 space-y-6">
        <LineCard
          key={`risk-${labels.join("-")}`}  // force remount when labels change
          title="Risk trend"
          series={riskSeries}
          options={riskOptions}
          height={320}
        />
        <BarCard
          key={`tools-${history.length}`}   // re-render on new scan count
          title="Tool findings distribution"
          series={toolsSeries}
          options={toolsOptions}
          height={320}
        />
        <BarCard
          key={`dist-${history.length}`}    // re-render on new scan count
          title="Risk score distribution"
          series={riskDistSeries}
          options={riskDistOptions}
          height={320}
        />
      </div>
    </div>
  );
}
export default Statistics;
