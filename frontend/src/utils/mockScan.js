// export function mockScan(url) {
//   const base = url.length % 100;
//   const ml = (base * 3) % 100;
//   const sslValid = !url.startsWith("http://");
//   const whoisAgeMonths = (base * 7) % 120;
//   const openPorts = [80, 443].filter((p) => (base + p) % 3 === 0);
//   const securityHeaders = ["Content-Security-Policy", "X-Frame-Options"].filter((_, i) => (base + i) % 2 === 0);
//   const keywords = ["login", "verify", "update"].filter((k, i) => (base + i) % 2 === 1);
//   const riskScore = Math.min(
//     100,
//     Math.round(0.5 * ml + (sslValid ? 0 : 20) + (whoisAgeMonths < 3 ? 25 : 0) + (openPorts.length > 2 ? 10 : 0))
//   );
//   const classification = riskScore < 30 ? "Safe" : riskScore < 60 ? "Suspicious" : "Dangerous";
//   const series = [
//     Math.max(0, 100 - riskScore - 10),
//     Math.max(0, Math.min(100, Math.round(riskScore * 0.4))),
//     Math.max(0, Math.min(100, Math.round(riskScore * 0.6))),
//   ];
//   return {
//     url,
//     riskScore,
//     classification,
//     details: { sslValid, whoisAgeMonths, openPorts, securityHeaders, keywords, mlPhishingScore: ml },
//     pie: { series, labels: ["Safe", "Suspicious", "Dangerous"] },
//   };
// }
