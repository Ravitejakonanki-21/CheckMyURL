export function explain(result) {
  if (!result) return "No scan yet.";
  const parts = [];
  const { riskScore, classification, details } = result;
  parts.push(`Overall risk score is ${riskScore} classifying as ${classification}.`);
  if (!details.sslValid) parts.push("No HTTPS/SSL detected which increases risk.");
  if (details.whoisAgeMonths < 3) parts.push("Domain is newly registered which can indicate phishing.");
  if (details.mlPhishingScore > 60) parts.push("Machine learning score indicates likely phishing traits.");
  if (details.keywords.length) parts.push(`Detected risky keywords: ${details.keywords.join(", ")}.`);
  if (!parts.length) parts.push("No significant risks detected.");
  return parts.join(" ");
}
