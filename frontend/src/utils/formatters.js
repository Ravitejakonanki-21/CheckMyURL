/**
 * formatters.js — shared display helpers used across result pages.
 */

/**
 * Format a date value (string, Date, or null) into a human-readable string.
 * @param {string|Date|null|undefined} value
 * @param {string} fallback
 * @returns {string}
 */
export function formatDate(value, fallback = "N/A") {
  if (!value) return fallback;
  try {
    const d = new Date(value);
    if (isNaN(d.getTime())) return fallback;
    return d.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return fallback;
  }
}

/**
 * Format a date with time.
 * @param {string|Date|null|undefined} value
 * @param {string} fallback
 * @returns {string}
 */
export function formatDateTime(value, fallback = "N/A") {
  if (!value) return fallback;
  try {
    const d = new Date(value);
    if (isNaN(d.getTime())) return fallback;
    return d.toLocaleString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return fallback;
  }
}

/**
 * Format a number as a percentage string.
 * @param {number|null|undefined} value - 0-100 range
 * @param {number} decimals
 * @returns {string}
 */
export function formatPercent(value, decimals = 0) {
  if (value === null || value === undefined || isNaN(value)) return "N/A";
  return `${Number(value).toFixed(decimals)}%`;
}

/**
 * Format a risk score (0-100) with a label.
 * @param {number} score
 * @returns {{ label: string, color: string }}
 */
export function riskMeta(score) {
  if (score >= 70) return { label: "High Risk", color: "#DD0303" };
  if (score >= 40) return { label: "Medium Risk", color: "#FAB12F" };
  return { label: "Low Risk", color: "#22c55e" };
}

/**
 * Format domain age in days to a human-friendly string.
 * @param {number|null|undefined} days
 * @returns {string}
 */
export function formatDomainAge(days) {
  if (days === null || days === undefined || isNaN(days)) return "Unknown";
  if (days < 1) return "Less than a day";
  if (days < 30) return `${days} day${days !== 1 ? "s" : ""}`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months} month${months !== 1 ? "s" : ""}`;
  const years = Math.floor(months / 12);
  const remMonths = months % 12;
  return remMonths > 0
    ? `${years}y ${remMonths}m`
    : `${years} year${years !== 1 ? "s" : ""}`;
}

/**
 * Truncate a long string to maxLen chars with an ellipsis.
 * @param {string} str
 * @param {number} maxLen
 * @returns {string}
 */
export function truncate(str, maxLen = 60) {
  if (!str) return "";
  return str.length <= maxLen ? str : `${str.slice(0, maxLen)}…`;
}

/**
 * Safely return a value or a fallback string.
 * @param {*} value
 * @param {string} fallback
 * @returns {*}
 */
export function orFallback(value, fallback = "N/A") {
  if (value === null || value === undefined || value === "") return fallback;
  return value;
}
