// src/services/headersService.js

/**
 * Calls the backend Flask /api/check-headers endpoint,
 * sending a POST request with { url } as JSON,
 * and returns the parsed security header check results.
 * 
 * @param {string} url - The URL to check headers for.
 * @returns {Promise<Object>} - The API result, or throws error.
 */
export async function checkSecurityHeaders(url) {
  try {
    const res = await fetch("http://127.0.0.1:5001/api/check-headers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });
    if (!res.ok) {
      throw new Error(`Header check failed with status: ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.error("Security Headers API Error:", err);
    throw err;
  }
}
