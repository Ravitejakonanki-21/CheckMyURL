from flask import Flask, request, jsonify
from urllib.parse import urlparse
from services.ssl_check import check_ssl

app = Flask(__name__)

@app.post("/analyze")
def analyze():
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400

    # extract hostname
    parsed = urlparse(url if "://" in url else "https://" + url)
    hostname = parsed.hostname or url

    ssl_info = check_ssl(hostname)

    results = {"ssl": ssl_info}
    risk_score = 0
    label = "Safe"

    return jsonify({"url": url, "results": results, "risk_score": risk_score, "label": label})

if __name__ == "__main__":
    app.run(debug=True)
