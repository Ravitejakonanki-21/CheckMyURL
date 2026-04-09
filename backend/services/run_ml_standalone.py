#!/usr/bin/env python3
"""
Standalone script to run the ML model alone on a URL.
"""
import json
import sys
from ml_scoring import score_url_with_model, ModelNotAvailableError

def run_ml_alone(url: str):
    """Run ML model on a URL with minimal results data."""
    # Create minimal results dict - ML model will use defaults for missing fields
    results = {
        "ssl": {},
        "whois": {},
        "idn": {},
        "keyword": {},
        "rules": {},
        "headers": {},
    }
    
    try:
        output = score_url_with_model(url, results)
        return output
    except ModelNotAvailableError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"ML scoring failed: {str(e)}"}

if __name__ == "__main__":
    # Test URLs
    test_urls = [
        "https://example.com",
        "https://google.com",
        "https://suspicious-phishing-site-12345.com/verify/account",
        "http://test-url-with-dash.com/path?query=value",
    ]
    
    if len(sys.argv) > 1:
        # Use URL from command line
        url = sys.argv[1]
        output = run_ml_alone(url)
        print(json.dumps(output, indent=2))
    else:
        # Run on test URLs
        for url in test_urls:
            print("=" * 60)
            print(f"URL: {url}")
            print("-" * 60)
            output = run_ml_alone(url)
            print(json.dumps(output, indent=2))
            print()

