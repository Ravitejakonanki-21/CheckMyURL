import sys
import os

# Add backend to sys.path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from services.ssl_check import check_ssl

print("Starting SSL check for google.com...")
try:
    result = check_ssl("google.com")
    print("SSL check completed.")
    print(f"HTTPS OK: {result.get('https_ok')}")
    print(f"Issuer: {result.get('issuer_cn')}")
except Exception as e:
    print(f"Error during SSL check: {e}")
