import sys
import os

# Add backend to sys.path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from services.headers_check import check_headers

print("Starting headers check for google.com...")
try:
    result = check_headers("google.com")
    print("Headers check completed.")
    print(f"Status: {result.get('status')}")
    print(f"Final URL: {result.get('final_url')}")
except Exception as e:
    print(f"Error during headers check: {e}")
