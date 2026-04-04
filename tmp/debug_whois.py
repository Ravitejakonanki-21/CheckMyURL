import sys
import os

# Add backend to sys.path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from services.whois_check import check_whois

print("Starting WHOIS check for google.com...")
try:
    result = check_whois("google.com")
    print("WHOIS check completed.")
    print(f"Domain: {result.get('domain')}")
    print(f"Age: {result.get('age_days')} days")
except Exception as e:
    print(f"Error during WHOIS check: {e}")
