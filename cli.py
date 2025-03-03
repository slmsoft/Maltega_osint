import requests
import argparse

API_URL = "http://localhost:8000/analyze"

def analyze_url(url):
    response = requests.get(f"{API_URL}?url={url}")
    data = response.json()
    print("\n🔍 Анализ сайта:", url)
    
    print("\n📜 WHOIS:")
    for key, value in data["whois"].items():
        print(f"  {key}: {value}")
    
    print("\n🔐 SSL:")
    for key, value in data["ssl"].items():
        print(f"  {key}: {value}")
    
    print("\n🛡 VirusTotal:")
    print(f"  Status: {data['virustotal']}")
    
    print("\n🚨 AbuseIPDB:")
    print(f"  Reports: {data['abuseipdb']}")
    
    print("\n⚠ Google Safe Browsing:")
    print(f"  Threats: {data['google_safe_browsing']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CLI-анализатор фишинговых сайтов")
    parser.add_argument("url", help="URL для анализа")
    args = parser.parse_args()
    analyze_url(args.url)
