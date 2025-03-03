from fastapi import FastAPI, Query
import requests
import  whois
import ssl 
import socket
from urllib.parse import urlparse

app = FastAPI()

# 🔐 API-ключи (убери их в .env для безопасности)
VIRUSTOTAL_API_KEY = "f9bd5589a60fcadc0c2e48c13ba7443e5fcfbb01d76f06b854d8c923462965e2"
ABUSEIPDB_API_KEY = "fb03d40c3cfc3d6a59c1eaa2b950f7432dcbb2357ca0a44394caedf8d72695eed30f8f7f0bc430b5"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyDwVLhXvrFHQ8GrfYHM7h2I_9ZekJSDv1M"


# 🔍 Функция для извлечения домена из URL (убирает https://, www.)
def extract_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc if parsed_url.netloc else url


# 🕵 WHOIS-информация о домене
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "created_date": str(w.creation_date),
            "updated_date": str(w.updated_date),
            "expiration_date": str(w.expiration_date),
            "registrar": w.registrar,
            "name_servers": w.name_servers,
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}


# 🔐 Проверка SSL-сертификата
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        return {
            "issuer": dict(x[0] for x in cert["issuer"]),
            "valid_from": cert["notBefore"],
            "valid_until": cert["notAfter"],
        }
    except Exception:
        return {"error": "SSL check failed (possible no HTTPS or expired cert)"}


# 🛡️ Проверка в VirusTotal
def scan_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
        return response.json() if response.status_code == 200 else {"error": "VirusTotal request failed"}
    except Exception as e:
        return {"error": f"VirusTotal API error: {str(e)}"}


# 🚨 Проверка IP в AbuseIPDB
def check_abuseipdb(ip):
    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
        return response.json() if response.status_code == 200 else {"error": "AbuseIPDB request failed"}
    except Exception as e:
        return {"error": f"AbuseIPDB API error: {str(e)}"}


# ⚠️ Проверка через Google Safe Browsing
def google_safe_browsing(url):
    try:
        payload = {
            "client": {"clientId": "phishing-checker", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
        )
        return response.json() if response.status_code == 200 else {"error": "Google Safe Browsing request failed"}
    except Exception as e:
        return {"error": f"Google Safe Browsing API error: {str(e)}"}


# 🔍 Главная API-функция анализа сайта
@app.get("/analyze")
def analyze(url: str = Query(...)):
    try:
        clean_domain = extract_domain(url)  # Убираем http://, https://
        ip = socket.gethostbyname(clean_domain)  # Получаем IP

        result = {
            "url": url,
            "domain": clean_domain,
            "whois": get_whois_info(clean_domain),
            "ssl": check_ssl(clean_domain),
            "virustotal": scan_virustotal(url),
            "abuseipdb": check_abuseipdb(ip),
            "google_safe_browsing": google_safe_browsing(url),
        }
        return result

    except socket.gaierror:
        return {"error": "Failed to resolve domain. Check if the website is online."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


# 🚀 Запуск сервера Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
