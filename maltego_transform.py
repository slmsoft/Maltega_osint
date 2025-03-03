from maltego_trx.maltego import MaltegoTransform
import requests

API_URL = "http://localhost:8000/analyze"

def phishing_check(maltego_input):
    url = maltego_input.Value
    response = requests.get(f"{API_URL}?url={url}")
    data = response.json()
    
    transform = MaltegoTransform()
    entity = transform.addEntity("maltego.URL", url)
    entity.addProperty("whois", "whois", "strict", str(data["whois"]))
    entity.addProperty("ssl", "ssl", "strict", str(data["ssl"]))
    transform.returnOutput()

if __name__ == "__main__":
    phishing_check()
