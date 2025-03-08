import requests

def get_public_ip():
    try:
        return requests.get("https://api64.ipify.org?format=json").json()["ip"]
    except:
        return "Unknown"

def get_ip_details(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        return response
    except:
        return {}

def report_hacker(ip):
    api_key = "YOUR_API_KEY"
    url = "https://api.abuseipdb.com/api/v2/report"
    data = {"ip": ip, "categories": "18", "comment": "Dark web attack detected"}
    headers = {"Key": api_key, "Accept": "application/json"}
    requests.post(url, data=data, headers=headers)
