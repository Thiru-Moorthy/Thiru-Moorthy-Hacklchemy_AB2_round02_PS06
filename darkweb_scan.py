import requests

# Define Tor SOCKS5 proxy
proxies = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

# Example onion website (change to actual dark web link)
darkweb_url = "http://check.torproject.org"  # This will confirm if you're using Tor

try:
    response = requests.get(darkweb_url, proxies=proxies, timeout=10)
    print("✅ Dark Web Response:", response.text[:500])  # Print first 500 chars
except requests.RequestException as e:
    print("❌ Could not connect to the Dark Web:", e)
