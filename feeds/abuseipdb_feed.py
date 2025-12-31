import requests
import json
import os

print("[+] Fetching malicious IPs from public AbuseIPDB feed...")

url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
response = requests.get(url)

if response.status_code != 200:
    print("[-] Failed to fetch threat feed")
    exit()

ips = []
for line in response.text.splitlines():
    if line and not line.startswith("#"):
        ip = line.split()[0]
        ips.append(ip)

data = {
    "source": "AbuseIPDB Public Feed",
    "ioc_type": "malicious_ips",
    "count": len(ips),
    "ips": ips[:50]  # limit for demo
}

os.makedirs("../data", exist_ok=True)

with open("../data/iocs.json", "w") as f:
    json.dump(data, f, indent=4)

print(f"[+] Collected {len(data['ips'])} malicious IPs")
print("[+] Saved to data/iocs.json")
