import json
from collections import defaultdict

print("[+] Starting IOC correlation...")

with open("../data/enriched_iocs.json", "r") as f:
    enriched = json.load(f)

correlation = defaultdict(list)

for entry in enriched:
    ip = entry["ip"]
    whois_data = entry.get("whois", "")

    # Simple but effective correlation logic
    if "abuse@" in whois_data:
        lines = whois_data.splitlines()
        for line in lines:
            if "abuse@" in line:
                correlation[line.strip()].append(ip)

results = []

for key, ips in correlation.items():
    if len(ips) > 1:
        results.append({
            "correlation_key": key,
            "related_ips": ips
        })

with open("../data/correlated_iocs.json", "w") as f:
    json.dump(results, f, indent=4)

print(f"[+] Correlation completed")
print(f"[+] Found {len(results)} correlated groups")
print("[+] Saved to data/correlated_iocs.json")
