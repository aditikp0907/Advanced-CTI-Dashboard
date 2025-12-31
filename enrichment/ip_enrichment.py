import json
import whois
import time

print("[+] Starting IOC enrichment...")

with open("../data/iocs.json", "r") as f:
    data = json.load(f)

enriched = []

for ip in data["ips"][:10]:  # limit to 10 for demo
    print(f"[+] Enriching {ip}")
    result = {
        "ip": ip,
        "whois": "N/A"
    }

    try:
        w = whois.whois(ip)
        result["whois"] = str(w)
    except Exception as e:
        result["whois"] = "Lookup failed"

    enriched.append(result)
    time.sleep(1)

with open("../data/enriched_iocs.json", "w") as f:
    json.dump(enriched, f, indent=4)

print("[+] IOC enrichment completed")
print("[+] Saved to data/enriched_iocs.json")
