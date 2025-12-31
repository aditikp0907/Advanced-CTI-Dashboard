import json

print("[+] Starting MITRE ATT&CK mapping...")

with open("../data/correlated_iocs.json", "r") as f:
    correlated = json.load(f)

mitre_results = []

for group in correlated:
    entry = {
        "correlation_key": group["correlation_key"],
        "related_ips": group["related_ips"],
        "mitre_mapping": []
    }

    # Rule-based MITRE mapping (simple & explainable)
    entry["mitre_mapping"].append({
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol (T1071)"
    })

    entry["mitre_mapping"].append({
        "tactic": "Lateral Movement",
        "technique": "Remote Services (T1021)"
    })

    if len(group["related_ips"]) >= 3:
        entry["mitre_mapping"].append({
            "tactic": "Credential Access",
            "technique": "Unsecured Credentials (T1552)"
        })

    mitre_results.append(entry)

with open("../data/mitre_mapped_iocs.json", "w") as f:
    json.dump(mitre_results, f, indent=4)

print("[+] MITRE mapping completed")
print("[+] Saved to data/mitre_mapped_iocs.json")
