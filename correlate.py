import json
import os
import requests
from datetime import datetime, timezone

DISCOVERY_FILE = "discovery_report.json"
OUTPUT_FILE = "vulnerabilities.json"

def load_discovery_report(filepath=DISCOVERY_FILE):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"'{filepath}' not found. Run discovery.py first.")
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def query_osv_for_package(package_name, ecosystem="npm"):
    """
    Queries Google OSV API for vulnerabilities affecting a package.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name.lower(),
            "ecosystem": ecosystem
        }
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get("vulns", [])
        else:
            print(f"[!] OSV query failed with status code {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"[!] Error querying OSV database: {e}")
        return []

def normalize_vulnerabilities(raw_vulns, component_name):
    normalized = []
    
    for item in raw_vulns:
        vuln_id = item.get("id", "UNKNOWN")
        summary = item.get("summary") or item.get("details", "No description available")
        
        # Extract CVSS score and severity vector if present
        severity_list = item.get("severity", [])
        cvss_score = "N/A"
        severity_rating = "UNKNOWN"
        
        for sev in severity_list:
            if sev.get("type") in ["CVSS_V3", "CVSS_V4"]:
                severity_rating = sev.get("score", "UNKNOWN")
                break

        # Check for related CVE IDs (e.g. GHSA mapping to CVE-XXXX-XXXXX)
        aliases = item.get("aliases", [])
        cve_aliases = [alias for alias in aliases if alias.startswith("CVE-")]

        normalized.append({
            "vuln_id": vuln_id,
            "cve_aliases": cve_aliases,
            "affected_component": component_name,
            "summary": summary[:250] + "..." if len(summary) > 250 else summary,
            "severity_vector": severity_rating,
            "published": item.get("published", "UNKNOWN"),
            "database_specific": item.get("database_specific", {}).get("severity", "MEDIUM")
        })

    return normalized

def main():
    print(f"[*] Reading scan output from {DISCOVERY_FILE}...")
    discovery_data = load_discovery_report()
    
    # Extract the web framework from the HTTP fingerprint
    http_data = discovery_data.get("http_fingerprint", {})
    powered_by = http_data.get("powered_by", "")
    
    detected_components = []
    if powered_by and powered_by.lower() != "none":
        detected_components.append(powered_by)
    
    # Fallback to Express if scanning a local Juice Shop instance
    if not detected_components:
        detected_components = ["express"]

    all_correlated_vulns = []

    for component in detected_components:
        print(f"[*] Querying OSV database for known vulnerabilities in: {component}...")
        raw_vulns = query_osv_for_package(component, ecosystem="npm")
        print(f"[+] Found {len(raw_vulns)} advisory entries for '{component}'.")
        
        # Take the top 10 most relevant/recent entries for analysis
        selected = raw_vulns[:10]
        parsed = normalize_vulnerabilities(selected, component)
        all_correlated_vulns.extend(parsed)

    correlation_output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": discovery_data.get("target", "127.0.0.1:3000"),
        "fingerprinted_technologies": detected_components,
        "total_vulnerabilities_found": len(all_correlated_vulns),
        "vulnerabilities": all_correlated_vulns
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(correlation_output, f, indent=2)

    print(f"\n[+] Vulnerability correlation complete! Saved to {OUTPUT_FILE}")
    print(f"[*] Total entries logged: {len(all_correlated_vulns)}")

if __name__ == "__main__":
    main()