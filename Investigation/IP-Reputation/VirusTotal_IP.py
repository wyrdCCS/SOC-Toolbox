import sys
import os
import requests
from tabulate import tabulate

#API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

API_KEY = "VT API Key"

def iplookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(response.text)
        return

    result = response.json()

    # VirusTotal stores most IP information under:
    # data -> attributes
    attributes = result["data"]["attributes"]

    # General IP information
    general_data = [
        ["IP Address", ip],
        ["Country", attributes.get("country", "N/A")],
        ["Continent", attributes.get("continent", "N/A")],
        ["Network", attributes.get("network", "N/A")],
        ["ASN", attributes.get("asn", "N/A")],
        ["AS Owner", attributes.get("as_owner", "N/A")],
        ["Regional Registry", attributes.get("regional_internet_registry", "N/A")]
    ]

    print("\nVIRUSTOTAL IP INFORMATION")

    print(tabulate(
        general_data,
        headers=["Field", "Value"],
        tablefmt="grid"
    ))

    # Analysis results
    stats = attributes.get("last_analysis_stats", {})

    analysis_data = [
        ["Malicious", stats.get("malicious", 0)],
        ["Suspicious", stats.get("suspicious", 0)],
        ["Harmless", stats.get("harmless", 0)],
        ["Undetected", stats.get("undetected", 0)],
        ["Timeout", stats.get("timeout", 0)]
    ]

    print("\nSECURITY VENDOR ANALYSIS")

    print(tabulate(
        analysis_data,
        headers=["Result", "Count"],
        tablefmt="grid"
    ))


if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <IP>")
    sys.exit(1)

ip = sys.argv[1]

iplookup(ip)