import sys
import os
from shodan import Shodan
from tabulate import tabulate

#API_KEY = os.environ.get("SHODAN_API_KEY")

API_KEY = "Shodan API Key"

api = Shodan(API_KEY)

def iplookup(ip):
    # Query Shodan
    ipinfo = api.host(ip)

    # Build host information table
    general_data = [
        ["IP Address", ipinfo.get("ip_str", "N/A")],
        ["Organization", ipinfo.get("org", "N/A")],
        ["ISP", ipinfo.get("isp", "N/A")],
        ["Operating System", ipinfo.get("os", "N/A")],
        ["Country", ipinfo.get("country_name", "N/A")],
        ["City", ipinfo.get("city", "N/A")],
        ["Hostnames", ", ".join(ipinfo.get("hostnames", []))],
        ["Open Ports", ", ".join(map(str, ipinfo.get("ports", [])))]
    ]

    print("\nSHODAN IP INFORMATION")
    print(tabulate(
        general_data,
        headers=["Field", "Value"],
        tablefmt="grid"
    ))

    # Build services table
    services = []

    for service in ipinfo.get("data", []):
        services.append([
            service.get("port", "N/A"),
            service.get("transport", "N/A"),
            service.get("_shodan", {}).get("module", "N/A"),
            service.get("product", "N/A"),
            service.get("version", "N/A")
        ])

    print("\nSERVICES")
    print(tabulate(
        services,
        headers=["Port", "Protocol", "Service", "Product", "Version"],
        tablefmt="grid"
    ))


# Make sure an IP was supplied
if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <IP>")
    sys.exit(1)

# Get IP from command line
ip = sys.argv[1]

# Run lookup
iplookup(ip)