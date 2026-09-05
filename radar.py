import requests
from scapy.all import ARP, Ether, srp
from rich.console import Console
from rich.table import Table

console = Console()

#In-Memory doctionary so we don't query the API twice for the same brand
VENDOR_CACHE = {}

def get_vendor(mac):
    # Check the first 8 characters of the MAC (OUI) to see if we have it cached
    oui = mac.upper()[0:8]
    if oui in VENDOR_CACHE:
        return VENDOR_CACHE[oui]

    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=1.5)
        if response.status_code == 200:
            vendor = response.text.strip()
            VENDOR_CACHE[oui] = vendor  # Cache the result
            return vendor
        else:
            return "Unknown Vendor"
    except Exception:
        return "Unknown Vendor"

#---PACKET ENGINE---
#Wrap the packet in a broadcast envelope for layer 2
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
#ARP question 
arp_request = ARP(pdst="192.168.0.1/24")
#Stack them
packet = broadcast/arp_request
#Send the packet and receive the response
print("[*]Scanning the network...")
answered, unanswered = srp(packet, timeout=2, verbose=False)
#Unpack the response and print the IP and MAC addresses
print("\n[*] Resolving hardware vendors...\n")
for sent, received in answered:
    vendor = get_vendor(received.hwsrc)
    print(f"IP: {received.psrc:<15} | MAC: {received.hwsrc} | Vendor: {vendor}")

# --- Collecting and Formatting Results ---
devices = []
print("\n[*] Parsing scan results...")

for sent, received in answered:
    vendor = get_vendor(received.hwsrc)
    devices.append({
        "ip": received.psrc,
        "mac": received.hwsrc.upper(),
        "vendor": vendor
    })

# Sort by IP address numerically
devices.sort(key=lambda d: [int(octet) for octet in d["ip"].split(".")])

# Build the rich visual table
table = Table(title="[bold red]📡 Local Network Radar 📡[/bold red]", show_header=True, header_style="bold magenta")
table.add_column("Status", justify="center", style="green")
table.add_column("IP Address", style="cyan", justify="left")
table.add_column("MAC Address", style="yellow", justify="left")
table.add_column("Hardware Vendor / OUI", style="white", justify="left")

for dev in devices:
    status_badge = "[bold green]ONLINE[/bold green]"
    table.add_row(status_badge, dev["ip"], dev["mac"], dev["vendor"])

console.print(table)
console.print(f"[bold green]✓ Scan Complete:[/bold green] [bold yellow]{len(devices)}[/bold yellow] devices mapped.\n")