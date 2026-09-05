# Local Network Radar 📡

A Python-based Layer 2 network reconnaissance tool that maps active devices on a local subnet using Scapy and identifies hardware manufacturers via OUI API lookups.

## Features
* **Layer 2 Discovery:** Uses ARP frame broadcasts (`ff:ff:ff:ff:ff:ff`) to bypass host-level ICMP ping drops.
* **Hardware Identification:** Queries the MAC Vendors REST API using the 3-byte Organizationally Unique Identifier (OUI).
* **Caching Layer:** In-memory caching prevents redundant external API lookups for identical vendor prefixes.
* **Terminal UI:** Formats live findings into an IP-sorted table using `rich`.

## Installation & Usage

```bash
# Install dependencies
py -m pip install -r requirements.txt

# Run scanner (requires elevated privileges on Windows for raw socket access)
py radar.py
```

## Privacy & Security Note
Modern mobile OS platforms (iOS, Android) default to MAC address randomization. Addresses showing randomized bits will report as "Unknown Vendor" because their locally administered OUIs do not exist in the IEEE hardware database.