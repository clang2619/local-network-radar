# 📡 Local Network Radar

A lightweight, real-time Layer 2 network reconnaissance tool built in Python. It maps active devices across a local subnet using Address Resolution Protocol (ARP) broadcasting and resolves hardware manufacturers via IEEE OUI database queries.

---

## 🛠️ Key Technical Features

* **Layer 2 Host Discovery:** Broadcasts raw Ethernet frames (`ff:ff:ff:ff:ff:ff`) to force replies from hosts that drop standard ICMP ping packets.
* **OUI Vendor Resolution:** Extracts the first 3 bytes of detected MAC addresses to dynamically query the MAC Vendors API.
* **In-Memory Caching:** Implements an internal lookup cache (`VENDOR_CACHE`) to eliminate redundant HTTP requests for identical hardware vendors.
* **Telemetry Dashboard:** Formats discovered hosts into an IP-sorted terminal interface using `rich`.

---

## 📸 Output & Proof of Concept

[Local Network Radar Dashboard](./radar_output.png)`

---

## 🧠 Engineering & Security Deep Dive

### 1. Layer 2 (ARP) vs. Layer 3 (ICMP) Reconnaissance
Standard network discovery tools frequently default to ICMP Echo Requests (pings). On modern operating systems (such as Windows with default firewall profiles), incoming ICMP traffic is silently dropped, rendering hosts invisible to Layer 3 scanners. 

Because devices inside a broadcast domain must resolve IP addresses to physical MAC addresses to communicate across a local switch or access point, hosts cannot ignore Layer 2 ARP requests without losing connectivity. Local Network Radar utilizes Scapy's encapsulation operator (`/`) to build and inject raw Ethernet frames directly onto the wire:

$$\text{Frame} = \text{Ether}(\text{dst}=\text{"ff:ff:ff:ff:ff:ff"}) \;/\; \text{ARP}(\text{pdst}=\text{"192.168.0.1/24"})$$

### 2. MAC Address Randomization Analysis
During local testing, several modern mobile devices returned `Unknown Vendor`. This occurs because modern mobile platforms (iOS, Android 10+) employ MAC address randomization for privacy:
* In randomized MAC addresses, the IEEE-assigned Organizationally Unique Identifier (OUI) is discarded.
* The locally administered bit (the second least-significant bit of the first byte) is set to `1` (identifiable by `x2:`, `x6:`, `xA:`, or `xE:` prefixes).
* These randomized frames prevent tracking across public networks and deliberately break static vendor lookups.

### 3. Socket Permissions
Transmitting raw Ethernet frames on Windows requires administrative privileges and access to the Npcap packet capture driver.

---

## 🚀 Installation & Usage

```powershell
# Clone the repository
git clone [https://github.com/clang2619/local-network-radar.git](https://github.com/clang2619/local-network-radar.git)
cd local-network-radar

# Install dependencies
py -m pip install -r requirements.txt

# Run scanner (Requires Administrator / elevated terminal)
py radar.py

---

# 🔍 Multi-Threaded Service Banner Grabber (`grabber.py`)

A concurrent TCP socket scanner designed to audit listening services and extract Application Layer (Layer 7) banners across discovered local assets.

### Features
* **Threaded Concurrency:** Leverages Python’s `concurrent.futures.ThreadPoolExecutor` to probe 20 target ports simultaneously, eliminating connection timeout latency.
* **Protocol Probing:** Automatically issues `HEAD / HTTP/1.1` probes against web-associated ports to parse HTTP `Server:` response headers.
* **Banner Extraction:** Captures service identification strings from standard administrative daemons (e.g., `lighttpd`, OpenSSH).

### Usage
```powershell
# Run interactively
py grabber.py

# Or pass a target IP directly via CLI
py grabber.py 192.168.0.1