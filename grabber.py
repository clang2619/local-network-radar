import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table

console = Console()

# Expanded portfolio targeting standard services, smart home, and streaming ports
TARGET_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Legacy Remote)",
    53: "DNS (Name Resolution)",
    80: "HTTP (Web Admin)",
    139: "NetBIOS (File Share)",
    443: "HTTPS (Secure Web)",
    445: "SMB (Direct Host)",
    554: "RTSP (Media Streaming)",
    5000: "UPnP / AirPlay / SSDP",
    7000: "AirPlay Service",
    8000: "HTTP-Alt / Dev Server",
    8008: "HTTP Alt / Smart TV",
    8009: "Cast Protocol",
    8080: "HTTP-Proxy / Admin",
    8443: "HTTPS-Alt / Management",
    8888: "HTTP Alternative",
    9000: "Media Server / Diagnostics",
    49152: "UPnP Base Listener",
    49153: "UPnP Secondary Listener"
}

WEB_PORTS = {80, 443, 5000, 8000, 8008, 8080, 8443, 8888, 9000, 49152, 49153}

def scan_port(ip, port, service_hint):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.2)
    
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = "Open (No banner returned)"
            
            # Send an HTTP probe if the port is commonly web-based
            if port in WEB_PORTS:
                probe = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: RadarGrabber/1.0\r\n\r\n"
                s.send(probe.encode("utf-8"))
            
            raw_response = s.recv(1024).decode("utf-8", errors="ignore").strip()
            
            if raw_response:
                for line in raw_response.splitlines():
                    if line.lower().startswith("server:"):
                        banner = line.replace("Server:", "").strip()
                        break
                else:
                    banner = raw_response.splitlines()[0][:50]

            return {
                "port": str(port),
                "service": service_hint,
                "status": "OPEN",
                "banner": banner
            }
    except Exception:
        pass
    finally:
        s.close()
        
    return None

def audit_target(ip):
    console.print(f"\n[bold cyan]Auditing {ip} across {len(TARGET_PORTS)} service & IoT ports...[/bold cyan]")
    open_services = []

    # Run checks concurrently
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(scan_port, ip, port, hint)
            for port, hint in TARGET_PORTS.items()
        ]
        for future in futures:
            res = future.result()
            if res:
                open_services.append(res)

    # Sort results numerically by port number
    open_services.sort(key=lambda item: int(item["port"]))

    table = Table(title=f"Service Audit: {ip}", header_style="bold magenta")
    table.add_column("Port", justify="center", style="yellow")
    table.add_column("Service Type", style="cyan")
    table.add_column("State", justify="center", style="green")
    table.add_column("Identified Banner / Software", style="white")

    if open_services:
        for s in open_services:
            table.add_row(s["port"], s["service"], s["status"], s["banner"])
        console.print(table)
    else:
        console.print("[yellow]No open target ports detected on this host.[/yellow]")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target IP to audit: ").strip()
        
    audit_target(target)