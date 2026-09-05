import socket
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table

console = Console()

# Target ports commonly hosting manageable services or banners
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Proxy / Alt",
    8443: "HTTPS-Alt"
}

def scan_port(ip, port, service_hint):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = "Open (No banner returned)"
            
            # Send an HTTP probe for web ports
            if port in [80, 8080, 443, 8443]:
                probe = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: RadarGrabber/1.0\r\n\r\n"
                s.send(probe.encode("utf-8"))
            
            # Catch immediate banners (SSH, FTP) or HTTP server headers
            raw_response = s.recv(1024).decode("utf-8", errors="ignore").strip()
            
            if raw_response:
                # Parse HTTP 'Server:' header if present
                for line in raw_response.splitlines():
                    if line.lower().startswith("server:"):
                        banner = line.replace("Server:", "").strip()
                        break
                else:
                    # Otherwise take the raw first line (e.g., SSH-2.0-OpenSSH...)
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
    console.print(f"\n[bold cyan]Initiating multi-threaded port audit on {ip}...[/bold cyan]")
    open_services = []

    # Fire all port probes concurrently across worker threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(scan_port, ip, port, hint)
            for port, hint in COMMON_PORTS.items()
        ]
        for future in futures:
            res = future.result()
            if res:
                open_services.append(res)

    # Render results table
    table = Table(title=f"Service Audit: {ip}", header_style="bold magenta")
    table.add_column("Port", justify="center", style="yellow")
    table.add_column("Standard Service", style="cyan")
    table.add_column("State", justify="center", style="green")
    table.add_column("Identified Banner / Software", style="white")

    if open_services:
        for s in open_services:
            table.add_row(s["port"], s["service"], s["status"], s["banner"])
        console.print(table)
    else:
        console.print("[yellow]No open common management ports detected.[/yellow]")

if __name__ == "__main__":
    import sys
    
    # If passed via command line (e.g. py grabber.py 192.168.0.146)
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target IP to audit: ").strip()
        
    audit_target(target)