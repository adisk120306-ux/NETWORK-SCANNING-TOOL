#!/usr/bin/env python3

import argparse
import concurrent.futures
import ipaddress
import json
import os
import platform
import socket
import ssl
import time
from datetime import datetime
from html import escape


# =========================
# COLORS
# =========================

RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"


# =========================
# ARGUMENTS
# =========================

parser = argparse.ArgumentParser(
    description="CyberLab - Nmap-like network scanner"
)

parser.add_argument(
    "targets",
    nargs="+",
    help="IP, hostname, or IPv4 CIDR network"
)

parser.add_argument(
    "-p",
    "--ports",
    default="1-1024",
    help="Ports: 22,80,443 or 1-1000"
)

parser.add_argument(
    "--udp",
    action="store_true",
    help="Perform basic UDP probing"
)

parser.add_argument(
    "--http",
    action="store_true",
    help="Analyze HTTP/HTTPS services"
)

parser.add_argument(
    "--timeout",
    type=float,
    default=0.5,
    help="Socket timeout"
)

parser.add_argument(
    "--workers",
    type=int,
    default=100,
    help="Parallel workers"
)

parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Verbose output"
)

parser.add_argument(
    "--json",
    help="Save JSON report"
)

parser.add_argument(
    "--html",
    help="Save HTML report"
)

args = parser.parse_args()


# =========================
# PORT PARSING
# =========================

def parse_ports(value):

    ports = set()

    for part in value.split(","):

        part = part.strip()

        if not part:
            continue

        if "-" in part:

            start, end = part.split("-", 1)

            start = int(start)
            end = int(end)

            if start < 1 or end > 65535 or start > end:
                raise ValueError(
                    f"Invalid port range: {part}"
                )

            ports.update(range(start, end + 1))

        else:

            port = int(part)

            if port < 1 or port > 65535:
                raise ValueError(
                    f"Invalid port: {port}"
                )

            ports.add(port)

    return sorted(ports)


# =========================
# TARGET EXPANSION
# =========================

def expand_target(target):

    try:

        network = ipaddress.ip_network(
            target,
            strict=False
        )

        # Safety limit for this learning tool.
        if network.num_addresses > 4096:
            raise ValueError(
                "Network too large. Use a smaller authorized range."
            )

        return [
            str(ip)
            for ip in network.hosts()
        ]

    except ValueError:

        try:

            socket.gethostbyname(target)

            return [target]

        except socket.gaierror:

            raise ValueError(
                f"Cannot resolve target: {target}"
            )


# =========================
# DNS
# =========================

def resolve_target(target):

    try:

        ip = socket.gethostbyname(target)

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = target

        return ip, hostname

    except socket.gaierror:

        return None, None


# =========================
# SERVICE NAMES
# =========================

def get_service(port, protocol="tcp"):

    try:

        return socket.getservbyport(
            port,
            protocol
        )

    except OSError:

        return "unknown"


# =========================
# TCP SCAN
# =========================

def tcp_scan(ip, port, timeout):

    start = time.perf_counter()

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:

        result = sock.connect_ex(
            (ip, port)
        )

        elapsed = (
            time.perf_counter() - start
        )

        if result == 0:

            return {
                "protocol": "tcp",
                "port": port,
                "state": "open",
                "service": get_service(
                    port,
                    "tcp"
                ),
                "latency_ms":
                    round(elapsed * 1000, 2)
            }

        return {
            "protocol": "tcp",
            "port": port,
            "state": "closed",
            "service": get_service(
                port,
                "tcp"
            )
        }

    except socket.timeout:

        return {
            "protocol": "tcp",
            "port": port,
            "state": "filtered",
            "service": get_service(
                port,
                "tcp"
            )
        }

    except OSError as e:

        return {
            "protocol": "tcp",
            "port": port,
            "state": "error",
            "error": str(e)
        }

    finally:

        sock.close()


# =========================
# UDP PROBE
# =========================

def udp_scan(ip, port, timeout):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.settimeout(timeout)

    start = time.perf_counter()

    try:

        # Empty UDP probe.
        sock.sendto(
            b"",
            (ip, port)
        )

        try:

            data, address = sock.recvfrom(1024)

            elapsed = (
                time.perf_counter() - start
            )

            return {
                "protocol": "udp",
                "port": port,
                "state": "open",
                "service": get_service(
                    port,
                    "udp"
                ),
                "latency_ms":
                    round(elapsed * 1000, 2),
                "response_bytes":
                    len(data)
            }

        except socket.timeout:

            # No UDP response does NOT prove that
            # the port is open. Many UDP services
            # simply do not respond to empty packets.
            return {
                "protocol": "udp",
                "port": port,
                "state": "open|filtered",
                "service": get_service(
                    port,
                    "udp"
                )
            }

    except OSError as e:

        return {
            "protocol": "udp",
            "port": port,
            "state": "error",
            "error": str(e)
        }

    finally:

        sock.close()


# =========================
# HTTP ANALYZER
# =========================

def analyze_http(ip, port, timeout):

    result = {
        "port": port,
        "protocol": "https"
        if port == 443
        else "http"
    }

    try:

        sock = socket.create_connection(
            (ip, port),
            timeout=timeout
        )

        sock.settimeout(timeout)

        if port == 443:

            context = ssl.create_default_context()

            # We are inspecting the service rather
            # than validating the certificate.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = context.wrap_socket(
                sock,
                server_hostname=ip
            )

        request = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.sendall(
            request.encode()
        )

        data = sock.recv(4096)

        sock.close()

        text = data.decode(
            errors="replace"
        )

        lines = text.splitlines()

        if lines:

            result["status"] = lines[0]

        headers = {}

        for line in lines[1:]:

            if ":" in line:

                key, value = line.split(
                    ":",
                    1
                )

                headers[
                    key.strip()
                ] = value.strip()

        result["headers"] = headers

        if "Server" in headers:
            result["server"] = headers["Server"]

        return result

    except Exception as e:

        result["error"] = str(e)

        return result


# =========================
# BASIC LOCAL OS INFO
# =========================

def local_system_info(ip):

    local_addresses = {
        "127.0.0.1",
        "::1"
    }

    try:

        local_addresses.add(
            socket.gethostbyname(
                socket.gethostname()
            )
        )

    except Exception:
        pass

    if ip not in local_addresses:

        return {}

    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "hostname": socket.gethostname()
    }


# =========================
# HOST SCANNER
# =========================

def scan_host(target, ports):

    ip, hostname = resolve_target(target)

    if not ip:

        print(
            f"{RED}[-] Cannot resolve "
            f"{target}{RESET}"
        )

        return None

    print()
    print(
        f"{CYAN}"
        f"================================"
        f"{RESET}"
    )

    print(
        f"Target : {target}"
    )

    print(
        f"IP     : {ip}"
    )

    print(
        f"Host   : {hostname}"
    )

    print(
        f"Ports  : {len(ports)}"
    )

    print(
        f"{CYAN}"
        f"================================"
        f"{RESET}"
    )

    results = []

    start_time = time.perf_counter()

    # -------------------------
    # TCP
    # -------------------------

    print(
        f"\n{BLUE}"
        f"TCP scan"
        f"{RESET}"
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:

        jobs = [
            executor.submit(
                tcp_scan,
                ip,
                port,
                args.timeout
            )
            for port in ports
        ]

        for job in concurrent.futures.as_completed(
            jobs
        ):

            result = job.result()

            results.append(result)

            if result["state"] == "open":

                print(
                    f"{GREEN}"
                    f"{result['port']:<7}"
                    f"OPEN"
                    f"{RESET}"
                    f"  "
                    f"{result['service']}"
                )

            elif args.verbose:

                print(
                    f"{result['port']:<7}"
                    f"{result['state']}"
                )

    # -------------------------
    # UDP
    # -------------------------

    if args.udp:

        print(
            f"\n{BLUE}"
            f"UDP scan"
            f"{RESET}"
        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.workers
        ) as executor:

            jobs = [
                executor.submit(
                    udp_scan,
                    ip,
                    port,
                    args.timeout
                )
                for port in ports
            ]

            for job in concurrent.futures.as_completed(
                jobs
            ):

                result = job.result()

                results.append(result)

                if result["state"] in (
                    "open",
                    "open|filtered"
                ):

                    print(
                        f"{YELLOW}"
                        f"{result['port']:<7}"
                        f"{result['state']}"
                        f"{RESET}"
                        f"  "
                        f"{result['service']}"
                    )

    # -------------------------
    # HTTP
    # -------------------------

    if args.http:

        print(
            f"\n{BLUE}"
            f"HTTP analysis"
            f"{RESET}"
        )

        tcp_open = [
            r for r in results
            if r.get("protocol") == "tcp"
            and r.get("state") == "open"
            and r.get("port") in (
                80,
                443,
                8080,
                8000,
                8443
            )
        ]

        for item in tcp_open:

            http_result = analyze_http(
                ip,
                item["port"],
                args.timeout
            )

            item["http"] = http_result

            print(
                f"\nPort {item['port']}"
            )

            if "status" in http_result:

                print(
                    f"  Status: "
                    f"{http_result['status']}"
                )

            if "server" in http_result:

                print(
                    f"  Server: "
                    f"{http_result['server']}"
                )

    # -------------------------
    # SYSTEM INFO
    # -------------------------

    system = local_system_info(ip)

    if system:

        print(
            f"\n{BLUE}"
            f"Local system information"
            f"{RESET}"
        )

        for key, value in system.items():

            print(
                f"  {key}: {value}"
            )

    elapsed = (
        time.perf_counter()
        - start_time
    )

    open_tcp = [
        r for r in results
        if r.get("protocol") == "tcp"
        and r.get("state") == "open"
    ]

    print(
        f"\n{GREEN}"
        f"Open TCP ports: "
        f"{len(open_tcp)}"
        f"{RESET}"
    )

    print(
        f"Scan time: "
        f"{elapsed:.2f} seconds"
    )

    return {
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "system": system,
        "results": results,
        "scan_time": round(
            elapsed,
            2
        )
    }


# =========================
# HTML REPORT
# =========================

def make_html(data):

    rows = ""

    for host in data:

        for result in host["results"]:

            if result.get(
                "state"
            ) not in (
                "open",
                "open|filtered"
            ):
                continue

            rows += f"""
            <tr>
                <td>{escape(
                    host["target"]
                )}</td>

                <td>{escape(
                    host["ip"]
                )}</td>

                <td>{result["protocol"]}</td>

                <td>{result["port"]}</td>

                <td>{result["state"]}</td>

                <td>{escape(
                    result.get(
                        "service",
                        "unknown"
                    )
                )}</td>
            </tr>
            """

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>CyberLab Scan Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #111;
    color: #eee;
    padding: 30px;
}}

h1 {{
    color: #00e5ff;
}}

table {{
    border-collapse: collapse;
    width: 100%;
}}

th, td {{
    border: 1px solid #444;
    padding: 10px;
}}

th {{
    background: #222;
}}

tr:nth-child(even) {{
    background: #181818;
}}

</style>
</head>

<body>

<h1>CyberLab Scan Report</h1>

<p>
Generated:
{escape(datetime.now().isoformat())}
</p>

<table>

<tr>
<th>Target</th>
<th>IP</th>
<th>Protocol</th>
<th>Port</th>
<th>State</th>
<th>Service</th>
</tr>

{rows}

</table>

</body>
</html>
"""


# =========================
# MAIN
# =========================

try:

    ports = parse_ports(
        args.ports
    )

except ValueError as e:

    print(
        f"{RED}Error: {e}{RESET}"
    )

    raise SystemExit(1)


targets = []

for target in args.targets:

    try:

        targets.extend(
            expand_target(target)
        )

    except ValueError as e:

        print(
            f"{RED}{e}{RESET}"
        )


if not targets:

    print(
        "No valid targets."
    )

    raise SystemExit(1)


print(
    f"{CYAN}"
    f"""
╔══════════════════════════════════════╗
║          CYBERLAB SCANNER            ║
╚══════════════════════════════════════╝
"""
    f"{RESET}"
)

print(
    f"Targets : {len(targets)}"
)

print(
    f"Ports   : {args.ports}"
)

print(
    f"Workers : {args.workers}"
)

all_results = []

for target in targets:

    result = scan_host(
        target,
        ports
    )

    if result:

        all_results.append(
            result
        )


# =========================
# JSON REPORT
# =========================

if args.json:

    try:

        with open(
            args.json,
            "w"
        ) as f:

            json.dump(
                all_results,
                f,
                indent=4
            )

        print(
            f"\n{GREEN}"
            f"JSON saved to "
            f"{args.json}"
            f"{RESET}"
        )

    except OSError as e:

        print(
            f"{RED}"
            f"Could not save JSON: "
            f"{e}"
            f"{RESET}"
        )


# =========================
# HTML REPORT
# =========================

if args.html:

    try:

        html = make_html(
            all_results
        )

        with open(
            args.html,
            "w"
        ) as f:

            f.write(html)

        print(
            f"{GREEN}"
            f"HTML saved to "
            f"{args.html}"
            f"{RESET}"
        )

    except OSError as e:

        print(
            f"{RED}"
            f"Could not save HTML: "
            f"{e}"
            f"{RESET}"
        )


print(
    f"\n{GREEN}"
    f"Scan finished."
    f"{RESET}"
)
