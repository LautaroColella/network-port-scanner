import socket
import sys
import argparse
import psutil
import ipaddress
import subprocess
import concurrent.futures
import threading
import json
import requests

parser = argparse.ArgumentParser()
parser.add_argument("-i", type=str, help="Interface to scan")
parser.add_argument(
    "-t",
    type=int,
    help="Number of threads for host discovery and port scanning",
)
parser.add_argument(
    "-os", type=str, help="Host OS: windows|linux|macos default windows"
)
parser.add_argument(
    "-u", type=str, help="Destination server URL to send the scan results"
)
parser.add_argument(
    "-f", type=str, help="Destination file name to save the scan results"
)
args = parser.parse_args()
interface = args.i
num_threads = args.t
host_os = args.os if args.os else "windows"
url = args.u if args.u else "http://127.0.0.1/example/fake_url.php"
filename = args.f if args.f else "output.json"

stop_event = threading.Event()


def getIP():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


def getNetmaskBits():
    net_if_addrs = psutil.net_if_addrs()
    if interface in net_if_addrs:
        for addr in net_if_addrs[interface]:
            if addr.family == socket.AF_INET:
                return sum([bin(int(x)).count("1") for x in addr.netmask.split(".")])
    else:
        print(f"[!] Interface '{interface}' not found. Exiting...")
        sys.exit(1)


def is_reachable(ip, timeout=1):
    try:
        if host_os == "windows":
            subprocess.run(
                ["ping", "-n", "1", str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
            )
        else:
            subprocess.run(
                ["ping", "-c", "1", str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
            )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def scan_port(host, port):
    if stop_event.is_set():
        return None

    results = {"tcp": None, "udp": None}

    tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpSocket.settimeout(1)
    try:
        tcpSocket.connect((str(host), port))
        banner = tcpSocket.recv(1024)
        if banner:
            results["tcp"] = {
                "port": port,
                "banner": banner.decode("utf-8", errors="ignore").strip(),
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        results["tcp"] = None
    finally:
        tcpSocket.close()

    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpSocket.settimeout(1)
    try:
        udpSocket.sendto(b"", (str(host), port))
        banner, _ = udpSocket.recvfrom(1024)
        results["udp"] = {
            "port": port,
            "banner": banner.decode("utf-8", errors="ignore").strip(),
        }
    except (socket.timeout, OSError):
        results["udp"] = None
    finally:
        udpSocket.close()

    return results if results["tcp"] or results["udp"] else None


scan_results = {}


def scan_ports(host, use_multithreading, max_workers):
    scan_results[host] = {"tcp": [], "udp": []}

    if use_multithreading:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scan_port, host, port): port for port in range(1, 65536)
            }
            try:
                for future in concurrent.futures.as_completed(futures):
                    if stop_event.is_set():
                        print("[!] Scan interrupted. Exiting...")
                        break
                    result = future.result()
                    if result:
                        if result["tcp"]:
                            scan_results[host]["tcp"].append(result["tcp"])
                            print(
                                f"    [TCP/{result['tcp']['port']}] {result['tcp']['banner']}"
                            )
                        if result["udp"]:
                            scan_results[host]["udp"].append(result["udp"])
                            print(
                                f"    [UDP/{result['udp']['port']}] {result['udp']['banner']}"
                            )
            except KeyboardInterrupt:
                print("[!] Scan interrupted. Exiting...")
                stop_event.set()
                executor.shutdown(wait=False)
                sys.exit(0)
    else:
        for port in range(1, 65536):
            result = scan_port(host, port)
            if result:
                if result["tcp"]:
                    scan_results[host]["tcp"].append(result["tcp"])
                    print(
                        f"    [TCP/{result['tcp']['port']}] {result['tcp']['banner']}"
                    )
                if result["udp"]:
                    scan_results[host]["udp"].append(result["udp"])
                    print(
                        f"    [UDP/{result['udp']['port']}] {result['udp']['banner']}"
                    )


host_ip = getIP()
net_bits = getNetmaskBits()
network = [
    str(host) for host in ipaddress.IPv4Network(f"{host_ip}/{net_bits}", strict=False)
]

print(f"\n[-] Scanning {host_ip}/{net_bits} for active hosts...", end="\n\n")

reachable_hosts = []

if num_threads:
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_host = {
            executor.submit(is_reachable, host): host
            for host in network
            if host != host_ip
        }
        try:
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                if future.result():
                    reachable_hosts.append(host)
                    print(f"[+] Hello there {host}")
                if stop_event.is_set():
                    print("[!] Reachability check interrupted. Exiting...")
                    break
        except KeyboardInterrupt:
            print("[!] Reachability check interrupted. Exiting...")
            stop_event.set()
            sys.exit(0)
else:
    for host in network:
        if host == host_ip:
            continue
        try:
            if is_reachable(host):
                reachable_hosts.append(host)
                print(f"[+] Hello there {host}")
        except KeyboardInterrupt:
            print("[!] Reachability check interrupted. Exiting...")
            sys.exit(0)

for host in reachable_hosts:
    print(f"\n[-] Scanning {host} for open ports...")
    scan_ports(host, num_threads is not None, num_threads)

print("\n[!] Scan finished!")

print(f"\n\n[-] Sending results to '{url}'...")
try:
    requests.post(url, json=scan_results, timeout=1)
    print("[+] Results sent", end="\n\n")
except Exception as e:
    print(f"[!] Error while sending results: {e}", end="\n\n")

print(f"[-] Saving results in '{filename}'...")
try:
    with open(filename, "w") as json_file:
        json.dump(scan_results, json_file, indent=4)
        print("[+] Results saved")
except Exception as e:
    print(f"[!] Error while saving results: {e}")

print("[-] All done, goodbye!")
