import ctypes
from ctypes import wintypes
import socket
import struct
import subprocess
import time
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

from .network_info import get_primary_adapter
from .vendor_lookup import get_vendor_info
from .port_scanner import check_target_ports, get_netbios_hostname, get_reverse_dns, get_web_title
from .device_classifier import classify_device
from .db import record_scan

iphlpapi = ctypes.windll.iphlpapi
ws2_32 = ctypes.windll.ws2_32

def send_arp_probe(ip_str):
    """
    Direct ARP query using Windows SendARP API.
    Returns: {"mac": str, "latency_ms": float} or None
    """
    try:
        dest_addr = ws2_32.inet_addr(ip_str.encode('ascii'))
        mac_addr = (ctypes.c_byte * 6)()
        mac_len = wintypes.ULONG(6)
        
        t0 = time.time()
        ret = iphlpapi.SendARP(dest_addr, 0, ctypes.byref(mac_addr), ctypes.byref(mac_len))
        dt = (time.time() - t0) * 1000
        
        if ret == 0:
            mac_hex = ':'.join(f"{b & 0xFF:02X}" for b in mac_addr)
            return {"mac": mac_hex, "latency_ms": round(dt, 1)}
    except Exception:
        pass
    return None

def get_system_arp_table():
    """
    Parses Windows system ARP table (arp -a).
    Useful to immediately identify all active devices across all subnets seen by Windows.
    """
    entries = {}
    try:
        res = subprocess.run(['arp', '-a'], capture_output=True, text=True, errors='ignore')
        for line in res.stdout.splitlines():
            line = line.strip()
            # Match: IP, MAC, Type
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)', line)
            if match:
                ip, raw_mac, ip_type = match.groups()
                mac = raw_mac.replace('-', ':').upper()
                # Skip broadcast and multicast addresses
                if not (ip.endswith('.255') or ip.startswith('224.') or ip.startswith('239.') or mac == 'FF:FF:FF:FF:FF:FF'):
                    entries[ip] = mac
    except Exception:
        pass
    return entries

class NetworkScanner:
    def __init__(self):
        self.is_scanning = False
        self.should_stop = False
        self.progress = 0
        self.total_targets = 0
        self.current_scanned = 0
        self.devices = []
        self.scan_stats = {}
        self.last_scan_time = None

    def scan(self, target_cidr=None, target_ip=None, target_netmask=None, custom_range=None, deep_scan=True, progress_cb=None):
        """
        Executes a high-speed network scan and returns full device analysis and IP stats.
        Dynamically calculates the network scope, host boundaries, and available IPs based on the subnet mask.
        """
        self.is_scanning = True
        self.should_stop = False
        self.progress = 0
        self.devices = []
        start_time = time.time()

        # 1. Determine active network adapter
        adapter = get_primary_adapter()
        local_ip = adapter.get("ip") if adapter else "127.0.0.1"
        gateway_ip = adapter.get("gateway") if adapter else None
        
        # 2. Determine target IP list dynamically by netmask or custom range
        target_ips = []
        scope_name = ""
        netmask_str = ""
        prefix_len = 24
        total_network_ips = 256
        usable_hosts_count = 254
        first_usable_ip = ""
        last_usable_ip = ""

        if custom_range and len(custom_range) == 2:
            start_ip, end_ip = custom_range
            try:
                start_int = int(ipaddress.IPv4Address(start_ip))
                end_int = int(ipaddress.IPv4Address(end_ip))
                target_ips = [str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)]
                scope_name = f"{start_ip} - {end_ip}"
                netmask_str = "Faixa Manual"
                usable_hosts_count = len(target_ips)
                total_network_ips = len(target_ips)
                first_usable_ip = start_ip
                last_usable_ip = end_ip
            except Exception:
                pass

        if not target_ips:
            net = None
            if target_ip and target_netmask:
                try:
                    net = ipaddress.IPv4Network(f"{target_ip}/{target_netmask}", strict=False)
                except Exception:
                    pass
            elif target_cidr:
                try:
                    net = ipaddress.IPv4Network(target_cidr, strict=False)
                except Exception:
                    pass

            if not net and adapter and adapter.get("cidr"):
                # Use primary adapter's detected scope, identified by its real subnet mask
                try:
                    net = ipaddress.IPv4Network(adapter["cidr"], strict=False)
                except Exception:
                    pass

            if net:
                scope_name = str(net)
                netmask_str = str(net.netmask)
                prefix_len = net.prefixlen
                total_network_ips = net.num_addresses
                target_ips = [str(ip) for ip in net.hosts()]
                usable_hosts_count = len(target_ips)
                if target_ips:
                    first_usable_ip = target_ips[0]
                    last_usable_ip = target_ips[-1]

                # Dynamically resolve local IP and gateway for this specific chosen subnet
                if adapter:
                    all_scopes = adapter.get("all_scopes") or adapter.get("scopes") or []
                    for sc in all_scopes:
                        try:
                            sc_ip = sc.get("ip")
                            if sc_ip and ipaddress.IPv4Address(sc_ip) in net:
                                local_ip = sc_ip
                                break
                        except Exception:
                            pass
                    try:
                        if gateway_ip and ipaddress.IPv4Address(gateway_ip) not in net:
                            gateway_ip = None
                    except Exception:
                        gateway_ip = None

        if not target_ips:
            # Fallback to local /24
            ip_parts = local_ip.split('.')
            local_c_block = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            net = ipaddress.IPv4Network(local_c_block, strict=False)
            scope_name = local_c_block
            netmask_str = "255.255.255.0"
            prefix_len = 24
            total_network_ips = 256
            target_ips = [str(ip) for ip in net.hosts()]
            usable_hosts_count = len(target_ips)
            if target_ips:
                first_usable_ip = target_ips[0]
                last_usable_ip = target_ips[-1]

        self.total_targets = len(target_ips)
        self.current_scanned = 0

        # Query existing system ARP cache (instant local active hosts)
        arp_cache = get_system_arp_table()

        # Concurrent SendARP ping sweep
        alive_hosts = {} # ip -> {mac, latency_ms}

        def worker(ip):
            if self.should_stop:
                return None
            res = send_arp_probe(ip)
            if res:
                return ip, res
            # Check if this IP is our local IP
            if ip == local_ip:
                return ip, {"mac": adapter.get("mac", "LOCAL"), "latency_ms": 0.1}
            # Check if it was in ARP cache
            if ip in arp_cache:
                return ip, {"mac": arp_cache[ip], "latency_ms": 1.0}
            return None

        # Dynamically scale workers based on scope size for maximum throughput
        if self.total_targets <= 256:
            worker_threads = 60
        elif self.total_targets <= 1024:
            worker_threads = 100
        elif self.total_targets <= 4096:
            worker_threads = 160
        else:
            worker_threads = 250

        step_report = max(1, self.total_targets // 100)

        with ThreadPoolExecutor(max_workers=worker_threads) as executor:
            futures = [executor.submit(worker, ip) for ip in target_ips]
            for fut in futures:
                if self.should_stop:
                    break
                self.current_scanned += 1
                self.progress = int((self.current_scanned / max(1, self.total_targets)) * 70)
                if progress_cb and (self.current_scanned % step_report == 0 or self.current_scanned == self.total_targets):
                    progress_cb(self.progress, f"Verificando IPs ({self.current_scanned}/{self.total_targets}) - {len(alive_hosts)} ativos...")
                res = fut.result()
                if res:
                    ip, data = res
                    alive_hosts[ip] = data

        # Also incorporate any ARP cache hosts that are in the target network
        for ip, mac in arp_cache.items():
            if ip not in alive_hosts and ip != local_ip:
                if ip in target_ips:
                    alive_hosts[ip] = {"mac": mac, "latency_ms": 1.5}

        # Second phase: Deep device enrichment (Hostnames, Ports, Vendors, Categories)
        discovered_devices = []
        total_alive = len(alive_hosts)
        enriched_count = 0

        def enrich_device(item):
            ip, data = item
            mac = data.get("mac")
            latency = data.get("latency_ms", 1.0)
            
            # Vendor lookup
            vendor_info = get_vendor_info(mac)
            
            # Hostname detection
            hostname = None
            if ip == local_ip:
                hostname = socket.gethostname()
            else:
                # Try Reverse DNS
                hostname = get_reverse_dns(ip)
                if not hostname:
                    hostname = get_netbios_hostname(ip)

            # Port checks
            open_ports = []
            web_title = None
            if deep_scan:
                open_ports = check_target_ports(ip)
                if any(p in open_ports for p in [80, 8080, 443]):
                    web_title = get_web_title(ip, open_ports)

            # Categorize
            classification = classify_device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor_info=vendor_info,
                open_ports=open_ports,
                web_title=web_title,
                gateway_ip=gateway_ip,
                local_ip=local_ip
            )

            device_item = {
                "ip": ip,
                "mac": mac,
                "latency_ms": latency,
                "hostname": hostname or "",
                "display_name": classification["display_name"],
                "category": classification["category"],
                "category_label": classification["category_label"],
                "icon": classification["icon"],
                "vendor": vendor_info.get("vendor", "Desconhecido"),
                "is_random_mac": vendor_info.get("is_randomized", False),
                "open_ports": open_ports,
                "web_title": web_title or "",
                "notes": classification.get("notes", ""),
                "is_custom": classification.get("is_custom", False),
                "is_gateway": (ip == gateway_ip),
                "is_local": (ip == local_ip),
                "status": "online"
            }
            return device_item

        # Enrich discovered devices concurrently
        with ThreadPoolExecutor(max_workers=20) as enrich_executor:
            futures = [enrich_executor.submit(enrich_device, item) for item in alive_hosts.items()]
            for fut in futures:
                if self.should_stop:
                    break
                dev = fut.result()
                if dev:
                    discovered_devices.append(dev)
                enriched_count += 1
                self.progress = 70 + int((enriched_count / max(1, total_alive)) * 30)
                if progress_cb:
                    progress_cb(self.progress, f"Classificando dispositivos ({enriched_count}/{total_alive})...")

        # Sort devices by IP address naturally
        try:
            discovered_devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
        except Exception:
            pass

        duration = round(time.time() - start_time, 2)
        occupied_ips = len(discovered_devices)
        total_ips = len(target_ips)
        free_ips = max(0, total_ips - occupied_ips)
        occupancy_rate = round((occupied_ips / max(1, total_ips)) * 100, 1)

        # Build list of free IP addresses
        occupied_ip_set = {d["ip"] for d in discovered_devices}
        free_ip_list = [ip for ip in target_ips if ip not in occupied_ip_set]

        # Category counters
        categories_count = {
            "computers": 0,
            "phones": 0,
            "printers": 0,
            "network": 0,
            "media": 0,
            "iot": 0,
            "unknown": 0
        }
        for d in discovered_devices:
            c = d.get("category", "unknown")
            if c in categories_count:
                categories_count[c] += 1
            else:
                categories_count["unknown"] += 1

        self.devices = discovered_devices
        self.scan_stats = {
            "scope": scope_name,
            "cidr": scope_name,
            "netmask": netmask_str,
            "prefix_len": prefix_len,
            "first_usable_ip": first_usable_ip,
            "last_usable_ip": last_usable_ip,
            "total_ips": total_network_ips,
            "usable_ips": usable_hosts_count,
            "occupied_ips": occupied_ips,
            "free_ips": free_ips,
            "occupancy_rate": occupancy_rate,
            "duration_sec": duration,
            "categories": categories_count,
            "adapter": adapter,
            "free_ips_sample": free_ip_list[:254], # for grid visualization
            "total_free_count": len(free_ip_list),
            "scanned_at": time.strftime("%d/%m/%Y %H:%M:%S")
        }
        self.is_scanning = False
        self.progress = 100

        # Record to DB history
        try:
            record_scan(
                interface=adapter.get("adapter_name", "Local"),
                subnet=scope_name,
                total_ips=total_ips,
                occupied_ips=occupied_ips,
                free_ips=free_ips,
                duration_sec=duration
            )
        except Exception:
            pass

        return {
            "stats": self.scan_stats,
            "devices": self.devices
        }

    def stop(self):
        self.should_stop = True
        self.is_scanning = False
