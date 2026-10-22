import subprocess
import socket
import ipaddress
import re

def calculate_network_scope(ip, netmask=None, prefix_len=None, gateway=None):
    """
    Calculates detailed network scope given an IP and its netmask or prefix length.
    Returns:
    {
        "ip": str,
        "netmask": str,
        "prefix_len": int,
        "cidr": str,
        "network_ip": str,
        "broadcast_ip": str,
        "first_usable_ip": str,
        "last_usable_ip": str,
        "total_ips": int,
        "usable_ips": int,
        "gateway": str,
        "is_gateway_scope": bool,
        "display_label": str
    }
    """
    if not ip:
        return None

    try:
        if prefix_len is not None:
            net = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
        elif netmask:
            net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        else:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        
        prefix = net.prefixlen
        total_ips = net.num_addresses

        if prefix <= 30:
            usable_ips = max(0, total_ips - 2)
            first_ip = str(ipaddress.IPv4Address(int(net.network_address) + 1))
            last_ip = str(ipaddress.IPv4Address(int(net.broadcast_address) - 1))
        else:
            usable_ips = total_ips
            first_ip = str(net.network_address)
            last_ip = str(net.broadcast_address)

        is_gateway_scope = False
        if gateway and gateway != "N/A":
            try:
                gw_addr = ipaddress.IPv4Address(gateway)
                is_gateway_scope = (gw_addr in net)
            except Exception:
                pass

        cidr_str = str(net)
        label = f"{cidr_str} (Máscara: {net.netmask}) - {usable_ips:,} IPs utilizáveis".replace(",", ".")

        return {
            "ip": ip,
            "netmask": str(net.netmask),
            "prefix_len": prefix,
            "cidr": cidr_str,
            "network_ip": str(net.network_address),
            "broadcast_ip": str(net.broadcast_address),
            "first_usable_ip": first_ip,
            "last_usable_ip": last_ip,
            "total_ips": total_ips,
            "usable_ips": usable_ips,
            "gateway": gateway or "N/A",
            "is_gateway_scope": is_gateway_scope,
            "display_label": label
        }
    except Exception:
        return None

def get_network_adapters():
    """
    Parses Windows network adapters extracting all IP bindings and corresponding netmasks.
    Calculates detailed network scopes dynamically for every binding.
    """
    adapters = []
    try:
        res = subprocess.run(
            ['ipconfig', '/all'],
            capture_output=True,
            text=True,
            encoding='cp850',
            errors='replace'
        )
        output = res.stdout
    except Exception:
        return []

    current_adapter = None
    pending_ip = None

    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue

        # New adapter section starts with non-space and contains ':'
        if not line.startswith(' ') and ':' in line:
            if current_adapter and current_adapter.get('bindings'):
                parsed = finalize_adapter(current_adapter)
                if parsed:
                    adapters.append(parsed)

            adapter_name = line.split(':')[0].strip()
            current_adapter = {
                'adapter_name': adapter_name,
                'description': adapter_name,
                'mac': 'N/A',
                'gateway': 'N/A',
                'dhcp': 'N/A',
                'dns_servers': [],
                'bindings': [] # list of (ip, netmask)
            }
            pending_ip = None
            continue

        if not current_adapter or ':' not in line:
            continue

        parts = line.split(':', 1)
        k = parts[0].strip().replace('.', '').lower()
        v = parts[1].strip()

        if 'descri' in k or 'description' in k:
            current_adapter['description'] = v
        elif 'físico' in k or 'fisico' in k or 'physical' in k or 'endereço físico' in k:
            current_adapter['mac'] = v.replace('-', ':').upper()
        elif 'gateway' in k:
            if v and v != '0.0.0.0':
                current_adapter['gateway'] = v
        elif 'servidor dhcp' in k or 'dhcp server' in k:
            current_adapter['dhcp'] = v
        elif 'servidores dns' in k or 'dns servers' in k:
            if v and v not in current_adapter['dns_servers']:
                current_adapter['dns_servers'].append(v)
        elif 'ipv4' in k:
            ip_clean = v.split('(')[0].strip()
            if not (ip_clean.startswith('127.') or ip_clean.startswith('169.254')):
                pending_ip = ip_clean
        elif ('máscara' in k or 'mascara' in k or 'subnet mask' in k or 'sub-rede' in k) and pending_ip:
            mask_clean = v.strip()
            current_adapter['bindings'].append((pending_ip, mask_clean))
            pending_ip = None

    if current_adapter and current_adapter.get('bindings'):
        parsed = finalize_adapter(current_adapter)
        if parsed:
            adapters.append(parsed)

    return adapters

def finalize_adapter(raw):
    bindings = raw.get('bindings', [])
    if not bindings:
        return None

    gateway = raw.get('gateway', 'N/A')
    scopes = []

    for ip_str, mask_str in bindings:
        scope = calculate_network_scope(ip_str, netmask=mask_str, gateway=gateway)
        if scope:
            scopes.append(scope)

    if not scopes:
        return None

    # Determine primary scope: preferably one that contains the gateway, or first scope
    primary_scope = None
    for s in scopes:
        if s.get('is_gateway_scope'):
            primary_scope = s
            break
    if not primary_scope:
        primary_scope = scopes[0]

    return {
        "adapter_name": raw["adapter_name"],
        "description": raw.get("description") or raw["adapter_name"],
        "ip": primary_scope["ip"],
        "netmask": primary_scope["netmask"],
        "prefix_len": primary_scope["prefix_len"],
        "cidr": primary_scope["cidr"],
        "network_ip": primary_scope["network_ip"],
        "broadcast_ip": primary_scope["broadcast_ip"],
        "first_usable_ip": primary_scope["first_usable_ip"],
        "last_usable_ip": primary_scope["last_usable_ip"],
        "total_ips": primary_scope["total_ips"],
        "usable_ips": primary_scope["usable_ips"],
        "gateway": gateway,
        "mac": raw.get("mac", "N/A"),
        "dhcp_server": raw.get("dhcp", "N/A"),
        "dns_servers": raw.get("dns_servers", []),
        "is_default": bool(gateway and gateway != "N/A"),
        "scopes": scopes
    }

def get_all_network_scopes():
    """
    Returns all valid scopes discovered across all active network adapters.
    """
    adapters = get_network_adapters()
    all_scopes = []
    seen_cidrs = set()

    for ad in adapters:
        for s in ad.get("scopes", []):
            if s["cidr"] not in seen_cidrs:
                seen_cidrs.add(s["cidr"])
                entry = dict(s)
                entry["adapter_name"] = ad["adapter_name"]
                all_scopes.append(entry)

    # Sort so that gateway scopes appear first
    all_scopes.sort(key=lambda s: (not s.get("is_gateway_scope", False), s.get("cidr")))
    return all_scopes

def get_primary_adapter():
    """
    Returns the primary network adapter and attaches all available scopes on the system.
    """
    adapters = get_network_adapters()
    all_scopes = get_all_network_scopes()

    if not adapters:
        # Fallback to local hostname
        try:
            h = socket.gethostname()
            ip = socket.gethostbyname(h)
            scope = calculate_network_scope(ip, "255.255.255.0", gateway="192.168.1.1")
            fallback_adapter = {
                "adapter_name": "Conexão Local",
                "description": "Adaptador Local",
                "ip": ip,
                "netmask": "255.255.255.0",
                "prefix_len": 24,
                "cidr": scope["cidr"],
                "network_ip": scope["network_ip"],
                "broadcast_ip": scope["broadcast_ip"],
                "first_usable_ip": scope["first_usable_ip"],
                "last_usable_ip": scope["last_usable_ip"],
                "total_ips": scope["total_ips"],
                "usable_ips": scope["usable_ips"],
                "gateway": "192.168.1.1",
                "mac": "N/A",
                "dhcp_server": "N/A",
                "dns_servers": ["1.1.1.1"],
                "is_default": True,
                "scopes": [scope],
                "all_scopes": [scope]
            }
            return fallback_adapter
        except Exception:
            return None

    # 1. First priority: match the adapter that handles the active default route
    chosen = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        active_route_ip = s.getsockname()[0]
        s.close()
        for a in adapters:
            bound_ips = [s_item.get("ip") for s_item in a.get("scopes", [])]
            if a.get("ip") == active_route_ip or active_route_ip in bound_ips:
                chosen = a
                break
    except Exception:
        pass

    # 2. Second priority: adapter that has a default gateway
    if not chosen:
        for a in adapters:
            if a.get("is_default"):
                chosen = a
                break

    # 3. Fallback: first detected adapter
    if not chosen:
        chosen = adapters[0]

    chosen["all_scopes"] = all_scopes
    return chosen

def get_client_view_adapter(client_ip):
    """
    Constructs an adapter / network scope view tailored for a client IP
    connecting to this server from another machine on the LAN.
    """
    server_adapter = get_primary_adapter()
    all_scopes = get_all_network_scopes()
    
    server_ip = server_adapter.get("ip") if server_adapter else None
    
    # If client is accessing from localhost or server's own IP
    if not client_ip or client_ip in ("127.0.0.1", "::1", "localhost") or client_ip == server_ip:
        if server_adapter:
            server_adapter["is_remote_client"] = False
            server_adapter["client_ip"] = server_ip or "127.0.0.1"
        return server_adapter

    # 1. Match network scope
    matching_scope = None
    try:
        c_addr = ipaddress.IPv4Address(client_ip)
        for s in all_scopes:
            net = ipaddress.IPv4Network(s["cidr"], strict=False)
            if c_addr in net:
                matching_scope = dict(s)
                break
    except Exception:
        pass

    if not matching_scope:
        if server_adapter and server_adapter.get("scopes"):
            matching_scope = dict(server_adapter["scopes"][0])
        else:
            matching_scope = calculate_network_scope(
                client_ip, 
                "255.255.255.0", 
                gateway=server_adapter.get("gateway") if server_adapter else None
            )

    # 2. Probe client MAC via ARP
    from .arp_scanner import send_arp_probe, get_system_arp_table
    from .vendor_lookup import get_vendor_info
    from .port_scanner import get_netbios_hostname, get_reverse_dns

    mac = None
    probe = send_arp_probe(client_ip)
    if probe and probe.get("mac"):
        mac = probe["mac"]
    else:
        arp_tbl = get_system_arp_table()
        mac = arp_tbl.get(client_ip, "N/A")

    vendor_info = get_vendor_info(mac) if (mac and mac != "N/A") else {"vendor": "Desconhecido"}
    vendor_name = vendor_info.get("vendor", "")

    hostname = ""
    try:
        hostname = get_netbios_hostname(client_ip, timeout=0.3) or ""
    except Exception:
        pass

    # Build descriptive label for the client's network connection
    parts = []
    if hostname:
        parts.append(hostname)
    if vendor_name and vendor_name not in ("Desconhecido", "Fabricante Não Identificado"):
        parts.append(vendor_name)
    
    label = " - ".join(parts) if parts else f"Dispositivo Cliente ({client_ip})"

    # Customize matching scope so the client's own IP is shown as its primary IP
    client_scope = dict(matching_scope)
    client_scope["ip"] = client_ip
    client_scope["display_label"] = f"{client_scope['cidr']} (Seu IP: {client_ip}) - {client_scope.get('usable_ips', 254):,} IPs".replace(",", ".")

    # CRITICAL: For a remote client device (e.g. mobile phone or another computer),
    # ONLY show target networks in which the client device actually has a valid IP!
    # Filter out server's virtual/internal adapters (e.g. 172.16.x.x, 192.168.35.x).
    valid_client_scopes = []
    try:
        c_addr = ipaddress.IPv4Address(client_ip)
        for s in all_scopes:
            net = ipaddress.IPv4Network(s["cidr"], strict=False)
            if c_addr in net:
                s_copy = dict(s)
                s_copy["ip"] = client_ip
                s_copy["display_label"] = f"{s_copy['cidr']} (Seu IP: {client_ip}) - {s_copy.get('usable_ips', 254):,} IPs".replace(",", ".")
                valid_client_scopes.append(s_copy)
    except Exception:
        pass

    if not valid_client_scopes:
        valid_client_scopes = [client_scope]

    client_adapter = {
        "adapter_name": f"Cliente: {label}",
        "description": f"💻 {label} (Seu Dispositivo)",
        "ip": client_ip,
        "mac": mac or "N/A",
        "hostname": hostname,
        "vendor": vendor_name,
        "netmask": client_scope.get("netmask", "255.255.255.0"),
        "prefix_len": client_scope.get("prefix_len", 24),
        "cidr": client_scope.get("cidr"),
        "network_ip": client_scope.get("network_ip"),
        "broadcast_ip": client_scope.get("broadcast_ip"),
        "first_usable_ip": client_scope.get("first_usable_ip"),
        "last_usable_ip": client_scope.get("last_usable_ip"),
        "total_ips": client_scope.get("total_ips"),
        "usable_ips": client_scope.get("usable_ips"),
        "gateway": client_scope.get("gateway", server_adapter.get("gateway", "N/A") if server_adapter else "N/A"),
        "is_default": True,
        "is_remote_client": True,
        "client_ip": client_ip,
        "server_host": socket.gethostname(),
        "server_ip": server_ip,
        "scopes": valid_client_scopes,
        "all_scopes": valid_client_scopes
    }
    return client_adapter

