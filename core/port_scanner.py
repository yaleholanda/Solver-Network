import socket
import struct
import urllib.request
import re

COMMON_PORTS = [80, 443, 445, 139, 3389, 22, 9100, 631, 515, 8008, 8080, 5357]

def check_target_ports(ip, ports=None, timeout=0.15):
    """
    Scans a targeted set of diagnostic ports to classify device.
    """
    if ports is None:
        ports = COMMON_PORTS

    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

def get_netbios_hostname(ip, timeout=0.3):
    """
    Queries NetBIOS Name Service (NBNS) on UDP 137 to get computer/device name.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Standard NBNS Node Status Query
        tr_id = b'\x13\x37'
        flags = b'\x00\x00'
        qdcount = b'\x00\x01'
        ancount = b'\x00\x00'
        nscount = b'\x00\x00'
        arcount = b'\x00\x00'
        qname = b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
        qtype = b'\x00\x21' # NBSTAT
        qclass = b'\x00\x01'
        query = tr_id + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass
        
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        
        if len(data) > 56:
            num_names = data[56]
            names = []
            for i in range(num_names):
                offset = 57 + i * 18
                if offset + 18 <= len(data):
                    name_bytes = data[offset:offset+15]
                    name_type = data[offset+15]
                    try:
                        clean_name = name_bytes.decode('ascii', errors='ignore').strip()
                        if clean_name and clean_name not in names:
                            names.append(clean_name)
                    except:
                        pass
            if names:
                return names[0]
    except Exception:
        pass
    return None

def get_reverse_dns(ip):
    """
    Resolves hostname via reverse DNS lookup.
    """
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

def get_web_title(ip, ports, timeout=0.8):
    """
    Grabs HTTP title / server banner for web servers (frequently identifies printers and routers).
    """
    candidates = [p for p in ports if p in [80, 8080, 443]]
    if not candidates:
        return None

    for p in candidates:
        proto = "https" if p == 443 else "http"
        url = f"{proto}://{ip}:{p}/"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            # Ignore SSL errors for local devices with self-signed certs
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                html = resp.read(2048).decode('utf-8', errors='ignore')
                match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
                if match:
                    title = match.group(1).strip()
                    if title:
                        return title
        except Exception:
            pass
    return None
