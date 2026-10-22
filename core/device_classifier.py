from .db import get_custom_device

CATEGORY_LABELS = {
    "computers": "Computador / Notebook",
    "phones": "Celular / Tablet",
    "printers": "Impressora",
    "network": "Roteador / Rede",
    "media": "Smart TV / Mídia",
    "iot": "IoT / Automação",
    "unknown": "Desconhecido"
}

CATEGORY_ICONS = {
    "computers": "💻",
    "phones": "📱",
    "printers": "🖨️",
    "network": "🌐",
    "media": "📺",
    "iot": "💡",
    "unknown": "❓"
}

def classify_device(ip, mac, hostname, vendor_info, open_ports, web_title, gateway_ip, local_ip):
    """
    Classifies a network device based on multiple heuristic signals.
    Returns: {"category": str, "category_label": str, "icon": str, "display_name": str, "is_custom": bool}
    """
    # 1. Check user override in database
    custom = get_custom_device(mac) if mac else None
    if custom and (custom.get("custom_category") or custom.get("custom_name")):
        cat = custom.get("custom_category") or "unknown"
        name = custom.get("custom_name") or hostname or (f"Dispositivo {ip}")
        return {
            "category": cat,
            "category_label": CATEGORY_LABELS.get(cat, "Personalizado"),
            "icon": CATEGORY_ICONS.get(cat, "🏷️"),
            "display_name": name,
            "notes": custom.get("notes", ""),
            "is_custom": True
        }

    # 2. Check if it's the Default Gateway
    if gateway_ip and ip == gateway_ip:
        return {
            "category": "network",
            "category_label": CATEGORY_LABELS["network"],
            "icon": "🌐",
            "display_name": f"Gateway / Roteador Principal ({vendor_info.get('vendor', 'Rede')})",
            "notes": "Roteador / Gateway Padrão da Rede",
            "is_custom": False
        }

    # 3. Check if it's the current local host machine
    if local_ip and ip == local_ip:
        return {
            "category": "computers",
            "category_label": CATEGORY_LABELS["computers"],
            "icon": "💻",
            "display_name": f"{hostname or 'Este Computador'} (Esta Máquina)",
            "notes": "Dispositivo local que está executando o Solver Network",
            "is_custom": False
        }

    vendor_name = (vendor_info.get("vendor") or "").lower()
    vendor_cat = vendor_info.get("category_hint", "unknown")
    is_random_mac = vendor_info.get("is_randomized", False)
    host_lower = (hostname or "").lower()
    title_lower = (web_title or "").lower()
    ports_set = set(open_ports or [])

    # Heuristic: Impressoras (Printers)
    # Port 9100 (JetDirect RAW), 631 (IPP), 515 (LPD)
    if ports_set.intersection({9100, 631, 515}):
        return _format_category("printers", hostname, vendor_info, "Impressora de Rede")

    if any(k in host_lower for k in ["printer", "impressora", "laserjet", "deskjet", "ecotank", "epson", "brother", "kyocera", "ricoh", "xerox"]):
        return _format_category("printers", hostname, vendor_info, "Impressora")

    if any(k in title_lower for k in ["printer", "laserjet", "deskjet", "ecotank", "series", "canon", "epson", "brother"]):
        return _format_category("printers", hostname, vendor_info, f"Impressora ({web_title})")

    if vendor_cat == "printers":
        return _format_category("printers", hostname, vendor_info, f"Impressora {vendor_info.get('vendor')}")

    # Heuristic: Computadores / Notebooks (SMB 445, NetBIOS 139, RDP 3389)
    if ports_set.intersection({445, 139, 3389}):
        return _format_category("computers", hostname, vendor_info, hostname or "Computador Windows / PC")

    if any(k in host_lower for k in ["desktop-", "laptop-", "pc", "macbook", "imac", "thinkpad", "surface", "workstation", "server"]):
        return _format_category("computers", hostname, vendor_info, hostname or "Computador")

    if vendor_cat == "computers" and not is_random_mac:
        return _format_category("computers", hostname, vendor_info, hostname or f"Computador ({vendor_info.get('vendor')})")

    # Heuristic: Smart TVs / Streaming / Mídia
    if ports_set.intersection({8008, 8009, 7000}): # Chromecast, AirPlay
        return _format_category("media", hostname, vendor_info, "Smart TV / Streaming")

    if any(k in host_lower for k in ["tv", "roku", "chromecast", "firetv", "appletv", "bravia", "webos", "tizen", "sony"]):
        return _format_category("media", hostname, vendor_info, hostname or "Smart TV / Dispositivo de Mídia")

    if vendor_cat == "media":
        return _format_category("media", hostname, vendor_info, hostname or f"Smart TV / Mídia ({vendor_info.get('vendor')})")

    # Heuristic: Equipamentos de Rede (Switches, Roteadores, APs)
    if vendor_cat == "network":
        return _format_category("network", hostname, vendor_info, hostname or f"Equipamento de Rede ({vendor_info.get('vendor')})")

    if ports_set.intersection({53, 67}):
        return _format_category("network", hostname, vendor_info, "Roteador / Servidor DNS")

    # Heuristic: Celulares / Tablets
    # If randomized MAC (standard iOS / Android private Wi-Fi) without computer ports
    if is_random_mac:
        return _format_category("phones", hostname, vendor_info, hostname or "Smartphone (MAC Privado)")

    if any(k in host_lower for k in ["iphone", "galaxy", "xiaomi", "redmi", "pixel", "ipad", "android", "moto", "poco", "huawei"]):
        return _format_category("phones", hostname, vendor_info, hostname or "Smartphone / Tablet")

    if vendor_cat == "phones":
        return _format_category("phones", hostname, vendor_info, hostname or f"Smartphone ({vendor_info.get('vendor')})")

    # Heuristic: IoT / Automação
    if vendor_cat == "iot" or any(k in host_lower for k in ["esp_", "tasmota", "sonoff", "shelly", "tuya", "cam", "camera"]):
        return _format_category("iot", hostname, vendor_info, hostname or f"Dispositivo IoT ({vendor_info.get('vendor')})")

    # Default: Desconhecido
    display = hostname or (f"Dispositivo ({vendor_info.get('vendor')})" if vendor_info.get("vendor") != "Desconhecido" and vendor_info.get("vendor") != "Fabricante Não Identificado" else f"Dispositivo {ip}")
    return {
        "category": "unknown",
        "category_label": CATEGORY_LABELS["unknown"],
        "icon": CATEGORY_ICONS["unknown"],
        "display_name": display,
        "notes": "",
        "is_custom": False
    }

def _format_category(cat, hostname, vendor_info, default_name):
    vendor = vendor_info.get("vendor", "")
    name = hostname
    if not name:
        if vendor and vendor != "Desconhecido" and vendor != "Fabricante Não Identificado":
            name = f"{default_name} ({vendor})"
        else:
            name = default_name

    return {
        "category": cat,
        "category_label": CATEGORY_LABELS.get(cat, cat.title()),
        "icon": CATEGORY_ICONS.get(cat, "📦"),
        "display_name": name,
        "notes": "",
        "is_custom": False
    }
