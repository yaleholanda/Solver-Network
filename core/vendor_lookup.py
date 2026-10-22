import os
import json
import urllib.request
import urllib.error
from .db import get_cached_vendor, cache_vendor

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
OUI_JSON_PATH = os.path.join(DATA_DIR, "top_ouis.json")

# In-memory OUI map
_OUI_MAP = {}

def load_oui_database():
    global _OUI_MAP
    if os.path.exists(OUI_JSON_PATH):
        try:
            with open(OUI_JSON_PATH, "r", encoding="utf-8") as f:
                _OUI_MAP = json.load(f)
        except Exception as e:
            _OUI_MAP = {}

load_oui_database()

def is_locally_administered_mac(mac):
    """
    Checks if a MAC address has the U/L (Universal/Local) bit set.
    If the second hex digit is 2, 6, A, or E (e.g. x2, x6, xA, xE),
    the MAC is locally administered (randomized MAC address, typical of iOS / Android 'Private Wi-Fi Address').
    """
    if not mac or len(mac) < 2:
        return False
    clean = mac.replace(":", "").replace("-", "")
    if len(clean) >= 2:
        try:
            second_nibble = clean[1].upper()
            return second_nibble in ('2', '6', 'A', 'E')
        except:
            return False
    return False

def get_vendor_info(mac, allow_online_fallback=True):
    """
    Resolves vendor and category hint from MAC address.
    Returns: {"vendor": str, "category_hint": str, "is_randomized": bool}
    """
    if not mac:
        return {"vendor": "Desconhecido", "category_hint": "unknown", "is_randomized": False}
    
    clean_mac = mac.upper().replace(":", "").replace("-", "").strip()
    prefix = clean_mac[:6]
    
    # Check 1: In-memory OUI curated database
    if prefix in _OUI_MAP:
        info = _OUI_MAP[prefix]
        return {
            "vendor": info.get("vendor", "Desconhecido"),
            "category_hint": info.get("category", "unknown"),
            "is_randomized": False
        }
        
    # Check 2: SQLite database cache
    cached = get_cached_vendor(prefix)
    if cached and cached.get("vendor"):
        return {
            "vendor": cached["vendor"],
            "category_hint": cached.get("category", "unknown"),
            "is_randomized": False
        }

    # Check 3: Check if it's a locally administered (randomized) MAC
    if is_locally_administered_mac(mac):
        return {
            "vendor": "MAC Aleatório (Privacidade Wi-Fi)",
            "category_hint": "phones",
            "is_randomized": True
        }

    # Check 4: Online lookup fallback
    if allow_online_fallback and len(clean_mac) >= 6:
        try:
            url = f"https://api.maclookup.app/v2/macs/{mac}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "SolverNetwork/1.0 (Network Device Discovery)"}
            )
            with urllib.request.urlopen(req, timeout=1.8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                company = data.get("company", "").strip()
                if company:
                    category = guess_category_from_vendor_name(company)
                    cache_vendor(prefix, company, category)
                    return {
                        "vendor": company,
                        "category_hint": category,
                        "is_randomized": False
                    }
        except Exception:
            pass

    return {
        "vendor": "Fabricante Não Identificado",
        "category_hint": "unknown",
        "is_randomized": False
    }

def guess_category_from_vendor_name(name):
    lower = name.lower()
    if any(k in lower for k in ["apple", "samsung", "xiaomi", "motorola", "oneplus", "huawei", "oppo", "vivo"]):
        return "phones"
    if any(k in lower for k in ["hp", "canon", "epson", "brother", "xerox", "lexmark", "kyocera", "ricoh"]):
        return "printers"
    if any(k in lower for k in ["cisco", "fortinet", "ubiquiti", "tp-link", "d-link", "mikrotik", "intelbras", "tenda", "netgear"]):
        return "network"
    if any(k in lower for k in ["dell", "lenovo", "asus", "acer", "intel", "msi", "micro-star", "gigabyte", "microsoft"]):
        return "computers"
    if any(k in lower for k in ["roku", "lg electronics", "sony", "amazon", "philips", "tcl"]):
        return "media"
    if any(k in lower for k in ["espressif", "tuya", "sonoff", "shelly", "raspberry"]):
        return "iot"
    return "unknown"
