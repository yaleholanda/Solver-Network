import sqlite3
import os
import time

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "solver_network.db")

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Custom device overrides (Name, Category, Notes)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS custom_devices (
        mac TEXT PRIMARY KEY,
        custom_name TEXT,
        custom_category TEXT,
        notes TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # OUI cache for looked up vendors
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS oui_cache (
        mac_prefix TEXT PRIMARY KEY,
        vendor TEXT,
        category TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # History of network scans
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        interface TEXT,
        subnet TEXT,
        total_ips INTEGER,
        occupied_ips INTEGER,
        free_ips INTEGER,
        duration_sec REAL
    )
    """)
    
    conn.commit()
    conn.close()

def get_custom_device(mac):
    if not mac:
        return None
    mac = mac.upper()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT custom_name, custom_category, notes FROM custom_devices WHERE mac = ?", (mac,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "custom_name": row["custom_name"],
            "custom_category": row["custom_category"],
            "notes": row["notes"]
        }
    return None

def set_custom_device(mac, custom_name=None, custom_category=None, notes=None):
    if not mac:
        return
    mac = mac.upper()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO custom_devices (mac, custom_name, custom_category, notes, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(mac) DO UPDATE SET
            custom_name = coalesce(excluded.custom_name, custom_devices.custom_name),
            custom_category = coalesce(excluded.custom_category, custom_devices.custom_category),
            notes = coalesce(excluded.notes, custom_devices.notes),
            updated_at = CURRENT_TIMESTAMP
    """, (mac, custom_name, custom_category, notes))
    conn.commit()
    conn.close()

def get_all_custom_devices():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT mac, custom_name, custom_category, notes FROM custom_devices")
    rows = cursor.fetchall()
    conn.close()
    return {row["mac"]: dict(row) for row in rows}

def get_cached_vendor(mac_prefix):
    if not mac_prefix:
        return None
    mac_prefix = mac_prefix.upper().replace(":", "").replace("-", "")[:6]
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT vendor, category FROM oui_cache WHERE mac_prefix = ?", (mac_prefix,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"vendor": row["vendor"], "category": row["category"]}
    return None

def cache_vendor(mac_prefix, vendor, category="unknown"):
    if not mac_prefix or not vendor:
        return
    mac_prefix = mac_prefix.upper().replace(":", "").replace("-", "")[:6]
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO oui_cache (mac_prefix, vendor, category, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    """, (mac_prefix, vendor, category))
    conn.commit()
    conn.close()

def record_scan(interface, subnet, total_ips, occupied_ips, free_ips, duration_sec):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history (interface, subnet, total_ips, occupied_ips, free_ips, duration_sec)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (interface, subnet, total_ips, occupied_ips, free_ips, duration_sec))
    conn.commit()
    conn.close()

# Initialize DB on module import
init_db()
