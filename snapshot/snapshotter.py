# ✅ Updated snapshotter.py to include timestamped filenames and history viewer with interactive snapshot comparison

import json
import os
import datetime
from api.aci_client import (
    get_fabric_health,
    get_faults,
    get_interface_status,
    get_endpoints,
    get_urib_routes,
    get_interface_errors,
    get_crc_errors
)

APICS = [
    {"num": "1", "site": "DC", "ip": "10.220.251.51"},
    {"num": "2", "site": "DRC", "ip": "10.221.251.51"},
    {"num": "3", "site": "DCI", "ip": "10.222.251.51"},
    {"num": "4", "site": "DEV", "ip": "10.201.16.138"},
]

def take_snapshot(cookies, apic_ip, base_filename):
    data = {
        "fabric_health": get_fabric_health(cookies, apic_ip),
        "faults": get_faults(cookies, apic_ip),
        "interfaces": get_interface_status(cookies, apic_ip),
        "interface_errors": get_interface_errors(cookies, apic_ip),
        "crc_errors": get_crc_errors(cookies, apic_ip),
        "endpoints": get_endpoints(cookies, apic_ip),
        "urib_routes": get_urib_routes(cookies, apic_ip),
    }
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M")
    filename = f"{base_filename}_{timestamp}.json"
    filepath = os.path.join("output", filename)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    print(f"✅ Snapshot saved to {filepath}")
    return filepath

def list_snapshots(site: str):
    folder = "output"
    if not os.path.exists(folder):
        print("📂 No snapshots taken yet.")
        return []
    files = [f for f in os.listdir(folder) if f.endswith(".json") and site in f]
    if not files:
        print("📂 No snapshot files found.")
        return []
    files.sort()
    print("\n🕓 Available Snapshots:")
    for i, f in enumerate(files):
        print(f"  [{i+1}] {f}")
    return files

def choose_snapshots():
    print("Available APICs:")
    for apic in APICS:
        print(f"{apic['num']}. {apic['site']} ({apic['ip']})")
    try:
        choice = input("Select APIC [1-4]: ").strip()
    except EOFError:
        choice = ""
    
    site = ""
    selected = next((a for a in APICS if a["num"] == choice), None)
    if selected:
        site = selected["site"]
    else:
        return None
            
    files = list_snapshots(site)
    if len(files) < 2:
        print("❌ Need at least 2 snapshots to compare.")
        return None, None, None
    try:
        first = int(input("🔢 Enter number for FIRST snapshot: ")) - 1
        second = int(input("🔢 Enter number for SECOND snapshot: ")) - 1
        if 0 <= first < len(files) and 0 <= second < len(files):
            return os.path.join("output", files[first]), os.path.join("output", files[second]), site
        else:
            print("❌ Invalid selection.")
            return None, None, None
    except ValueError:
        print("❌ Please enter valid numbers.")
        return None, None, None
