import getpass
import glob
import requests
from requests.cookies import RequestsCookieJar
from datetime import datetime
from typing import Tuple, Optional
from api.aci_client import login
from snapshot.snapshotter import take_snapshot, list_snapshots, choose_snapshots
from compare.comparer import compare_snapshots
from compare.comparer import print_colored_result
from compare.comparer import save_to_csv
from healthcheck.checklist_aci import main_healthcheck_aci
from rich.console import Console

DEFAULT_APIC_IP = "10.8.254.91"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "Master082025"
console = Console()

APICS = [
    {"num": "1", "site": "DC", "ip": "10.220.251.51"},
    {"num": "2", "site": "DRC", "ip": "10.221.251.51"},
    {"num": "3", "site": "DCI", "ip": "10.222.251.51"},
    {"num": "4", "site": "DEV", "ip": "10.201.16.138"},
]


def get_credentials() -> Tuple[str, str, str]:
    """Get APIC credentials from interactive input"""
    # Get APIC IP
    print("Available APICs:")
    for apic in APICS:
        print(f"{apic['num']}. {apic['site']} ({apic['ip']})")
    try:
        choice = input("Select APIC [1-4]: ").strip()
    except EOFError:
        choice = ""

    apic_ip = ""
    site = ""
    selected = next((a for a in APICS if a["num"] == choice), None)
    if selected:
        apic_ip = selected["ip"]
        site = selected["site"]
    else:
        apic_ip = DEFAULT_APIC_IP
        console.print(f"[dim]Using default APIC IP: {DEFAULT_APIC_IP}[/dim]")
    # Get username
    try:
        username = input("Enter Username: ").strip()
    except EOFError:
        username = ""
    if not username:
        username = DEFAULT_USERNAME
        console.print(f"[dim]Using default username: {DEFAULT_USERNAME}[/dim]")

    # Get password
    try:
        password = getpass.getpass("Enter Password: ")
    except Exception:
        password = ""
    if not password:
        password = DEFAULT_PASSWORD
        console.print(f"[dim]Using default password: {DEFAULT_PASSWORD}[/dim]")

    return apic_ip, site, username, password


def apic_login(apic_ip: str, username: str, password: str) -> Optional[RequestsCookieJar]:
    """Authenticate to APIC and return session cookies"""
    login_url = f"https://{apic_ip}/api/aaaLogin.json"
    auth_payload = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}

    try:
        resp = requests.post(login_url, json=auth_payload, verify=False, timeout=30)
        if resp.status_code != 200:
            console.print(f"[red]✗ Login failed with status code: {resp.status_code}[/red]")
            return None

        # Check if login was successful
        response_data = resp.json()
        # APIC returns imdata with aaaaLogin attributes on success; check presence
        if 'imdata' in response_data and len(response_data['imdata']) > 0:
            # if there's an error object, treat as failure
            if isinstance(response_data['imdata'][0], dict) and 'error' in response_data['imdata'][0]:
                console.print("[red]✗ Authentication failed: Invalid credentials[/red]")
                return None

        console.print(f"[green]✓ Successfully authenticated to APIC {apic_ip}[/green]")
        return resp.cookies
    except requests.exceptions.ConnectionError:
        console.print(f"[red]✗ Cannot connect to APIC at {apic_ip}[/red]")
        return None
    except requests.exceptions.Timeout:
        console.print("[red]✗ Connection timeout[/red]")
        return None
    except Exception as e:
        console.print(f"[red]✗ Login failed: {str(e)}[/red]")
        return None

def timestamp_filename(base: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%dT%H-%M")
    return f"{base}_{ts}.json"

def main():
    print("📦 Cisco ACI Snapshot Checker\n" + "-"*40)
    while True:
        print("\n🔧 Main Menu")
        print("1. Take snapshot")
        print("2. Healthcheck ACI")
        # print("3. Compare last snapshots")
        print("3. Compare any two snapshots")
        print("0. Exit")

        choice = input("👉 Choose an option [0–3]: ").strip()

        if choice == "1":
            apic_ip, site, username, password = get_credentials()
            cookies = apic_login(apic_ip, username, password)
            if cookies:
                cookies, apic_base = login(apic_ip, username, password)
                take_snapshot(cookies, apic_base, site)
            else:
                print("❌ Could not authenticate to APIC.")
        elif choice == "2":
            main_healthcheck_aci()

        # elif choice == "3":           
        #     # Find the latest snapshot_*.json
        #     files = sorted(glob.glob("output/snapshot_*.json"))
            
        #     if not files:
        #         print("❌ Could not find timestamped snapshot files.")
        #     else:
        #         latest_before = files[-2]
        #         latest_after = files[-1]
        #         print(f"📊 Comparing:\n  BEFORE: {latest_before}\n  AFTER:  {latest_after}")
        #         result = compare_snapshots(latest_before, latest_after)
        #         print_colored_result(result)
        #         save_to_csv(result)

        elif choice == "3":
            file1, file2, site = choose_snapshots()
            if file1 and file2:
                print(f"📊 Comparing '{file1}' and '{file2}'...")
                result = compare_snapshots(file1, file2)
                print_colored_result(result)
                save_to_csv(result, site)

        elif choice == "0":
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid option. Please enter 0, 1, 2, or 3.")

if __name__ == "__main__":
    main()
