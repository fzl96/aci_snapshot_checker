import json
import re
import datetime
from collections import defaultdict
from rich import print as rprint
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from typing import Optional
import csv


def summarize_interfaces(data):
    result = {}
    for intf in data:
        attrs = intf.get('l1PhysIf', {}).get('attributes', {})
        dn = attrs.get('dn')
        state = attrs.get('operSt')
        if dn and state:
            result[dn] = state
    return result

def summarize_interface_errors(interface_errors):
    summary = {}
    for entry in interface_errors:
        dn = entry.get("dn")
        crc = int(entry.get("crc", 0))
        input_discards = int(entry.get("inputDiscards", 0))
        total_errors = crc + input_discards
        if dn:
            summary[dn] = total_errors
    return summary

def extract_interface_from_dn(dn):
    """
    Extract node ID and port from DN string.
    Example input: "topology/pod-1/node-102/sys/phys-[eth1/5]/dbgEtherStats"
    Output: ("node-102", "eth1/5")
    """
    match = re.search(r'node-(\d+).*phys-\[(.*?)\]', dn)
    if match:
        node_id = f"node-{match.group(1)}"
        port = match.group(2)
        return node_id, port
    return None, None

def compare_snapshots(file1, file2):
    with open(file1) as f1, open(file2) as f2:
        before = json.load(f1)
        after = json.load(f2)

    result = {}

    # Fabric Health
    result["fabric_health"] = {
        "before": before.get("fabric_health"),
        "after": after.get("fabric_health"),
    }

    # Faults
    before_faults = {f["faultInst"]["attributes"]["dn"] for f in before.get("faults", [])}
    after_faults = {f["faultInst"]["attributes"]["dn"] for f in after.get("faults", [])}
    result["new_faults"] = sorted(after_faults - before_faults)
    result["cleared_faults"] = sorted(before_faults - after_faults)

    # Endpoints
    before_eps = {ep["fvCEp"]["attributes"]["dn"]: ep["fvCEp"]["attributes"].get("ip") for ep in before.get("endpoints", [])}
    after_eps = {ep["fvCEp"]["attributes"]["dn"]: ep["fvCEp"]["attributes"].get("ip") for ep in after.get("endpoints", [])}
    result["new_endpoints"] = sorted(set(after_eps) - set(before_eps))
    result["missing_endpoints"] = sorted(set(before_eps) - set(after_eps))
    result["moved_endpoints"] = sorted([
        dn for dn in set(before_eps) & set(after_eps)
        if before_eps[dn] != after_eps[dn]
    ])

    # Interface status
    before_intfs = summarize_interfaces(before.get("interfaces", []))
    after_intfs = summarize_interfaces(after.get("interfaces", []))
    intf_changes = {
        "status_changed": [
            f"{k}: {before_intfs[k]} ➜ {after_intfs[k]}"
            for k in before_intfs.keys() & after_intfs.keys()
            if before_intfs[k] != after_intfs[k]
        ],
        "missing": sorted(set(before_intfs) - set(after_intfs)),
        "new": sorted(set(after_intfs) - set(before_intfs))
    }
    result["interface_changes"] = intf_changes

    # Interface Errors
    before_errs = summarize_interface_errors(before.get("interface_errors", []))
    after_errs = summarize_interface_errors(after.get("interface_errors", []))
    error_changes = {}
    for dn in set(before_errs) | set(after_errs):
        b = before_errs.get(dn, 0)
        a = after_errs.get(dn, 0)
        if a > b:
            error_changes[dn] = f"{b} ➜ {a}"
    result["interface_error_changes"] = error_changes

    # CRC Errors - Only show interfaces with increased errors
    before_crc = {}
    for e in before.get("crc_errors", []):
        if "rmonEtherStats" in e and "attributes" in e["rmonEtherStats"]:
            dn = e["rmonEtherStats"]["attributes"].get("dn")
            # Note: The key is "cRCAlignErrors" not "crcAlignErrors"
            crc_align_errors = int(e["rmonEtherStats"]["attributes"].get("cRCAlignErrors", 0))
            if dn:
                before_crc[dn] = crc_align_errors
    
    after_crc = {}
    for e in after.get("crc_errors", []):
        if "rmonEtherStats" in e and "attributes" in e["rmonEtherStats"]:
            dn = e["rmonEtherStats"]["attributes"].get("dn")
            # Note: The key is "cRCAlignErrors" not "crcAlignErrors"
            crc_align_errors = int(e["rmonEtherStats"]["attributes"].get("cRCAlignErrors", 0))
            if dn:
                after_crc[dn] = crc_align_errors
    
    crc_changes = {}
    
    all_interfaces = set(before_crc.keys()) | set(after_crc.keys())
    
    for dn in all_interfaces:
        b = before_crc.get(dn, 0)
        a = after_crc.get(dn, 0)
        
        if a > b:
            # Extract interface name for better readability
            interface_name = extract_interface_from_dn(dn)
            crc_changes[interface_name] = f"{b} ➜ {a}"
    
    result["crc_error_changes"] = crc_changes

    # URIB routes
    before_routes = {r["uribv4Route"]["attributes"]["dn"] for r in before.get("urib_routes", [])}
    after_routes = {r["uribv4Route"]["attributes"]["dn"] for r in after.get("urib_routes", [])}
    route_changes = {
        "missing": sorted(before_routes - after_routes),
        "new": sorted(after_routes - before_routes),
    }
    result["urib_route_changes"] = route_changes

    return result


def print_colored_result(result):
    rprint("\n📈 [bold]COMPARISON RESULT:[/bold]\n")

    # Print summary counts
    rprint("[bold underline]Summary:[/bold underline]")
    for section, content in result.items():
        if section == "fabric_health":
            continue
        if isinstance(content, dict):
            count = len(content)
        elif isinstance(content, list):
            count = len(content)
        else:
            count = 1
        rprint(f"• [cyan]{section}[/cyan]: [bold yellow]{count}[/bold yellow]")
    rprint("")

    def print_section(title, content):
        rprint(f"🔹 [cyan]{title}[/cyan]:")
        if isinstance(content, dict):
            if not content:
                rprint("  (none)")
            else:
                for k, v in content.items():
                    rprint(f"  • {k}: {v}")
        elif isinstance(content, list):
            if not content:
                rprint("  (none)")
            else:
                for item in content:
                    rprint(f"  • {item}")
        else:
            rprint(f"  {content}")
        rprint("")  # spacing

    for section in [
        "fabric_health",
        "new_faults",
        "cleared_faults",
        "new_endpoints",
        "missing_endpoints",
        "moved_endpoints",
        "interface_changes",
        "interface_error_changes",
        "crc_error_changes",
        "urib_route_changes"
    ]:
        if section in result:
            print_section(section, result[section])
        else:
            rprint(f"🔹 [yellow]{section}[/yellow]: (not available)\n")


def save_to_csv(result, site, filename=None):
    """
    Save comparison results to a CSV file.
    
    Args:
        result: The comparison result dictionary
        filename: Output filename (optional). If not provided, generates a timestamped filename.
    """
    if filename is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if site:
            filename = f"{site}_comparison_result_{timestamp}.csv"
        else:
            filename = f"comparison_result_{timestamp}.csv"
            
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow(['Category', 'Item', 'Details'])
        
        # Fabric Health
        fabric_health = result.get('fabric_health', {})
        writer.writerow(['Fabric Health', 'Before', fabric_health.get('before', 'N/A')])
        writer.writerow(['Fabric Health', 'After', fabric_health.get('after', 'N/A')])
        
        # New Faults
        for fault in result.get('new_faults', []):
            writer.writerow(['New Faults', fault, ''])
        
        # Cleared Faults
        for fault in result.get('cleared_faults', []):
            writer.writerow(['Cleared Faults', fault, ''])
        
        # New Endpoints
        for ep in result.get('new_endpoints', []):
            writer.writerow(['New Endpoints', ep, ''])
        
        # Missing Endpoints
        for ep in result.get('missing_endpoints', []):
            writer.writerow(['Missing Endpoints', ep, ''])
        
        # Moved Endpoints
        for ep in result.get('moved_endpoints', []):
            writer.writerow(['Moved Endpoints', ep, ''])
        
        # Interface Changes - Status Changed
        intf_changes = result.get('interface_changes', {})
        for change in intf_changes.get('status_changed', []):
            writer.writerow(['Interface Status Changed', change, ''])
        
        # Interface Changes - Missing
        for intf in intf_changes.get('missing', []):
            writer.writerow(['Interface Missing', intf, ''])
        
        # Interface Changes - New
        for intf in intf_changes.get('new', []):
            writer.writerow(['Interface New', intf, ''])
        
        # Interface Error Changes
        error_changes = result.get('interface_error_changes', {})
        for dn, change in error_changes.items():
            writer.writerow(['Interface Error Changes', dn, change])
        
        # CRC Error Changes
        crc_changes = result.get('crc_error_changes', {})
        for intf, change in crc_changes.items():
            writer.writerow(['CRC Error Changes', str(intf), change])
        
        # URIB Route Changes
        route_changes = result.get('urib_route_changes', {})
        for route in route_changes.get('missing', []):
            writer.writerow(['URIB Routes Missing', route, ''])
        for route in route_changes.get('new', []):
            writer.writerow(['URIB Routes New', route, ''])
    
    rprint(f"[green]Results saved to {filename}[/green]")

    