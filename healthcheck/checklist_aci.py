#!/usr/bin/env python3
import requests
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
import sys
import os
import getpass
import csv
from typing import Dict, List, Tuple, Optional
from requests.cookies import RequestsCookieJar
import re

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)  # type: ignore

# Configuration with default values
DEFAULT_APIC_IP = "10.8.254.91"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "Master082025"
DEFAULT_HEALTH_THRESHOLD = 90
DEFAULT_CPU_MEM_THRESHOLD = 75  # percent
DEFAULT_INTERFACE_ERROR_THRESHOLD = 0
APICS = [
    {"num": "1", "site": "DC", "ip": "10.220.251.51"},
    {"num": "2", "site": "DRC", "ip": "10.221.251.51"},
    {"num": "3", "site": "DCI", "ip": "10.222.251.51"},
    {"num": "4", "site": "DEV", "ip": "10.201.16.138"},
]


console = Console()


# -------------------- Authentication -------------------- #

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


# -------------------- Fetch functions -------------------- #

def fetch_api(url: str, cookies: RequestsCookieJar,
              description: str = "Fetching data") -> Optional[Dict]:
    """Generic API fetch function with error handling"""
    try:
        with console.status(f"[cyan]{description}...[/cyan]", spinner="dots"):
            response = requests.get(url, cookies=cookies, verify=False, timeout=60)

        if response.status_code != 200:
            console.print(f"[yellow]⚠ API call to {url} returned status {response.status_code}[/yellow]")
            return None

        return response.json()
    except requests.exceptions.Timeout:
        console.print(f"[yellow]⚠ Timeout while {description}[/yellow]")
        return None
    except Exception as e:
        console.print(f"[yellow]⚠ Error while {description}: {str(e)}[/yellow]")
        return None


def fetch_apic_health(apic_ip: str, cookies: RequestsCookieJar) -> Optional[Dict]:
    """Fetch APIC cluster health data"""
    url = f"https://{apic_ip}/api/node/mo/topology/pod-1/node-1.json?query-target=subtree&target-subtree-class=infraWiNode"
    return fetch_api(url, cookies, "Fetching APIC health")


def fetch_top_system(apic_ip: str, cookies: RequestsCookieJar) -> Optional[Dict]:
    """Fetch topSystem data with health information"""
    url = f"https://{apic_ip}/api/node/class/topSystem.json?rsp-subtree-include=health"
    return fetch_api(url, cookies, "Fetching node information")


def fetch_faults(apic_ip: str, cookies: RequestsCookieJar) -> Optional[Dict]:
    """Fetch fault information"""
    url = f"https://{apic_ip}/api/node/class/faultInst.json"
    return fetch_api(url, cookies, "Fetching faults")


def fetch_cpu_mem(apic_ip: str, cookies: RequestsCookieJar) -> Tuple[Optional[Dict], Optional[Dict]]:
    """Fetch CPU and memory utilization data"""
    cpu_url = f"https://{apic_ip}/api/node/class/procSysCPU1d.json"
    mem_url = f"https://{apic_ip}/api/node/class/procSysMem1d.json"

    cpu_data = fetch_api(cpu_url, cookies, "Fetching CPU data")
    mem_data = fetch_api(mem_url, cookies, "Fetching memory data")

    return cpu_data, mem_data


def fetch_fabric_health(apic_ip: str, cookies: RequestsCookieJar) -> Optional[Dict]:
    """Fetch fabric health data"""
    url = f"https://{apic_ip}/api/node/class/fabricHealthTotal.json"
    return fetch_api(url, cookies, "Fetching fabric health")


def fetch_crc_errors(apic_ip: str, cookies: RequestsCookieJar) -> Optional[Dict]:
    """Fetch CRC error statistics from rmonEtherStats"""
    url = f"https://{apic_ip}/api/node/class/rmonEtherStats.json"
    return fetch_api(url, cookies, "Fetching CRC error statistics")


def fetch_fcs_errors(apic_ip: str, cookies: RequestsCookieJar) -> Optional[Dict]:
    """Fetch FCS error statistics from rmonDot3Stats"""
    url = f"https://{apic_ip}/api/node/class/rmonDot3Stats.json"
    return fetch_api(url, cookies, "Fetching FCS error statistics")


# -------------------- Process functions -------------------- #

def _get_first_child_attributes(item: Dict, child_key: str) -> Dict:
    """Helper to find a child entry by class name and return its attributes, if any."""
    children = item.get(list(item.keys())[0], {}).get("children", []) if isinstance(item, dict) else []
    for c in children:
        if child_key in c:
            return c[child_key].get("attributes", {})
    return {}


def process_apic_data(data: Dict) -> List[Dict]:
    """Process APIC controller data (robust to different APIC JSON shapes)"""
    nodes = []
    if not data:
        return nodes

    # If data has a top-level list keyed by 'infraWiNode' (some endpoints), handle it
    if isinstance(data, dict) and "infraWiNode" in data and isinstance(data["infraWiNode"], list):
        for node in data["infraWiNode"]:
            attrs = node.get("attributes", {}) if isinstance(node, dict) else {}
            name = attrs.get("nodeName") or attrs.get("name") or attrs.get("id", "")
            serial = attrs.get("mbSn") or attrs.get("serial", "")
            nodes.append({
                "name": name,
                "serial": serial,
                "mode": attrs.get("apicMode", ""),
                "status": attrs.get("operSt", ""),
                "health_str": attrs.get("health", "unknown"),
                "health": 100 if str(attrs.get("health", "")).lower() in ["fully-fit", "100"] else 50 if str(attrs.get("health", "")).lower() == "degraded" else int(attrs.get("health", 0) or 0)
            })
        return nodes

    # More common APIC responses use 'imdata' list
    imdata = data.get("imdata") if isinstance(data, dict) else None
    if not imdata:
        return nodes

    for entry in imdata:
        if not isinstance(entry, dict):
            continue
        # entry will have a single key whose value contains attributes
        class_key = next(iter(entry.keys()), None)
        if not class_key:
            continue
        obj = entry.get(class_key, {})
        attrs = obj.get("attributes", {})
        # Try to form sensible fields even if names differ
        name = attrs.get("nodeName") or attrs.get("name") or attrs.get("id") or ""
        serial = attrs.get("mbSn") or attrs.get("serial") or ""
        # ip may be stored in different fields
        ip = attrs.get("oobNetwork", {}).get("address4", "").split("/")[0] if isinstance(attrs.get("oobNetwork"), dict) else attrs.get("oobMgmtAddr", "") or attrs.get("address", "")
        # health string may be nested or numeric
        health_str = attrs.get("health") or attrs.get("healthRollup") or ""
        # derive numeric health
        try:
            numeric_health = int(attrs.get("health", attrs.get("cur", 0)) or 0)
        except Exception:
            numeric_health = 100 if str(health_str).lower() in ["fully-fit", "fully fit"] else 50 if str(health_str).lower() == "degraded" else 0

        nodes.append({
            "name": name,
            "serial": serial,
            "ip": ip,
            "mode": attrs.get("apicMode", ""),
            "status": attrs.get("operSt", attrs.get("status", "")),
            "health_str": health_str if health_str else str(numeric_health),
            "health": numeric_health
        })
    return nodes


def process_leaf_spine(top_data: Dict, cpu_data: Dict, mem_data: Dict) -> List[Dict]:
    """Process leaf and spine node data"""
    nodes = []

    if not top_data or "imdata" not in top_data:
        return nodes

    # Build CPU/Memory map keyed by node-id forms ('1', 'node-1')
    cpu_map: Dict[str, float] = {}
    mem_map: Dict[str, float] = {}

    if cpu_data and "imdata" in cpu_data:
        for c in cpu_data.get("imdata", []):
            obj_key = next(iter(c.keys()), None)
            if not obj_key or obj_key not in c:
                continue
            attrs = c[obj_key].get("attributes", {})
            dn = attrs.get("dn", "")
            # try to extract node id
            node_id_numeric = None
            m = re.search(r'node-(\d+)', dn)
            if m:
                node_id_numeric = m.group(1)
            else:
                # alternative parsing of dn e.g. something like sys/proc/syscpu
                parts = dn.split("/")
                for p in parts:
                    pm = re.match(r'node-(\d+)', p)
                    if pm:
                        node_id_numeric = pm.group(1)
                        break

            try:
                user_util = float(attrs.get("userAvg", 0))
                kernel_util = float(attrs.get("kernelAvg", 0))
                primary_util = user_util + kernel_util
            except Exception:
                primary_util = float(attrs.get("util", 0) or 0)

           # try:
            #    idle_value = float(attrs.get("idleLast", 100))
             #   idle_based_util = 100 - idle_value
            #except Exception:
             #   idle_based_util = primary_util

            # if we got a node id, store both keyed forms
            if node_id_numeric is not None:
                cpu_map[node_id_numeric] = primary_util
                cpu_map[f"node-{node_id_numeric}"] = primary_util

    if mem_data and "imdata" in mem_data:
        for m in mem_data.get("imdata", []):
            obj_key = next(iter(m.keys()), None)
            if not obj_key or obj_key not in m:
                continue
            attrs = m[obj_key].get("attributes", {})
            dn = attrs.get("dn", "")
            node_id_numeric = None
            mm = re.search(r'node-(\d+)', dn)
            if mm:
                node_id_numeric = mm.group(1)

            if "PercUsedMemoryAvg" in attrs:
                try:
                    mem_val = float(attrs.get("PercUsedMemoryAvg", 0))
                except Exception:
                    mem_val = 0.0
            else:
                try:
                    total_avg = float(attrs.get("totalAvg", 0))
                    used_avg = float(attrs.get("usedAvg", 0))
                    mem_val = (used_avg / total_avg) * 100 if total_avg > 0 else 0.0
                except Exception:
                    mem_val = 0.0

            if node_id_numeric is not None:
                mem_map[node_id_numeric] = mem_val
                mem_map[f"node-{node_id_numeric}"] = mem_val

    # Now parse topSystem entries
    for item in top_data.get("imdata", []):
        class_key = next(iter(item.keys()), None)
        if not class_key:
            continue
        top_obj = item[class_key]
        attr = top_obj.get("attributes", {})
        role = (attr.get("role") or "").lower()
        if role not in ["leaf", "spine"]:
            # Some environments don't set role; we can still include switches by checking other hints
            # skip if role missing to avoid extraneous entries
            continue

        # Find health child attributes if present
        health_attr = {}
        for child in top_obj.get("children", []):
            if "healthInst" in child:
                health_attr = child["healthInst"].get("attributes", {})
                break
            # also check nested child's children
            for cc in child.get("children", []):
                if "healthInst" in cc:
                    health_attr = cc["healthInst"].get("attributes", {})
                    break

        # health score numeric
        try:
            health_score = int(health_attr.get("cur", attr.get("health", 0) or 0))
        except Exception:
            try:
                health_score = int(attr.get("health", 0) or 0)
            except Exception:
                health_score = 0

        # node id detection: prefer id attribute
        node_id = str(attr.get("id") or attr.get("serial") or "")
        # if id looks like numeric, keep numeric only to match cpu_map keys
        if node_id.startswith("node-"):
            node_id_key = node_id.replace("node-", "")
        else:
            node_id_key = node_id

        # fallback: try to extract from oobMgmtAddr or dn fields if id not present
        if not node_id_key:
            dn = attr.get("dn", "")
            m = re.search(r'node-(\d+)', dn)
            if m:
                node_id_key = m.group(1)

        nodes.append({
            "name": attr.get("name", ""),
            "role": role,
            "serial": attr.get("serial", ""),
            "ip": attr.get("oobMgmtAddr", attr.get("address", "")),
            "version": attr.get("version", ""),
            "uptime": attr.get("systemUpTime", ""),
            "health": health_score,
            "cpu": float(cpu_map.get(node_id_key, 0)),
            "memory": float(mem_map.get(node_id_key, 0))
        })
    return nodes


def process_faults(data: Dict) -> List[Dict]:
    """Process fault data"""
    faults = []
    if not data or "imdata" not in data:
        return faults

    for f in data.get("imdata", []):
        class_key = next(iter(f.keys()), None)
        if not class_key:
            continue
        attr = f[class_key].get("attributes", {})
        # Only include critical and major faults
        if attr.get("severity", "").lower() in ["critical", "major"]:
            faults.append({
                "severity": attr.get("severity", ""),
                "code": attr.get("code", ""),
                "description": attr.get("descr", ""),
                "last_change": attr.get("lastTransition", ""),
                "dn": attr.get("dn", "")
            })
    return faults


def process_fabric_health(data: Dict) -> int:
    """Extract fabric health score from fabricHealthTotal data"""
    if not data or "imdata" not in data or not data["imdata"]:
        return 0

    # pick first item that has fabricHealthTotal
    for item in data.get("imdata", []):
        key = next(iter(item.keys()), None)
        if key and "fabricHealthTotal" in key:
            health_attr = item[key].get("attributes", {})
            try:
                return int(health_attr.get("cur", 0))
            except Exception:
                return 0

    # fallback
    try:
        health_attr = data["imdata"][0][next(iter(data["imdata"][0].keys()))].get("attributes", {})
        return int(health_attr.get("cur", 0) or 0)
    except Exception:
        return 0


def process_fcs_errors(data: Dict, threshold: int) -> List[Dict]:
    """Process FCS error data"""
    interfaces = []
    if not data or "imdata" not in data:
        return interfaces

    for item in data.get("imdata", []):
        class_key = next(iter(item.keys()), None)
        if not class_key:
            continue
        attr = item[class_key].get("attributes", {})

        # Get FCS errors (key may be fCSErrors or fcsErrors depending on schema)
        fcs_errors = int(attr.get("fCSErrors", attr.get("fcsErrors", 0) or 0))

        # Only include interfaces with fcs errors above threshold
        if fcs_errors > threshold:
            dn = attr.get("dn", "")
            interface_name = "Unknown"
            node_id = "Unknown"

            interface_match = re.search(r'(phys|aggr)-\[(.*?)\]', dn)
            if interface_match:
                interface_name = interface_match.group(2)

            node_match = re.search(r'node-(\d+)', dn)
            if node_match:
                node_id = f"node-{node_match.group(1)}"

            interfaces.append({
                "node": node_id,
                "interface": interface_name,
                "fcs_errors": fcs_errors,
                "dn": dn
            })

    return interfaces


def process_crc_errors(data: Dict, threshold: int) -> List[Dict]:
    """Process CRC error data"""
    interfaces = []
    if not data or "imdata" not in data:
        return interfaces

    for item in data.get("imdata", []):
        class_key = next(iter(item.keys()), None)
        if not class_key:
            continue
        attr = item[class_key].get("attributes", {})

        # Get CRC errors (key names differ by schema)
        crc_errors = int(attr.get("cRCAlignErrors", attr.get("crcAlignErrors", 0) or 0))

        if crc_errors > threshold:
            dn = attr.get("dn", "")
            interface_name = "Unknown"
            node_id = "Unknown"

            interface_match = re.search(r'(phys|aggr)-\[(.*?)\]', dn)
            if interface_match:
                interface_name = interface_match.group(2)

            node_match = re.search(r'node-(\d+)', dn)
            if node_match:
                node_id = f"node-{node_match.group(1)}"

            interfaces.append({
                "node": node_id,
                "interface": interface_name,
                "crc_errors": crc_errors,
                "dn": dn
            })

    return interfaces


# -------------------- Reporting -------------------- #

def print_report(apic_nodes: List[Dict], leaf_spine_nodes: List[Dict],
                 faults: List[Dict], fabric_health: int, fcs_errors: List[Dict],
                 crc_errors: List[Dict]):
    """Print comprehensive health report"""

    # Use default thresholds
    health_threshold = DEFAULT_HEALTH_THRESHOLD
    cpu_mem_threshold = DEFAULT_CPU_MEM_THRESHOLD
    interface_threshold = DEFAULT_INTERFACE_ERROR_THRESHOLD

    # Fabric health panel
    health_status = "Normal" if fabric_health >= health_threshold else "Needs Attention"
    status_color = "green" if fabric_health >= health_threshold else "red"

    console.print(Panel(
        f"Fabric Health Score: [bold]{fabric_health}%[/bold] - [{status_color}]{health_status}[/{status_color}]",
        title="FABRIC HEALTH SUMMARY",
        expand=False
    ))
    console.print()

    # APIC Table
    if apic_nodes:
        apic_table = Table(title="APIC CONTROLLERS", box=box.ROUNDED)
        apic_table.add_column("Hostname", style="bold")
        apic_table.add_column("Serial")
        apic_table.add_column("Mode")
        apic_table.add_column("Status")
        apic_table.add_column("Health")

        for n in apic_nodes:
            status_style = "green" if n.get("health", 0) >= health_threshold else "red"
            apic_table.add_row(
                str(n.get("name", "")),
                str(n.get("serial", "")),
                str(n.get("mode", "")),
                str(n.get("status", "")),
                f"[{status_style}]{n.get('health_str', '')}[/{status_style}]"
            )
        console.print(apic_table)
        console.print()
    else:
        console.print("[yellow]No APIC controller data available[/yellow]")
        console.print()

    # Leaf/Spine Table
    if leaf_spine_nodes:
        leaf_table = Table(title="LEAF/SPINE NODES", box=box.ROUNDED)
        for col in ["Hostname", "Role", "Serial", "IP", "Version", "Uptime", "Health", "CPU", "Memory"]:
            leaf_table.add_column(col)

        for n in leaf_spine_nodes:
            health_style = "green" if n.get("health", 0) >= health_threshold else "red"
            cpu_style = "green" if n.get("cpu", 0) < cpu_mem_threshold else "red"
            mem_style = "green" if n.get("memory", 0) < cpu_mem_threshold else "red"

            leaf_table.add_row(
                str(n.get("name", "")),
                str(n.get("role", "")).capitalize(),
                str(n.get("serial", "")),
                str(n.get("ip", "")),
                str(n.get("version", "")),
                str(n.get("uptime", "")),
                f"[{health_style}]{n.get('health', 0)}%[/{health_style}]",
                f"[{cpu_style}]{n.get('cpu', 0):.1f}%[/{cpu_style}]",
                f"[{mem_style}]{n.get('memory', 0):.1f}%[/{mem_style}]"
            )
        console.print(leaf_table)
        console.print()
    else:
        console.print("[yellow]No leaf/spine node data available[/yellow]")
        console.print()

    # Faults Table
    if faults:
        fault_table = Table(title="CRITICAL/MAJOR FAULTS", box=box.ROUNDED)
        for col in ["Severity", "Code", "Description", "Last Change", "DN"]:
            fault_table.add_column(col)

        for f in faults:
            severity_style = "red" if f.get("severity", "").lower() == "critical" else "yellow"
            fault_table.add_row(
                f"[{severity_style}]{f.get('severity', '').upper()}[/{severity_style}]",
                str(f.get("code", "")),
                str(f.get("description", "")),
                str(f.get("last_change", "")),
                str(f.get("dn", ""))
            )
        console.print(fault_table)
        console.print()
    else:
        console.print(Panel("✓ No critical or major faults found", style="green"))
        console.print()

    # FCS Errors Table
    if fcs_errors:
        fcs_table = Table(title=f"FCS ERRORS (Threshold: {interface_threshold})", box=box.ROUNDED)
        fcs_table.add_column("Node")
        fcs_table.add_column("Interface")
        fcs_table.add_column("FCS Errors")
        fcs_table.add_column("DN")

        for intf in fcs_errors:
            fcs_error_style = "red" if intf.get("fcs_errors", 0) > interface_threshold else "yellow"

            fcs_table.add_row(
                str(intf.get("node", "")),
                str(intf.get("interface", "")),
                f"[{fcs_error_style}]{intf.get('fcs_errors', 0)}[/{fcs_error_style}]",
                str(intf.get("dn", ""))
            )
        console.print(fcs_table)
        console.print()
    else:
        console.print(Panel("✓ No FCS errors above threshold found", style="green"))
        console.print()

    # CRC Errors Table
    if crc_errors:
        crc_table = Table(title=f"CRC ERRORS (Threshold: {interface_threshold})", box=box.ROUNDED)
        crc_table.add_column("Node")
        crc_table.add_column("Interface")
        crc_table.add_column("CRC Errors")
        crc_table.add_column("DN")

        for intf in crc_errors:
            crc_error_style = "red" if intf.get("crc_errors", 0) > interface_threshold else "yellow"

            crc_table.add_row(
                str(intf.get("node", "")),
                str(intf.get("interface", "")),
                f"[{crc_error_style}]{intf.get('crc_errors', 0)}[/{crc_error_style}]",
                str(intf.get("dn", ""))
            )
        console.print(crc_table)
        console.print()
    else:
        console.print(Panel("✓ No CRC errors above threshold found", style="green"))
        console.print()

    # Generate and display summary
    summary_data = generate_summary(apic_nodes, leaf_spine_nodes, faults,
                                    fabric_health, fcs_errors, crc_errors)
    print_summary(summary_data)


def generate_summary(apic_nodes: List[Dict], leaf_spine_nodes: List[Dict],
                     faults: List[Dict], fabric_health: int, fcs_errors: List[Dict],
                     crc_errors: List[Dict]) -> Dict:
    """Generate summary data for the report"""
    # Use default thresholds
    health_threshold = DEFAULT_HEALTH_THRESHOLD
    cpu_mem_threshold = DEFAULT_CPU_MEM_THRESHOLD
    interface_threshold = DEFAULT_INTERFACE_ERROR_THRESHOLD

    # APIC Health
    apic_health_ok = all(n.get("health", 0) >= health_threshold for n in apic_nodes) if apic_nodes else False
    apic_count = len(apic_nodes)
    apic_problem_count = len([n for n in apic_nodes if n.get("health", 0) < health_threshold])

    # Leaf/Spine Health
    leaf_spine_health_ok = all(n.get("health", 0) >= health_threshold for n in leaf_spine_nodes) if leaf_spine_nodes else False
    leaf_spine_count = len(leaf_spine_nodes)
    leaf_spine_health_problem_count = len([n for n in leaf_spine_nodes if n.get("health", 0) < health_threshold])

    # CPU/Memory Health
    cpu_mem_ok = all(
        n.get("cpu", 0) < cpu_mem_threshold and n.get("memory", 0) < cpu_mem_threshold
        for n in leaf_spine_nodes
    ) if leaf_spine_nodes else False
    cpu_problem_count = len([n for n in leaf_spine_nodes if n.get("cpu", 0) >= cpu_mem_threshold])
    mem_problem_count = len([n for n in leaf_spine_nodes if n.get("memory", 0) >= cpu_mem_threshold])

    # Fabric Health
    fabric_health_ok = fabric_health >= health_threshold

    # Faults
    critical_faults = len([f for f in faults if f.get("severity", "").lower() == "critical"])
    major_faults = len([f for f in faults if f.get("severity", "").lower() == "major"])

    # FCS Errors
    fcs_error_count = len(fcs_errors or [])
    fcs_errors_ok = fcs_error_count == 0

    # CRC Errors
    crc_error_count = len(crc_errors or [])
    crc_errors_ok = crc_error_count == 0

    # Overall status
    overall_ok = (apic_health_ok and leaf_spine_health_ok and cpu_mem_ok and
                  fabric_health_ok and critical_faults == 0 and major_faults == 0 and
                  crc_errors_ok and fcs_errors_ok)

    return {
        "overall_status": "PASS" if overall_ok else "FAIL",
        "apic": {
            "status": "PASS" if apic_health_ok else "FAIL",
            "total": apic_count,
            "problems": apic_problem_count
        },
        "leaf_spine": {
            "status": "PASS" if leaf_spine_health_ok else "FAIL",
            "total": leaf_spine_count,
            "health_problems": leaf_spine_health_problem_count,
            "cpu_problems": cpu_problem_count,
            "mem_problems": mem_problem_count
        },
        "fabric": {
            "status": "PASS" if fabric_health_ok else "FAIL",
            "score": fabric_health
        },
        "faults": {
            "critical": critical_faults,
            "major": major_faults
        },
        "fcs_errors": {
            "status": "PASS" if fcs_errors_ok else "FAIL",
            "count": fcs_error_count,
        },
        "crc_errors": {
            "status": "PASS" if crc_errors_ok else "FAIL",
            "count": crc_error_count,
        },
        "thresholds": {
            "health": health_threshold,
            "cpu_mem": cpu_mem_threshold,
            "interface": interface_threshold
        }
    }


def print_summary(summary_data: Dict):
    """Print summary panel"""
    summary_text = Text()

    # Overall status
    overall_color = "green" if summary_data["overall_status"] == "PASS" else "red"
    summary_text.append("OVERALL STATUS: ", style="bold")
    summary_text.append(f"{summary_data['overall_status']}\n", style=f"bold {overall_color}")
    summary_text.append("\n")

    # APIC Status
    apic_color = "green" if summary_data["apic"]["status"] == "PASS" else "red"
    summary_text.append("APIC Controllers: ", style="bold")
    summary_text.append(f"{summary_data['apic']['status']} ", style=apic_color)
    summary_text.append(f"({summary_data['apic']['problems']} of {summary_data['apic']['total']} with issues)\n")

    # Leaf/Spine Status
    leaf_spine_color = "green" if summary_data["leaf_spine"]["status"] == "PASS" else "red"
    summary_text.append("Leaf/Spine Nodes: ", style="bold")
    summary_text.append(f"{summary_data['leaf_spine']['status']} ", style=leaf_spine_color)
    summary_text.append(f"({summary_data['leaf_spine']['health_problems']} health, ")
    summary_text.append(f"{summary_data['leaf_spine']['cpu_problems']} CPU, ")
    summary_text.append(f"{summary_data['leaf_spine']['mem_problems']} memory issues)\n")

    # Fabric Status
    fabric_color = "green" if summary_data["fabric"]["status"] == "PASS" else "red"
    summary_text.append("Fabric Health: ", style="bold")
    summary_text.append(f"{summary_data['fabric']['status']} ", style=fabric_color)
    summary_text.append(f"(Score: {summary_data['fabric']['score']}%)\n")

    # Faults
    faults_total = summary_data["faults"]["critical"] + summary_data["faults"]["major"]
    faults_color = "green" if faults_total == 0 else "red"
    summary_text.append("Critical/Major Faults: ", style="bold")
    summary_text.append(f"{faults_total} ", style=faults_color)
    summary_text.append(f"({summary_data['faults']['critical']} critical, {summary_data['faults']['major']} major)\n")

    # FCS Errors
    fcs_color = "green" if summary_data["fcs_errors"]["status"] == "PASS" else "red"
    summary_text.append("FCS Errors: ", style="bold")
    summary_text.append(f"{summary_data['fcs_errors']['status']} ", style=fcs_color)
    summary_text.append(f"({summary_data['fcs_errors']['count']} interfaces)\n")

    # CRC Errors
    crc_color = "green" if summary_data["crc_errors"]["status"] == "PASS" else "red"
    summary_text.append("CRC Errors: ", style="bold")
    summary_text.append(f"{summary_data['crc_errors']['status']} ", style=crc_color)
    summary_text.append(f"({summary_data['crc_errors']['count']} interfaces)\n")

    # Thresholds
    summary_text.append("\nThresholds: ", style="bold")
    summary_text.append(f"Health: {summary_data['thresholds']['health']}%, ")
    summary_text.append(f"CPU/Memory: {summary_data['thresholds']['cpu_mem']}%, ")
    summary_text.append(f"Interface: {summary_data['thresholds']['interface']} errors\n")

    console.print(Panel(summary_text, title="SUMMARY", style="bold"))
    console.print()

    # Final status panel
    status_msg = "✓ ALL CHECKS PASSED" if summary_data["overall_status"] == "PASS" else "✗ ISSUES DETECTED"
    status_style = "green" if summary_data["overall_status"] == "PASS" else "red"
    console.print(Panel(status_msg, style=status_style, expand=False))


# -------------------- Data Saving -------------------- #

def ensure_dir(directory: str) -> bool:
    """Ensure directory exists, create if it doesn't"""
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        console.print(f"[red]Error creating directory {directory}: {str(e)}[/red]")
        return False


def save_raw_json(apic_raw: Optional[Dict], top_raw: Optional[Dict], cpu_raw: Optional[Dict],
                  mem_raw: Optional[Dict], faults_raw: Optional[Dict], fabric_raw: Optional[Dict],
                  crc_raw: Optional[Dict], fcs_raw: Optional[Dict], intf_raw: Optional[Dict], output_dir: str) -> bool:
    """Save raw JSON responses to files"""
    if not ensure_dir(output_dir):
        return False

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    files = [
        (f"APIC_Raw_{timestamp}.json", apic_raw),
        (f"TopSystem_Raw_{timestamp}.json", top_raw),
        (f"CPU_Raw_{timestamp}.json", cpu_raw),
        (f"MEM_Raw_{timestamp}.json", mem_raw),
        (f"Faults_Raw_{timestamp}.json", faults_raw),
        (f"FabricHealth_Raw_{timestamp}.json", fabric_raw),
        (f"FCS_Errors_Raw_{timestamp}.json", fcs_raw),
        (f"CRC_Errors_Raw_{timestamp}.json", crc_raw),
        (f"InterfaceStats_Raw_{timestamp}.json", intf_raw)
    ]

    try:
        for fname, data in files:
            if data is not None:  # Only save if we have data
                with open(os.path.join(output_dir, fname), "w") as f:
                    json.dump(data, f, indent=4)

        console.print(f"[green]✓ Raw JSON files saved to {output_dir} with timestamp {timestamp}[/green]")
        return True
    except Exception as e:
        console.print(f"[red]Error saving JSON files: {str(e)}[/red]")
        return False


def save_report_text(apic_nodes: List[Dict], leaf_spine_nodes: List[Dict],
                     faults: List[Dict], fabric_health: int, fcs_errors: List[Dict],
                     crc_errors: List[Dict], output_dir: str) -> bool:
    """Save report as text file with comprehensive summary"""
    if not ensure_dir(output_dir):
        return False

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"ACI_Health_Report_{timestamp}.txt")

    try:
        with open(filename, 'w') as f:
            # Header
            f.write("=" * 60 + "\n")
            f.write("ACI FABRIC HEALTH REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"APIC: {getattr('apic', '')}\n")
            f.write(f"Health Threshold: {DEFAULT_HEALTH_THRESHOLD}%\n")
            f.write(f"CPU/Memory Threshold: {DEFAULT_CPU_MEM_THRESHOLD}%\n")
            f.write("=" * 60 + "\n\n")

            # Fabric health
            f.write(f"FABRIC HEALTH SCORE: {fabric_health}%\n")
            f.write("Status: ")
            f.write("NORMAL\n\n" if fabric_health >= DEFAULT_HEALTH_THRESHOLD else "NEEDS ATTENTION\n\n")

            # Generate summary data
            summary_data = generate_summary(apic_nodes, leaf_spine_nodes, faults,
                                            fabric_health, fcs_errors, crc_errors)

            # Summary section
            f.write("SUMMARY\n")
            f.write("-" * 60 + "\n")
            f.write(f"Overall Status: {summary_data['overall_status']}\n")
            f.write(f"APIC Controllers: {summary_data['apic']['status']} ")
            f.write(f"({summary_data['apic']['problems']} of {summary_data['apic']['total']} with issues)\n")
            f.write(f"Leaf/Spine Nodes: {summary_data['leaf_spine']['status']} ")
            f.write(f"({summary_data['leaf_spine']['health_problems']} health, ")
            f.write(f"{summary_data['leaf_spine']['cpu_problems']} CPU, ")
            f.write(f"{summary_data['leaf_spine']['mem_problems']} memory issues)\n")
            f.write(f"Fabric Health: {summary_data['fabric']['status']} ")
            f.write(f"(Score: {summary_data['fabric']['score']}%)\n")
            f.write(f"Critical/Major Faults: {summary_data['faults']['critical'] + summary_data['faults']['major']} ")
            f.write(f"({summary_data['faults']['critical']} critical, {summary_data['faults']['major']} major)\n\n")

            # APIC Controllers
            f.write("APIC CONTROLLERS\n")
            f.write("-" * 60 + "\n")
            if apic_nodes:
                for node in apic_nodes:
                    status = "OK" if node.get("health", 0) >= DEFAULT_HEALTH_THRESHOLD else "ISSUE"
                    f.write(f"{str(node.get('name','')):15} {str(node.get('serial','')):15} {str(node.get('ip','')):15} ")
                    f.write(f"{str(node.get('mode','')):10} {str(node.get('status','')):10} {str(node.get('health_str','')):12} [{status}]\n")
            else:
                f.write("No APIC controller data available\n")
            f.write("\n")

            # Leaf/Spine Nodes
            f.write("LEAF/SPINE NODES\n")
            f.write("-" * 60 + "\n")
            if leaf_spine_nodes:
                for node in leaf_spine_nodes:
                    health_status = "OK" if node.get("health", 0) >= DEFAULT_HEALTH_THRESHOLD else "ISSUE"
                    cpu_status = "OK" if node.get("cpu", 0) < DEFAULT_CPU_MEM_THRESHOLD else "ISSUE"
                    mem_status = "OK" if node.get("memory", 0) < DEFAULT_CPU_MEM_THRESHOLD else "ISSUE"

                    f.write(f"{str(node.get('name','')):15} {str(node.get('role','')).capitalize():6} {str(node.get('serial','')):15} ")
                    f.write(f"{str(node.get('ip','')):15} {str(node.get('version','')):12} ")
                    f.write(f"{node.get('health',0):3}% [{health_status}] ")
                    f.write(f"{node.get('cpu',0):5.1f}% [{cpu_status}] ")
                    f.write(f"{node.get('memory',0):5.1f}% [{mem_status}]\n")
            else:
                f.write("No leaf/spine node data available\n")
            f.write("\n")

            # Faults
            f.write("CRITICAL/MAJOR FAULTS\n")
            f.write("-" * 60 + "\n")
            if faults:
                for fault in faults:
                    f.write(f"{fault.get('severity','').upper():10} {fault.get('code',''):10} ")
                    f.write(f"{fault.get('last_change',''):25} {fault.get('description','')}\n")
            else:
                f.write("No critical or major faults found\n")
            f.write("\n")

            # FCS Errors section
            f.write("FCS ERRORS\n")
            f.write("-" * 60 + "\n")
            if fcs_errors:
                f.write(f"Node{'':10} Interface{'':10} FCS Errors{'':6}\n")
                for intf in fcs_errors:
                    f.write(f"{str(intf.get('node','')):15} {str(intf.get('interface','')):15} ")
                    f.write(f"{intf.get('fcs_errors',0):12} \n")
            else:
                f.write("No FCS errors above threshold found\n")
            f.write("\n")

            # CRC Errors section
            f.write("CRC ERRORS\n")
            f.write("-" * 60 + "\n")
            if crc_errors:
                f.write(f"Node{'':10} Interface{'':10} CRC Errors{'':6}\n")
                for intf in crc_errors:
                    crc_val = intf.get('crc_errors', intf.get('total_crc_errors', 0))
                    f.write(f"{str(intf.get('node','')):15} {str(intf.get('interface','')):15} ")
                    f.write(f"{crc_val:12} \n")
            else:
                f.write("No CRC errors above threshold found\n")
            f.write("\n")

        console.print(f"[green]✓ Text report saved to {filename}[/green]")
        return True
    except Exception as e:
        console.print("[red]Error saving text report:[/red]", e)
        # best-effort debug (guarded)
        try:
            if fcs_errors:
                console.print("FCS Errors data sample (first 5):")
                for i, err in enumerate(fcs_errors[:5]):
                    console.print(f"  {i}: {err}")
        except Exception:
            pass
        return False


def save_report_csv(apic_nodes: List[Dict], site: str, leaf_spine_nodes: List[Dict],
                    faults: List[Dict], fabric_health: int, fcs_errors: List[Dict],
                    crc_errors: List[Dict], output_dir: str) -> bool:
    """Save report as CSV files"""
    if not ensure_dir(output_dir):
        return False
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        # Save APIC Controllers
        if apic_nodes:
            filename = os.path.join(output_dir, f"{site}_APIC_Controllers_{timestamp}.csv")
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    "Hostname",
                    "Serial",
                    "IP", 
                    "Mode", 
                    "Status", 
                    "Health"
                ])
                
                for node in apic_nodes:
                    writer.writerow([
                        str(node.get("name", "")),
                        str(node.get("serial", "")),
                        str(node.get("ip", "")),
                        str(node.get("mode", "")),
                        str(node.get("status", "")),
                        str(node.get("health_str", ""))
                    ])
            console.print(f"[green]✓ APIC controllers CSV saved to {filename}[/green]")

        # Save Leaf/Spine Nodes
        if leaf_spine_nodes:
            filename = os.path.join(output_dir, f"{site}_Leaf_Spine_Nodes_{timestamp}.csv")
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    "Hostname",
                    "Role",
                    "Serial",
                    "IP",
                    "Version",
                    "Uptime",
                    "Health",
                    "CPU",
                    "Memory"
                ])
                
                for node in leaf_spine_nodes:
                    writer.writerow([
                        str(node.get("name", "")),
                        str(node.get("role", "")),
                        str(node.get("serial", "")),
                        str(node.get("ip", "")),
                        str(node.get("version", "")),
                        str(node.get("uptime", "")),
                        str(node.get("health", "")),
                        str(node.get("cpu", "")),
                        str(node.get("memory", ""))
                    ])
            console.print(f"[green]✓ Leaf/Spine nodes CSV saved to {filename}[/green]")

        # Save Faults
        if faults:
            filename = os.path.join(output_dir, f"{site}_Faults_{timestamp}.csv")
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    "Severity",
                    "Code",
                    "Description",
                    "Last Change",
                    "DN"
                ])
                
                for fault in faults:
                    writer.writerow([
                        str(fault.get("severity", "")),
                        str(fault.get("code", "")),
                        str(fault.get("description", "")),
                        str(fault.get("last_change", "")),
                        str(fault.get("dn", ""))
                    ])
            console.print(f"[green]✓ Faults CSV saved to {filename}[/green]")

        # Save FCS Errors
        if fcs_errors:
            filename = os.path.join(output_dir, f"{site}_FCS_Errors_{timestamp}.csv")
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    "Node",
                    "Interface",
                    "FCS Errors",
                    "DN"
                ])
                
                for error in fcs_errors:
                    writer.writerow([
                        str(error.get("node", "")),
                        str(error.get("interface", "")),
                        str(error.get("fcs_errors", "")),
                        str(error.get("dn", ""))
                    ])
            console.print(f"[green]✓ FCS errors CSV saved to {filename}[/green]")

        # Save CRC Errors
        if crc_errors:
            filename = os.path.join(output_dir, f"{site}_CRC_Errors_{timestamp}.csv")
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    "Node",
                    "Interface",
                    "CRC Errors",
                    "DN"
                ])
                
                for error in crc_errors:
                    writer.writerow([
                        str(error.get("node", "")),
                        str(error.get("interface", "")),
                        str(error.get("crc_errors", "")),
                        str(error.get("dn", ""))
                    ])
            console.print(f"[green]✓ CRC errors CSV saved to {filename}[/green]")

        return True
    except Exception as e:
        console.print(f"[red]Error saving CSV files: {str(e)}[/red]")
        return False


# -------------------- Main -------------------- #

def main_healthcheck_aci():
    """Main function to execute ACI health check"""

    # Get credentials
    apic_ip, site, username, password = get_credentials()

    # Login to APIC
    cookies = apic_login(apic_ip, username, password)
    if not cookies:
        sys.exit(1)

    # Fetch data with progress indication
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
    ) as progress:
        progress.add_task(description="Collecting APIC health data...", total=None)
        apic_raw = fetch_apic_health(apic_ip, cookies)

        progress.add_task(description="Collecting node information...", total=None)
        top_raw = fetch_top_system(apic_ip, cookies)

        progress.add_task(description="Checking for faults...", total=None)
        faults_raw = fetch_faults(apic_ip, cookies)

        progress.add_task(description="Collecting CPU/Memory data...", total=None)
        cpu_raw, mem_raw = fetch_cpu_mem(apic_ip, cookies)

        progress.add_task(description="Checking fabric health...", total=None)
        fabric_raw = fetch_fabric_health(apic_ip, cookies)

        progress.add_task(description="Checking FCS errors...", total=None)
        fcs_raw = fetch_fcs_errors(apic_ip, cookies)

        progress.add_task(description="Checking CRC errors...", total=None)
        crc_raw = fetch_crc_errors(apic_ip, cookies)

    # Process data
    interface_threshold = DEFAULT_INTERFACE_ERROR_THRESHOLD
    apic_nodes = process_apic_data(apic_raw) if apic_raw else []
    leaf_spine_nodes = process_leaf_spine(
        top_raw,
        cpu_raw if cpu_raw is not None else {},
        mem_raw if mem_raw is not None else {}
    ) if top_raw else []
    faults = process_faults(faults_raw) if faults_raw else []
    fabric_health = process_fabric_health(fabric_raw) if fabric_raw else 0
    fcs_errors = process_fcs_errors(fcs_raw,  interface_threshold ) if fcs_raw else []
    crc_errors = process_crc_errors(crc_raw,  interface_threshold ) if crc_raw else []

    # Report
    print_report(apic_nodes, leaf_spine_nodes, faults, fabric_health, fcs_errors,
                 crc_errors)

    # Always save csv report
    save_report_csv(apic_nodes, site, leaf_spine_nodes, faults, fabric_health, fcs_errors,
                        crc_errors, output_dir="output_healthcheck")
        