import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # type: ignore

def login(apic_ip, username, password):
    url = f"https://{apic_ip}/api/aaaLogin.json"
    payload = {
        "aaaUser": {
            "attributes": {
                "name": username,
                "pwd": password
            }
        }
    }
    response = requests.post(url, json=payload, verify=False)
    response.raise_for_status()
    return response.cookies, apic_ip

def get_fabric_health(cookies, apic_ip):
    url = f"https://{apic_ip}/api/node/class/fabricHealthTotal.json"
    r = requests.get(url, cookies=cookies, verify=False)
    return int(r.json()['imdata'][0]['fabricHealthTotal']['attributes']['cur'])

def get_faults(cookies, apic_ip):
    url = f"https://{apic_ip}/api/node/class/faultInst.json?query-target-filter=eq(faultInst.severity,\"critical\")"
    r = requests.get(url, cookies=cookies, verify=False)
    return r.json().get("imdata", [])

def get_interface_status(cookies, apic_ip):
    url = f"https://{apic_ip}/api/node/class/l1PhysIf.json"
    r = requests.get(url, cookies=cookies, verify=False)
    return r.json().get("imdata", [])

def get_endpoints(cookies, apic_ip):
    url = f"https://{apic_ip}/api/node/class/fvCEp.json"
    r = requests.get(url, cookies=cookies, verify=False)
    return r.json().get("imdata", [])

def get_urib_routes(cookies, apic_ip):
    url = f"https://{apic_ip}/api/node/class/uribv4Route.json"
    r = requests.get(url, cookies=cookies, verify=False)
    return r.json().get("imdata", [])

def get_interface_errors(cookies, apic_ip):
    url = f"https://{apic_ip}/api/node/class/ethpmPhysIf.json"
    r = requests.get(url, cookies=cookies, verify=False)
    return r.json().get("imdata", [])

def get_crc_errors(cookies, apic_ip):
    """Get CRC error statistics from rmonEtherStats"""
    url = f"https://{apic_ip}/api/node/class/rmonEtherStats.json"
    r = requests.get(url, cookies=cookies, verify=False)
    return r.json().get("imdata", [])

