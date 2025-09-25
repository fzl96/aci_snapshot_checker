# ACI Snapshot Checker Tool

A Python-based tool to **capture and compare the state of your Cisco ACI environment** before and after changes such as configuration updates, L3Out modifications, or tenant migrations.

---

## ✅ Features

- 🔐 **Secure interactive login** (username/password input at runtime)
- 📸 **Snapshots** of:
  - Fabric health score
  - Critical faults
  - Endpoints (MAC, IP, location)
  - Interface status (up/down)
  - **Interface error counters** (CRC errors, input discards, etc.)
  - Unified routing table (`uribv4Route`)
- 📊 **Comparisons**:
  - Missing / new / moved routes
  - Missing / new / moved endpoints
  - Fabric health delta
  - Fault delta
  - Interface state changes
  - **Interface error spikes** (detect counter increases)
- 🕓 **Timestamped snapshots** (`snapshot_before_YYYY-MM-DDTHH-MM.json`)
- 🔍 **Interactive CLI** with:
  1. Take snapshot BEFORE change
  2. Take snapshot AFTER change
  3. Compare last snapshots
  4. Compare any two snapshots
  5. Exit
- 🎨 **Colored, grouped output** via Rich
- 📂 **JSON-based snapshot storage**, plus history viewer

---

## 📁 Folder Structure

```
aci_snapshot_checker/
├── main.py
├── api/
│ └── aci_client.py
├── snapshot/
│ └── snapshotter.py
├── compare/
│ └── comparer.py
├── output/
│ ├── snapshot_before_2025-07-25T10-00.json
│ └── snapshot_after_2025-07-25T10-05.json
├── README.md
└── requirements.txt
```

---

## 🚀 How to Use

### 1. Clone the Repository

```bash
git clone https://github.com/nikmatjayadi/aci-snapshot-checker/
cd aci-snapshot-checker
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Tool

```bash
python main.py
```

### 4. Choose an Action

```
🔧 ACI Snapshot Checker
1. Take snapshot BEFORE change
2. Take snapshot AFTER change
3. Compare snapshots
4. Compare any two snapshots
0. Exit
```

---

## 📊 Sample Output

```
📈 COMPARISON RESULT:

🔹 fabric_health:
  - before: 91
  - after: 91

🔹 new_faults:
  (none)

🔹 cleared_faults:
  (none)

🔹 new_endpoints:
  (none)

🔹 missing_endpoints:
  (none)

🔹 moved_endpoints:
  (none)

🔹 interface_changes:
  - status_changed: (none)
  - missing: (none)
  - new: (none)

🔹 interface_error_changes:
  - new_errors:
     🆕 topology/pod-1/node-201/sys/phys-[eth1/1]/phys — CRC errors: 2 ➜ 5
  - cleared_errors:
     ✅ topology/pod-1/node-201/sys/phys-[eth1/5]/phys — CRC errors: 4 ➜ 0

🔹 urib_route_changes:
  - missing: (none)
  - new: (none)
```

---

## 📦 Requirements

- Python 3.7+
- Cisco ACI APIC (HTTPS reachable)
- Read-only API access (recommended: `read-all` privileges)

---

## 👨‍💻 Author

Created by **NJ** · Cisco ACI & Python automation enthusiast  
GitHub: [nikmatjayadi](https://github.com/nikmatjayadi)
