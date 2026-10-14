# Firewall Policy Tools

A web-based firewall policy management tool. It currently supports importing and parsing configurations from Cisco ASA, Palo Alto, Fortinet, and Huawei devices, with unified policy search, object inventory, risk analysis, policy change requests, and audit logs.

## Features

- Multi-vendor configuration import: Cisco ASA, Palo Alto, Fortinet, Huawei
- Multi-device tree navigation grouped by vendor and device
- Policy search by source, destination, port/service, application, user, zone/ACL, action, and keyword
- NAT rule inventory and search, including original and translated addresses/services
- Object inventory for address objects, service objects, and object groups
- Policy visualization: path analysis, matrix view, topology view, dependency graph, and rule order view
- Policy and NAT analysis: conflicts, duplicates, shadowed or never-hit rules, overly broad rules, risky ports/applications, cross-zone risk, broad NAT, duplicate NAT, and inbound NAT exposure
- Change precheck: detects conflicts, overlap, mutual exclusion, and recommends placement before adding a policy
- Device access: add a management IP in the GUI, test SSH/Telnet connectivity, fetch running configuration, and import it automatically
- Local persistence: imported results and request records are stored in SQLite

## Docker Installation

Clone the repository:

```bash
git clone https://github.com/boxie283555/FireWall-Policy-tools.git FireWall-Policy-tools
cd FireWall-Policy-tools
```

Start the service:

```bash
docker compose up -d --build
```

Open:

```text
http://127.0.0.1:8080
```

View logs:

```bash
docker compose logs -f
```

Stop the service:

```bash
docker compose down
```

Imported data is stored in the local `data/` directory and is not committed to Git.

## Local Python Installation

Use this option for local development or debugging. The commands below work on macOS and Linux.

### 1. Prerequisites

Make sure these are installed:

- Python 3.10 or later
- Git

Check versions:

```bash
python3 --version
git --version
```

### 2. Clone the Code

```bash
git clone https://github.com/boxie283555/FireWall-Policy-tools.git
cd FireWall-Policy-tools
```

### 3. Create a Python Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

After activation, the terminal prompt usually starts with `(.venv)`.

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Start the Service

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open:

```text
http://127.0.0.1:8080
```

To allow other machines on the same LAN to access it, start with:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Then open:

```text
http://<your-mac-ip>:8080
```

### 6. Stop the Service

Press this in the terminal running `uvicorn`:

```text
Ctrl + C
```

### 7. Start Again Later

```bash
cd FireWall-Policy-tools
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

### 8. Update the Code

```bash
cd FireWall-Policy-tools
git pull
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Imported data remains in `data/`; code updates do not remove it automatically.

## Deploy to 192.168.20.169

After Docker and Docker Compose are installed on `192.168.20.169`, clone and start the service:

```bash
ssh 192.168.20.169
git clone https://github.com/boxie283555/FireWall-Policy-tools.git /opt/firewall-policy-tools
cd /opt/firewall-policy-tools
docker compose up -d --build
```

To update an existing deployment:

```bash
cd /opt/firewall-policy-tools
git pull
docker compose up -d --build
```

The service listens on port `8080` by default.

You can also deploy from your current machine with the helper script:

```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh 192.168.20.169 /opt/firewall-policy-tools
```

## Usage

1. Open `http://127.0.0.1:8080` or `http://192.168.20.169:8080`.
2. Go to `Import Config`.
3. Select vendor and device name, then upload or paste a configuration.
4. Or go to `Device Access`, enter device IP, protocol, port, username, and a temporary password, then fetch the configuration directly.
5. Go to `Access Rules` to search security policies.
6. Go to `NAT Rules` to search NAT policies and review NAT analysis findings.
7. Go to `Objects` to search objects.
8. Go to `Path / Topology` to view path analysis, matrix, topology, dependency graph, and rule order.
9. Go to `Risk Findings` to review security policy analysis results.
10. Go to `Change Requests` to run precheck before adding a policy.

## Device Access

The `Device Access` page fetches configuration directly from firewalls:

- Vendors: Cisco ASA, Palo Alto, Fortinet, Huawei
- Protocols: SSH and Telnet
- Saved fields: device name, vendor, management IP, protocol, port, username, notes
- Not saved: password, enable password, token
- A successful fetch is parsed and imported automatically

Default commands by vendor:

- Cisco ASA: `terminal pager 0`, `show running-config`
- Palo Alto: `set cli pager off`, `set cli config-output-format set`, `configure`, `show`
- Fortinet: `config system console`, `set output standard`, `end`, `show full-configuration`
- Huawei: `screen-length 0 temporary`, `display current-configuration`

If Cisco ASA requires enable mode, select `Cisco ASA requires enable mode` and enter the enable password when testing or fetching.

## GitHub Push

First-time push to GitHub:

```bash
git remote add origin https://github.com/boxie283555/FireWall-Policy-tools.git
git branch -M main
git push -u origin main
```
