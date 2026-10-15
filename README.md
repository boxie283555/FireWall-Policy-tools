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
- Policy lifecycle and governance checks: disabled rules, expired rules, expiring rules, missing owner metadata, and missing expiration metadata
- Change precheck: detects conflicts, overlap, mutual exclusion, and recommends placement before adding a policy
- Change workflow tracking: draft, review, approved, rejected, and implemented status updates with audit log entries
- Reporting exports: CSV exports for findings, policy inventory, and NAT inventory
- Device access: add a management IP in the GUI, test SSH, Telnet, API/HTTPS, or NETCONF connectivity, fetch running configuration, and import it automatically
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
9. Go to `Risk Findings` to review security policy and NAT risk summaries, then export findings, policy inventory, or NAT inventory as CSV.
10. Go to `Change Requests` to run precheck before adding a policy and track the request status through review, approval, rejection, or implementation.

## Device Access

The `Device Access` page fetches configuration directly from firewalls:

- Vendors: Cisco ASA, Palo Alto, Fortinet, Huawei
- Protocols: SSH, Telnet, API/HTTPS, and NETCONF
- Saved fields: device name, vendor, management IP, protocol, port, username, notes
- Not saved: password, enable password, token
- A successful fetch is parsed and imported automatically

Recommended online fetch methods:

- Palo Alto: use `API / HTTPS` on port `443`. In the password field, enter either a PAN-OS API key or the account password. If a password is entered, the tool tries PAN-OS XML API key generation and then exports the configuration.
- Fortinet: use `API / HTTPS` on port `443`. In the password field, enter a Fortinet API token.
- Huawei: use `NETCONF` on port `830`. Enter the NETCONF username and password.
- Cisco ASA: use `SSH` or `Telnet`. ASA API support depends heavily on version and installed REST API components, so CLI fetch remains the default.

Default SSH/Telnet commands by vendor:

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

## Risk Remediation

Risk Findings uses a collapsible tree: security policy or NAT → risk category → individual finding. Expand a finding to inspect its rules, start a remediation ticket, or generate candidate commands. Tickets store the owner, editable plan, command and rollback text, status, and original rule snapshots in SQLite; creation and updates appear in the audit log. Tickets remain available after configuration reimports.

Command generation currently supports PAN-OS local security/NAT rules and FortiGate firewall policies: disable a selected rule or replace its complete source, destination, or service scope. Confirm the correct vsys/VDOM and enter existing object names, one per line. The generator includes rollback commands and does not execute anything. PAN-OS commit is left to the reviewer. ASA, Huawei, Panorama pre/post rules, and FortiGate NAT require a manually reviewed command plan and display an explicit unsupported-context message. Saved workflow statuses are manual records; they do not imply device execution or automatic risk verification.

Template references: [PAN-OS CLI](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy), [FortiGate policy](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/656084/firewall-policy).

## PAN-OS Online Policy Editing

Open **PAN-OS Online** and enter the management host, HTTPS port, account and password/API key. Certificate verification is enabled by default; select the explicit lab self-signed option only for your lab device. Credentials are not written to SQLite or browser storage. An opaque session handle remains in page memory and expires after 30 minutes of inactivity; server restart or Disconnect clears the connection.

Connections default to **Read only / Preview**: the server blocks candidate writes and commits while allowing reads, optimization previews, and existing job status queries. Reconnect explicitly in **Edit candidate / Commit** mode to execute reviewed changes.

Select a virtual system and security/NAT rulebase to read live candidate policies. Security policies have a field editor, while NAT uses the complete rule XML. Existing security profiles and other fields outside the editor are preserved. New rules start disabled. The existing risk engine analyzes the live security rules and links findings to **Edit / Optimize**. Imported Palo Alto risk cards also offer **Edit online** links, which require confirming the correct management host and vsys.

Previews compare risk counts before and after the proposed operation, including resolved and introduced findings. These comparisons use the existing heuristic engine and do not prove traffic impact or resolve all object dependencies. The workspace also accepts an existing commit job ID independently of initiating a commit.

Use **Preview Edit & Risks**, **Preview Delete** or **Preview Move**, review the exact diff, then choose **Confirm Save to Candidate**. Saving does not commit. A changed candidate configuration invalidates the preview; reload and review again. Timed-out writes are not retried automatically. These checks reduce accidental overwrites but do not provide an atomic device-side lock against another administrator writing at the same moment.

**Review Full Commit** displays a device-wide candidate/running diff with sensitive values masked. **Confirm Full Commit** includes all pending device changes, even those outside the selected policy scope or made by other administrators. Check the returned job ID until it finishes; only FIN/OK is reported as success. Download the diff before a change for review and rollback planning. Device-side object and dependency validation remains authoritative; heuristic risk analysis is not a substitute.

Scope: direct firewall connections and local per-vsys security/NAT rulebases. Panorama pre/post policies and automatic remediation are not supported by this editor. Online edits do not automatically replace the offline imported inventory: fetch/import the configuration after a successful commit when you want offline reports to reflect it.

References: [PAN-OS configuration API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api), [commit API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/commit), [asynchronous jobs](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/asynchronous-and-synchronous-requests-to-the-pan-os-xml-api).
