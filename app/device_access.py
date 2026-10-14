from __future__ import annotations

import re
import ssl
import telnetlib
import time
from dataclasses import dataclass
from typing import Protocol
from urllib import parse, request
from urllib.error import HTTPError, URLError
import xml.etree.ElementTree as ET

import paramiko

from app.models import DeviceConnection, Vendor


@dataclass(frozen=True)
class FetchedConfig:
    config_text: str
    session_text: str
    command_log: list[str]


class FetchConfigError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        config_text: str = "",
        session_text: str = "",
        command_log: list[str] | None = None,
    ):
        super().__init__(message)
        self.config_text = config_text
        self.session_text = session_text
        self.command_log = command_log or []

    def payload(self) -> dict[str, object]:
        return {
            "error": str(self),
            "commands": self.command_log,
            "config_size": len(self.config_text),
            "config_preview": self.config_text[:8000],
            "session_preview": self.session_text[-8000:],
        }


class InteractiveChannel(Protocol):
    def send(self, command: str) -> None: ...
    def read_until_idle(self, idle_seconds: float = 0.9, timeout: float = 45.0) -> str: ...
    def read_available(self) -> str: ...
    def close(self) -> None: ...


def test_device_connection(device: DeviceConnection, password: str) -> dict[str, str]:
    if device.protocol == "api_https":
        return _test_api_connection(device, password)
    if device.protocol == "netconf":
        return _test_netconf_connection(device, password)
    channel = _connect(device, password)
    try:
        banner = channel.read_available()
        return {"status": "ok", "detail": f"{device.protocol} connected", "preview": _preview(banner, 1200)}
    finally:
        channel.close()


def fetch_running_config(device: DeviceConnection, password: str, enable_password: str | None = None) -> FetchedConfig:
    if device.protocol == "api_https":
        return _fetch_api_config(device, password)
    if device.protocol == "netconf":
        return _fetch_netconf_config(device, password)
    client = _connect(device, password)
    try:
        time.sleep(0.8)
        session_parts = [client.read_available()]
        commands = _commands_for_vendor(device.vendor, enable_password)
        chunks: list[str] = []
        for command in commands:
            client.send(command + "\n")
            timeout = 120.0 if _is_config_command(command) else 45.0
            idle_seconds = 1.5 if _is_config_command(command) else 0.9
            output = client.read_until_idle(idle_seconds=idle_seconds, timeout=timeout)
            chunks.append(output)
            session_parts.append(output)
        text = "\n".join(chunks)
        session_text = "\n".join(session_parts)
        if enable_password:
            text = text.replace(enable_password, "<enable-password>")
            session_text = session_text.replace(enable_password, "<enable-password>")
        config_text = _extract_config_text(device.vendor, text)
        masked_commands = _masked_commands(commands, enable_password)
        _validate_config_text(device.vendor, config_text, session_text, masked_commands)
        return FetchedConfig(config_text=config_text, session_text=session_text, command_log=masked_commands)
    finally:
        client.close()


def _connect(device: DeviceConnection, password: str) -> InteractiveChannel:
    if device.protocol == "ssh":
        return _connect_ssh(device, password)
    if device.protocol == "telnet":
        return _connect_telnet(device, password)
    raise ValueError(f"Unsupported protocol: {device.protocol}")


def _test_api_connection(device: DeviceConnection, password: str) -> dict[str, str]:
    if device.vendor == Vendor.palo_alto:
        try:
            text = _panos_api_request(device, {"type": "op", "cmd": "<show><system><info></info></system></show>", "key": password})
        except FetchConfigError:
            key_response = _panos_api_request(device, {"type": "keygen", "user": device.username, "password": password})
            api_key = _extract_panos_key(key_response)
            text = _panos_api_request(device, {"type": "op", "cmd": "<show><system><info></info></system></show>", "key": api_key})
        return {"status": "ok", "detail": "Palo Alto XML API connected", "preview": _preview(text, 1200)}
    if device.vendor in {Vendor.fortinet, Vendor.fortigate}:
        text = _fortinet_api_get(device, "/api/v2/monitor/system/status", password)
        return {"status": "ok", "detail": "Fortinet REST API connected", "preview": _preview(text, 1200)}
    raise ValueError(f"API/HTTPS fetch is not implemented for {device.vendor.value}. Use SSH/Telnet for this vendor.")


def _test_netconf_connection(device: DeviceConnection, password: str) -> dict[str, str]:
    with _huawei_netconf_manager(device, password) as manager:
        capabilities = "\n".join(str(item) for item in manager.server_capabilities)
    return {"status": "ok", "detail": "NETCONF connected", "preview": _preview(capabilities, 1200)}


def _fetch_api_config(device: DeviceConnection, password: str) -> FetchedConfig:
    if device.vendor == Vendor.palo_alto:
        return _fetch_palo_alto_api_config(device, password)
    if device.vendor in {Vendor.fortinet, Vendor.fortigate}:
        return _fetch_fortinet_api_config(device, password)
    raise ValueError(f"API/HTTPS fetch is not implemented for {device.vendor.value}. Use SSH/Telnet for this vendor.")


def _fetch_palo_alto_api_config(device: DeviceConnection, password_or_key: str) -> FetchedConfig:
    commands = ["PAN-OS XML API: export configuration"]
    session_parts: list[str] = []
    api_key = password_or_key
    try:
        text = _panos_api_request(device, {"type": "export", "category": "configuration", "key": api_key})
    except FetchConfigError as first_error:
        commands.insert(0, "PAN-OS XML API: keygen")
        key_response = _panos_api_request(device, {"type": "keygen", "user": device.username, "password": password_or_key})
        session_parts.append(key_response.replace(password_or_key, "<password>"))
        api_key = _extract_panos_key(key_response)
        try:
            text = _panos_api_request(device, {"type": "export", "category": "configuration", "key": api_key})
        except FetchConfigError as second_error:
            raise FetchConfigError(
                f"Palo Alto API export failed after API-key and username/password attempts: {second_error}",
                session_text=first_error.session_text + "\n" + second_error.session_text,
                command_log=commands,
            ) from second_error
    session_parts.append(text)
    config_text = _extract_config_text(device.vendor, text)
    _validate_config_text(device.vendor, config_text, "\n".join(session_parts), commands)
    return FetchedConfig(config_text=config_text, session_text="\n".join(session_parts), command_log=commands)


def _fetch_fortinet_api_config(device: DeviceConnection, token: str) -> FetchedConfig:
    commands = ["Fortinet REST API: monitor/system/config/backup"]
    text = _fortinet_api_get(device, "/api/v2/monitor/system/config/backup?scope=global", token)
    config_text = _extract_config_text(device.vendor, text)
    _validate_config_text(device.vendor, config_text, text, commands)
    return FetchedConfig(config_text=config_text, session_text=text, command_log=commands)


def _fetch_netconf_config(device: DeviceConnection, password: str) -> FetchedConfig:
    if device.vendor != Vendor.huawei:
        raise ValueError(f"NETCONF fetch is currently implemented for Huawei. Use SSH/Telnet or API/HTTPS for {device.vendor.value}.")
    commands = ["NETCONF get-config source=running"]
    with _huawei_netconf_manager(device, password) as manager:
        result = manager.get_config(source="running")
        text = result.data_xml
    _validate_config_text(device.vendor, text, text, commands)
    return FetchedConfig(config_text=text, session_text=text, command_log=commands)


def _panos_api_request(device: DeviceConnection, params: dict[str, str]) -> str:
    url = f"https://{device.host}:{device.port}/api/?{parse.urlencode(params)}"
    text = _https_get(url)
    if _panos_response_is_error(text):
        raise FetchConfigError("Palo Alto XML API returned an error.", session_text=text)
    return text


def _fortinet_api_get(device: DeviceConnection, path: str, token: str) -> str:
    url = f"https://{device.host}:{device.port}{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "text/plain, application/json, */*"}
    return _https_get(url, headers=headers)


def _https_get(url: str, headers: dict[str, str] | None = None) -> str:
    ssl_context = ssl._create_unverified_context()
    req = request.Request(url, headers=headers or {})
    try:
        with request.urlopen(req, timeout=45, context=ssl_context) as response:
            return response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise FetchConfigError(f"HTTP {exc.code} from device API.", session_text=body) from exc
    except URLError as exc:
        raise FetchConfigError(f"Could not reach device API: {exc.reason}") from exc


def _panos_response_is_error(text: str) -> bool:
    try:
        root = ET.fromstring(text.strip())
    except ET.ParseError:
        return False
    return root.tag == "response" and root.attrib.get("status") == "error"


def _extract_panos_key(text: str) -> str:
    try:
        root = ET.fromstring(text.strip())
    except ET.ParseError as exc:
        raise FetchConfigError("Palo Alto keygen response was not valid XML.", session_text=text) from exc
    key = root.findtext(".//key")
    if not key:
        raise FetchConfigError("Palo Alto keygen response did not include an API key.", session_text=text)
    return key


def _huawei_netconf_manager(device: DeviceConnection, password: str):
    try:
        from ncclient import manager
    except ImportError as exc:
        raise RuntimeError("NETCONF support requires the ncclient package. Run pip install -r requirements.txt.") from exc
    return manager.connect(
        host=device.host,
        port=device.port,
        username=device.username,
        password=password,
        hostkey_verify=False,
        allow_agent=False,
        look_for_keys=False,
        device_params={"name": "huawei"},
        timeout=30,
    )


class SshChannel:
    def __init__(self, client: paramiko.SSHClient):
        self.client = client
        self.shell = client.invoke_shell(width=240, height=1000)

    def send(self, command: str) -> None:
        self.shell.send(command)

    def read_until_idle(self, idle_seconds: float = 0.9, timeout: float = 45.0) -> str:
        return _read_ssh_until_idle(self.shell, idle_seconds, timeout)

    def read_available(self) -> str:
        chunks: list[str] = []
        while self.shell.recv_ready():
            chunks.append(self.shell.recv(65535).decode("utf-8", errors="replace"))
        return "".join(chunks)

    def close(self) -> None:
        self.client.close()


class TelnetChannel:
    def __init__(self, client: telnetlib.Telnet):
        self.client = client

    def send(self, command: str) -> None:
        self.client.write(command.encode("utf-8", errors="replace"))

    def read_until_idle(self, idle_seconds: float = 0.9, timeout: float = 45.0) -> str:
        return _read_channel_until_idle(
            recv_ready=lambda: True,
            recv=self.client.read_very_eager,
            send=lambda value: self.client.write(value.encode("utf-8", errors="replace")),
            idle_seconds=idle_seconds,
            timeout=timeout,
        )

    def read_available(self) -> str:
        return self.client.read_very_eager().decode("utf-8", errors="replace")

    def close(self) -> None:
        self.client.close()


def _connect_ssh(device: DeviceConnection, password: str) -> SshChannel:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=device.host,
        port=device.port,
        username=device.username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=12,
        auth_timeout=12,
        banner_timeout=18,
    )
    return SshChannel(client)


def _connect_telnet(device: DeviceConnection, password: str) -> TelnetChannel:
    client = telnetlib.Telnet(device.host, device.port, timeout=12)
    banner = _telnet_read_until_login_prompt(client)
    if _looks_like_username_prompt(banner):
        client.write((device.username + "\n").encode("utf-8"))
        _telnet_read_until_login_prompt(client)
    elif _looks_like_password_prompt(banner):
        pass
    else:
        client.write((device.username + "\n").encode("utf-8"))
        _telnet_read_until_login_prompt(client)
    client.write((password + "\n").encode("utf-8"))
    time.sleep(1.0)
    channel = TelnetChannel(client)
    channel.read_available()
    return channel


def _looks_like_username_prompt(data: bytes) -> bool:
    text = data.decode("utf-8", errors="ignore").lower()
    return "login" in text or "username" in text or "user name" in text


def _looks_like_password_prompt(data: bytes) -> bool:
    return "password" in data.decode("utf-8", errors="ignore").lower()


def _telnet_read_until_login_prompt(client: telnetlib.Telnet, timeout: float = 10.0) -> bytes:
    deadline = time.time() + timeout
    data = b""
    while time.time() < deadline:
        data += client.read_very_eager()
        lowered = data.lower()
        if b"login" in lowered or b"username" in lowered or b"user name" in lowered or b"password" in lowered:
            return data
        if re.search(rb"[\r\n][^\r\n]{1,80}[>#]\s*$", data):
            return data
        time.sleep(0.15)
    return data


def _commands_for_vendor(vendor: Vendor, enable_password: str | None) -> list[str]:
    if vendor == Vendor.cisco_asa:
        commands = []
        if enable_password:
            commands.extend(["enable", enable_password])
        commands.extend(["terminal pager 0", "show running-config"])
        return commands
    if vendor == Vendor.palo_alto:
        return ["set cli pager off", "set cli config-output-format set", "configure", "show"]
    if vendor in {Vendor.fortinet, Vendor.fortigate}:
        return ["config system console", "set output standard", "end", "show full-configuration"]
    if vendor == Vendor.huawei:
        return ["screen-length 0 temporary", "display current-configuration"]
    raise ValueError(f"Unsupported vendor: {vendor}")


def _is_config_command(command: str) -> bool:
    lowered = command.lower()
    return "show running-config" in lowered or "show full-configuration" in lowered or "display current-configuration" in lowered


def _masked_commands(commands: list[str], enable_password: str | None) -> list[str]:
    if not enable_password:
        return commands
    return ["<enable-password>" if command == enable_password else command for command in commands]


def _read_ssh_until_idle(shell: paramiko.Channel, idle_seconds: float = 0.9, timeout: float = 45.0) -> str:
    return _read_channel_until_idle(
        recv_ready=shell.recv_ready,
        recv=lambda: shell.recv(65535),
        send=lambda value: shell.send(value),
        idle_seconds=idle_seconds,
        timeout=timeout,
    )


def _read_channel_until_idle(recv_ready, recv, send, idle_seconds: float = 0.9, timeout: float = 45.0) -> str:
    deadline = time.time() + timeout
    last_data = time.time()
    chunks: list[str] = []
    while time.time() < deadline:
        if recv_ready():
            raw = recv()
            if not raw:
                if time.time() - last_data >= idle_seconds:
                    break
                time.sleep(0.1)
                continue
            data = raw.decode("utf-8", errors="replace")
            if _needs_more(data):
                send(" ")
            chunks.append(data)
            last_data = time.time()
            if _looks_like_device_prompt("".join(chunks)) and time.time() - last_data >= 0.2:
                break
        elif time.time() - last_data >= idle_seconds:
            break
        else:
            time.sleep(0.1)
    return "".join(chunks)


def _needs_more(data: str) -> bool:
    lowered = data.lower()
    return "--more--" in lowered or "more:" in lowered or "press any key" in lowered or "---- more ----" in lowered


def _looks_like_device_prompt(text: str) -> bool:
    tail = "\n".join(text.rstrip().splitlines()[-3:])
    return bool(re.search(r"(^|\n)[A-Za-z0-9_.@()/:-]{1,80}[>#]\s*$", tail))

def _extract_config_text(vendor: Vendor, raw: str) -> str:
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    text = _strip_command_echo(text)
    if vendor == Vendor.palo_alto:
        marker = "set "
        idx = text.find(marker)
        return text[idx:] if idx >= 0 else text
    if vendor == Vendor.cisco_asa:
        idx = text.find("ASA Version")
        if idx < 0:
            idx = text.find(": Saved")
        return text[idx:] if idx >= 0 else text
    if vendor in {Vendor.fortinet, Vendor.fortigate}:
        idx = text.find("config ")
        return text[idx:] if idx >= 0 else text
    if vendor == Vendor.huawei:
        idx = text.find("#")
        return text[idx:] if idx >= 0 else text
    return text


def _validate_config_text(vendor: Vendor, config_text: str, session_text: str, command_log: list[str] | None = None) -> None:
    if len(config_text.strip()) < 80:
        raise FetchConfigError(
            "Fetched output is too short to be a configuration.",
            config_text=config_text,
            session_text=session_text,
            command_log=command_log,
        )
    markers = {
        Vendor.cisco_asa: ["ASA Version", "access-list", "object network", "nat ("],
        Vendor.palo_alto: ["set ", "rulebase", "config {", "<config"],
        Vendor.fortinet: ["config ", "edit ", "set "],
        Vendor.fortigate: ["config ", "edit ", "set "],
        Vendor.huawei: ["#", "security-policy", "acl", "nat-policy", "<data", "<configuration"],
    }
    if not any(marker in config_text for marker in markers.get(vendor, [])):
        raise FetchConfigError(
            f"Fetched output does not look like a {vendor.value} configuration.",
            config_text=config_text,
            session_text=session_text,
            command_log=command_log,
        )


def _preview(value: str | bytes, limit: int = 2400) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    text = text.replace("\r", "")
    return text[-limit:]


def _strip_command_echo(text: str) -> str:
    ignored = {
        "enable",
        "terminal pager 0",
        "show running-config",
        "set cli pager off",
        "set cli config-output-format set",
        "configure",
        "show",
        "config system console",
        "set output standard",
        "end",
        "show full-configuration",
        "screen-length 0 temporary",
        "display current-configuration",
    }
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped in ignored:
            continue
        if re.match(r"^[<\\[].+[>\\]]\\s*$", stripped):
            continue
        lines.append(line)
    return "\n".join(lines).strip()
