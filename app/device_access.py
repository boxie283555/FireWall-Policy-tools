from __future__ import annotations

import re
import time
from dataclasses import dataclass

import paramiko

from app.models import DeviceConnection, Vendor


@dataclass(frozen=True)
class FetchedConfig:
    config_text: str
    command_log: list[str]


def test_ssh_connection(device: DeviceConnection, password: str) -> dict[str, str]:
    client = _connect(device, password)
    try:
        transport = client.get_transport()
        remote = transport.remote_version if transport else "ssh connected"
        return {"status": "ok", "detail": remote}
    finally:
        client.close()


def fetch_running_config(device: DeviceConnection, password: str, enable_password: str | None = None) -> FetchedConfig:
    client = _connect(device, password)
    try:
        shell = client.invoke_shell(width=240, height=1000)
        time.sleep(0.8)
        _read_available(shell)
        commands = _commands_for_vendor(device.vendor, enable_password)
        chunks: list[str] = []
        for command in commands:
            chunks.append(_send_command(shell, command))
        text = "\n".join(chunks)
        if enable_password:
            text = text.replace(enable_password, "<enable-password>")
        return FetchedConfig(config_text=_extract_config_text(device.vendor, text), command_log=_masked_commands(commands, enable_password))
    finally:
        client.close()


def _connect(device: DeviceConnection, password: str) -> paramiko.SSHClient:
    if device.protocol != "ssh":
        raise ValueError("当前版本仅支持 SSH 拉取配置。")
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
    return client


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


def _masked_commands(commands: list[str], enable_password: str | None) -> list[str]:
    if not enable_password:
        return commands
    return ["<enable-password>" if command == enable_password else command for command in commands]


def _send_command(shell: paramiko.Channel, command: str) -> str:
    shell.send(command + "\n")
    return _read_until_idle(shell)


def _read_until_idle(shell: paramiko.Channel, idle_seconds: float = 0.9, timeout: float = 45.0) -> str:
    deadline = time.time() + timeout
    last_data = time.time()
    chunks: list[str] = []
    while time.time() < deadline:
        if shell.recv_ready():
            data = shell.recv(65535).decode("utf-8", errors="replace")
            chunks.append(data)
            last_data = time.time()
        elif time.time() - last_data >= idle_seconds:
            break
        else:
            time.sleep(0.1)
    return "".join(chunks)


def _read_available(shell: paramiko.Channel) -> str:
    chunks: list[str] = []
    while shell.recv_ready():
        chunks.append(shell.recv(65535).decode("utf-8", errors="replace"))
    return "".join(chunks)


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
