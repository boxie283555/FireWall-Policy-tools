from __future__ import annotations

import re
import telnetlib
import time
from dataclasses import dataclass
from typing import Protocol

import paramiko

from app.models import DeviceConnection, Vendor


@dataclass(frozen=True)
class FetchedConfig:
    config_text: str
    command_log: list[str]


class InteractiveChannel(Protocol):
    def send(self, command: str) -> None: ...
    def read_until_idle(self, idle_seconds: float = 0.9, timeout: float = 45.0) -> str: ...
    def read_available(self) -> str: ...
    def close(self) -> None: ...


def test_device_connection(device: DeviceConnection, password: str) -> dict[str, str]:
    channel = _connect(device, password)
    try:
        return {"status": "ok", "detail": f"{device.protocol} connected"}
    finally:
        channel.close()


def fetch_running_config(device: DeviceConnection, password: str, enable_password: str | None = None) -> FetchedConfig:
    client = _connect(device, password)
    try:
        time.sleep(0.8)
        client.read_available()
        commands = _commands_for_vendor(device.vendor, enable_password)
        chunks: list[str] = []
        for command in commands:
            client.send(command + "\n")
            chunks.append(client.read_until_idle())
        text = "\n".join(chunks)
        if enable_password:
            text = text.replace(enable_password, "<enable-password>")
        return FetchedConfig(config_text=_extract_config_text(device.vendor, text), command_log=_masked_commands(commands, enable_password))
    finally:
        client.close()


def _connect(device: DeviceConnection, password: str) -> InteractiveChannel:
    if device.protocol == "ssh":
        return _connect_ssh(device, password)
    if device.protocol == "telnet":
        return _connect_telnet(device, password)
    raise ValueError(f"Unsupported protocol: {device.protocol}")


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
        deadline = time.time() + timeout
        last_data = time.time()
        chunks: list[str] = []
        while time.time() < deadline:
            data = self.client.read_very_eager()
            if data:
                chunks.append(data.decode("utf-8", errors="replace"))
                last_data = time.time()
            elif time.time() - last_data >= idle_seconds:
                break
            else:
                time.sleep(0.1)
        return "".join(chunks)

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
    banner = client.read_until(b":", timeout=8)
    if _looks_like_username_prompt(banner):
        client.write((device.username + "\n").encode("utf-8"))
        client.read_until(b":", timeout=8)
    elif _looks_like_password_prompt(banner):
        pass
    else:
        client.write((device.username + "\n").encode("utf-8"))
        client.read_until(b":", timeout=8)
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


def _read_ssh_until_idle(shell: paramiko.Channel, idle_seconds: float = 0.9, timeout: float = 45.0) -> str:
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
