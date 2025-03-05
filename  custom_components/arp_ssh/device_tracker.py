"""arp parsing."""

from __future__ import annotations

from datetime import timedelta
import logging
import re
from typing import Any

import pexpect
import voluptuous as vol

from homeassistant.components.device_tracker import (
    DOMAIN as DEVICE_TRACKER_DOMAIN,
    PLATFORM_SCHEMA as DEVICE_TRACKER_PLATFORM_SCHEMA,
    DeviceScanner,
)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType
from homeassistant.util import Throttle

_LOGGER = logging.getLogger(__name__)

MIN_TIME_BETWEEN_SCANS = timedelta(seconds=60)

PLATFORM_SCHEMA = DEVICE_TRACKER_PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_USERNAME, default="root"): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
    }
)


def get_scanner(hass: HomeAssistant, config: ConfigType) -> ArpDeviceScanner:
    return ArpDeviceScanner(config[DEVICE_TRACKER_DOMAIN])


class ArpDeviceScanner(DeviceScanner):
    def __init__(self, config) -> None:
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.ssh_key = config[CONF_PASSWORD]

        self.parse_api_pattern = re.compile(
            r"(((.*)\..*)|\?) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\) at (([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})) \[(.*)\]  on br-lan"
        )

        self.clients: dict[str, dict[str, Any]] = {}

        self.success_init = self._update_info_ssh()

    def scan_devices(self) -> list[str]:
        """Scan for new devices and return a list with found device IDs."""
        self._update_info_ssh()
        home_devices = [
            device
            for device, info in self.clients.items()
            if info.get("location_name") == "home"
        ]
        _LOGGER.debug(home_devices)
        return home_devices

    def get_device_name(self, device: str) -> str | None:
        """Return the name of the given device or None if we don't know."""
        client_info = self.clients.get(device)
        if client_info:
            return client_info.get("hostname")
        return None

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info_ssh(self):
        connect = f"ssh -i {self.ssh_key} {self.username}@{self.host} -o StrictHostKeyChecking=no"
        ssh: pexpect.spawn[str] = pexpect.spawn(connect, encoding="utf-8")

        query = ssh.expect(
            [
                "#",
                "nothing",
                pexpect.TIMEOUT,
                pexpect.EOF,
                "continue connecting",
                "Host key verification failed.",
                "Connection refused",
                "Connection timed out",
                "Host key changed",
                "Permission denied",
            ],
            timeout=120,
        )

        if query == 1:
            _LOGGER.error("Timeout")
            return None
        if query == 2:
            _LOGGER.error("Unexpected response from router")
            return None
        if query == 3:
            ssh.sendline("yes")
            # ssh.expect("#")
        elif query == 4:
            _LOGGER.error("Host key changed")
            return None
        elif query == 5:
            _LOGGER.error("Connection refused by server")
            return None
        elif query == 6:
            _LOGGER.error("Connection timed out")
            return None
        elif query == 7:
            _LOGGER.error("Permission denied")
            return None

        ssh.sendline("arp")

        ssh.expect("#")
        devices_result = (ssh.before or "").splitlines()
        ssh.sendline("exit")

        _LOGGER.debug(devices_result)

        new_clients: dict[str, dict[str, Any]] = {}
        for line in devices_result:
            for match in self.parse_api_pattern.findall(line):
                mac_address = match[4]
                new_clients[mac_address] = {
                    "hostname": match[2] if match[2] else mac_address,
                    "location_name": "home",
                }
        self.clients = new_clients
        return True
