"""arp parsing."""

from __future__ import annotations

from datetime import timedelta
from http import HTTPStatus
import logging
import re
from typing import Any

import pexpect
import requests
import voluptuous as vol

import pathlib

from homeassistant.components.device_tracker import (
    DOMAIN as DEVICE_TRACKER_DOMAIN,
    PLATFORM_SCHEMA as DEVICE_TRACKER_PLATFORM_SCHEMA,
    DeviceScanner,
)
from homeassistant.const import (
    CONF_HOST,
    # CONF_SSH_KEY,
    # CONF_PATH,
    # CONF_PORT,
    # CONF_SSL,
    CONF_USERNAME,
    # CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType
from homeassistant.util import Throttle

_LOGGER = logging.getLogger(__name__)

MIN_TIME_BETWEEN_SCANS = timedelta(seconds=60)

PLATFORM_SCHEMA = DEVICE_TRACKER_PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOST): cv.string,
        # vol.Required(CONF_SSH_KEY): cv.string,
        # vol.Required(CONF_PATH): cv.string,
        # vol.Optional(CONF_PORT): cv.port,
        # vol.Optional(CONF_SSL, default=True): cv.boolean,
        # vol.Optional(CONF_VERIFY_SSL, default=False): vol.Any(cv.boolean, cv.isfile),
        # vol.Optional(CONF_PASSWORD, default=""): cv.string,
        vol.Required(CONF_USERNAME, default="root"): cv.string,
    }
)


def get_scanner(hass: HomeAssistant, config: ConfigType) -> ArpDeviceScanner:
    return ArpDeviceScanner(config[DEVICE_TRACKER_DOMAIN])


class ArpDeviceScanner(DeviceScanner):
    def __init__(self, config) -> None:
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        # path = config[CONF_PATH]
        # port = config.get(CONF_PORT)
        # username, password = config[CONF_USERNAME], config[CONF_PASSWORD]
        # self.ssl, self.verify_ssl = config[CONF_SSL], config[CONF_VERIFY_SSL]
        # if port is None:
        #     port = 443 if self.ssl else 80

        # protocol = "https" if self.ssl else "http"
        # self.req = requests.Request(
        #     "POST",
        #     f"{protocol}://{host}:{port}/{path}",
        #     auth=requests.auth.HTTPBasicAuth(username, password),
        # ).prepare()

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
        _LOGGER.error(home_devices)
        return home_devices

    def get_device_name(self, device: str) -> str | None:
        """Return the name of the given device or None if we don't know."""
        client_info = self.clients.get(device)
        if client_info:
            _LOGGER.error(client_info)
            return client_info.get("hostname")
        return None

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info_ssh(self):
        _LOGGER.error(pathlib.Path(__file__).parent.resolve())
        connect = f"ssh {self.username}@{self.host}"
        ssh: pexpect.spawn[str] = pexpect.spawn(connect, encoding="utf-8")
        ssh.expect(
            "#",
            timeout=120,
        )
        ssh.sendline("arp")
        ssh.expect("#")
        devices_result = (ssh.before or "").splitlines()
        ssh.sendline("exit")

        _LOGGER.error(devices_result)

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

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info_https(self):
        _LOGGER.error("Scanning")

        try:
            if self.ssl:
                response = requests.Session().send(
                    self.req, timeout=60, verify=self.verify_ssl
                )
            else:
                response = requests.Session().send(self.req, timeout=60)

            if response.status_code == HTTPStatus.OK:
                new_clients: dict[str, dict[str, Any]] = {}
                for match in self.parse_api_pattern.findall(response.text):
                    mac_address = match[4]
                    new_clients[mac_address] = {
                        "hostname": match[2] if match[2] else mac_address,
                        "location_name": "home",
                    }
                self.clients = new_clients
                return True

            if response.status_code == HTTPStatus.UNAUTHORIZED:
                # Authentication error
                _LOGGER.exception(
                    "Failed to authenticate, please check your username and password"
                )
                return False

        except requests.exceptions.ConnectionError:
            # We get this if we could not connect to the router or
            # an invalid http_id was supplied.
            _LOGGER.exception(
                "Failed to connect to the router or invalid http_id supplied"
            )
            return False

        except requests.exceptions.Timeout:
            # We get this if we could not connect to the router or
            # an invalid http_id was supplied.
            _LOGGER.exception("Connection to the router timed out")
            return False

        except ValueError:
            # If JSON decoder could not parse the response.
            _LOGGER.exception("Failed to parse response from router")
            return False
