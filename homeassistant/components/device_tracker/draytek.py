"""
homeassistant.components.device_tracker.draytek
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Device tracker platform that supports scanning a Draytek Vigor router for device
presence.

"""
import logging
from datetime import timedelta
from collections import namedtuple
import threading
import requests
import re

from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from homeassistant.util import Throttle
from homeassistant.components.device_tracker import DOMAIN

# Return cached results if last scan was less then this time ago
MIN_TIME_BETWEEN_SCANS = timedelta(seconds=5)

_LOGGER = logging.getLogger(__name__)
_REGEX = r"([\d\.]+?) *?([\dA-F]{2}(?:[-:][\dA-F]{2}){5}) +?([\d:]+) +?([^ ']+).*?'"
REQUIREMENTS = ['requests']
Device = namedtuple("Device", ["mac", "ip", "last_update", "host"])


def get_scanner(hass, config):
    """ Validates config and returns a Draytek scanner.
        :param hass: Unused.
        :param config: configuration object.
        :returns: scanner object
    """
    info = config[DOMAIN]
    host = info.get(CONF_HOST)
    username = info.get(CONF_USERNAME)
    password = info.get(CONF_PASSWORD)

    if password is not None and host is None:
        _LOGGER.warning('Found username or password but no host')
        return None

    scanner = DraytekDeviceScanner(host, username, password)

    return scanner if scanner.success_init else None


class DraytekDeviceScanner(object):
    """ This class queries a Draytek wireless router. """

    def __init__(self, host, username, password):

        self.last_results = []
        self.lock = threading.Lock()
        self.mac2name = {}
        self.cookie_url = 'http://{host}/cgi-bin/wlogin.cgi?aa={username}&ab={password}'.format(
            host=host,
            username=username,
            password=password
        )
        self.query_url = 'http://{host}/doc/ipdhcptb.sht'.format(host=host)

        results = self.scan_devices()

        self.success_init = results is not None

        if self.success_init:
            self.last_results = results
        else:
            _LOGGER.error("Failed to Login")

    def scan_devices(self):
        """ Scans for new devices and return a list containing found device ids.
        """
        self._update_info()
        return (device.mac for device in self.last_results)

    def get_device_name(self, mac):
        """ :param mac: desired device mac id
            :return: return name for device, or None.
        """
        try:
            return next(device.name for device in self.last_results
                        if device.mac == mac)
        except StopIteration:
            return None

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """
        Retrieves latest information from the Draytek router.
        Returns boolean if scanning successful.
        """
        if not self.success_init:
            return

        with self.lock:
            _LOGGER.info("Scanning")

            session = requests.Session()
            session.get(self.cookie_url)  # set initial cookie to enable second request.
            results = session.get(self.query_url).text

            parsed = re.findall(_REGEX, results, re.MULTILINE)
            devices = [Device(mac, ip, lease, host) for ip, mac, lease, host in parsed]
            self.last_results = devices or []
