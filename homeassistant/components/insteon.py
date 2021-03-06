"""
homeassistant.components.light
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Support for Insteon Hub.
"""

import logging
import homeassistant.bootstrap as bootstrap
from homeassistant.helpers import validate_config
from homeassistant.loader import get_component
from homeassistant.helpers.entity import ToggleEntity
from homeassistant.const import (
    CONF_USERNAME, CONF_PASSWORD, ATTR_DISCOVERED,
    ATTR_SERVICE, EVENT_PLATFORM_DISCOVERED)

# The domain of your component. Should be equal to the name of your component
DOMAIN = "insteon"

# List of component names (string) your component depends upon
REQUIREMENTS = [
    'insteon_hub==0.4.5'
]

API_KEY = "3eb14d15-a486-4d9e-99af-179d0e9417c11444718937.80636061"
INSTEON = None

DISCOVER_LIGHTS = "insteon.lights"

_LOGGER = logging.getLogger(__name__)


def setup(hass, config):
    """
    Setup Insteon Hub component.
    This will automatically import associated lights.
    """
    if not validate_config(
            config,
            {DOMAIN: [CONF_USERNAME, CONF_PASSWORD]},
            _LOGGER):
        return False

    import insteon
    username = config[DOMAIN][CONF_USERNAME]
    password = config[DOMAIN][CONF_PASSWORD]
    global INSTEON
    INSTEON = insteon.Insteon(username, password, API_KEY)

    comp_name = 'light'
    discovery = DISCOVER_LIGHTS
    component = get_component(comp_name)
    bootstrap.setup_component(hass, component.DOMAIN, config)
    hass.bus.fire(
        EVENT_PLATFORM_DISCOVERED,
        {ATTR_SERVICE: discovery, ATTR_DISCOVERED: {}})
    return True


class InsteonToggleDevice(ToggleEntity):
    """ Abstract Class for an Insteon node. """

    def __init__(self, node):
        self.node = node
        self._value = 0

    @property
    def name(self):
        """ Returns the name of the node. """
        return self.node.DeviceName

    @property
    def unique_id(self):
        """ Returns the id of this insteon node. """
        return self.node.DeviceID

    def update(self):
        """ Update state of the sensor. """
        resp = self.node.send_command('get_status', wait=True)
        try:
            self._value = resp['response']['level']
        except KeyError:
            pass

    @property
    def is_on(self):
        """ Returns boolean response if the node is on. """
        return self._value != 0

    def turn_on(self, **kwargs):
        self.node.send_command('on')

    def turn_off(self, **kwargs):
        self.node.send_command('off')
