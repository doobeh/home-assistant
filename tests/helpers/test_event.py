"""
tests.helpers.event_test
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests event helpers.
"""
# pylint: disable=protected-access,too-many-public-methods
# pylint: disable=too-few-public-methods
import unittest
from datetime import datetime

from astral import Astral

import homeassistant.core as ha
from homeassistant.helpers.event import *
from homeassistant.components import sun


class TestEventHelpers(unittest.TestCase):
    """
    Tests the Home Assistant event helpers.
    """

    def setUp(self):     # pylint: disable=invalid-name
        """ things to be run when tests are started. """
        self.hass = ha.HomeAssistant()
        self.hass.states.set("light.Bowl", "on")
        self.hass.states.set("switch.AC", "off")

    def tearDown(self):  # pylint: disable=invalid-name
        """ Stop down stuff we started. """
        self.hass.stop()

    def test_track_point_in_time(self):
        """ Test track point in time. """
        before_birthday = datetime(1985, 7, 9, 12, 0, 0, tzinfo=dt_util.UTC)
        birthday_paulus = datetime(1986, 7, 9, 12, 0, 0, tzinfo=dt_util.UTC)
        after_birthday = datetime(1987, 7, 9, 12, 0, 0, tzinfo=dt_util.UTC)

        runs = []

        track_point_in_utc_time(
            self.hass, lambda x: runs.append(1), birthday_paulus)

        self._send_time_changed(before_birthday)
        self.hass.pool.block_till_done()
        self.assertEqual(0, len(runs))

        self._send_time_changed(birthday_paulus)
        self.hass.pool.block_till_done()
        self.assertEqual(1, len(runs))

        # A point in time tracker will only fire once, this should do nothing
        self._send_time_changed(birthday_paulus)
        self.hass.pool.block_till_done()
        self.assertEqual(1, len(runs))

        track_point_in_time(
            self.hass, lambda x: runs.append(1), birthday_paulus)

        self._send_time_changed(after_birthday)
        self.hass.pool.block_till_done()
        self.assertEqual(2, len(runs))

    def test_track_time_change(self):
        """ Test tracking time change. """
        wildcard_runs = []
        specific_runs = []

        track_time_change(self.hass, lambda x: wildcard_runs.append(1))
        track_utc_time_change(
            self.hass, lambda x: specific_runs.append(1), second=[0, 30])

        self._send_time_changed(datetime(2014, 5, 24, 12, 0, 0))
        self.hass.pool.block_till_done()
        self.assertEqual(1, len(specific_runs))
        self.assertEqual(1, len(wildcard_runs))

        self._send_time_changed(datetime(2014, 5, 24, 12, 0, 15))
        self.hass.pool.block_till_done()
        self.assertEqual(1, len(specific_runs))
        self.assertEqual(2, len(wildcard_runs))

        self._send_time_changed(datetime(2014, 5, 24, 12, 0, 30))
        self.hass.pool.block_till_done()
        self.assertEqual(2, len(specific_runs))
        self.assertEqual(3, len(wildcard_runs))

    def test_track_state_change(self):
        """ Test track_state_change. """
        # 2 lists to track how often our callbacks get called
        specific_runs = []
        wildcard_runs = []

        track_state_change(
            self.hass, 'light.Bowl', lambda a, b, c: specific_runs.append(1),
            'on', 'off')

        track_state_change(
            self.hass, 'light.Bowl', lambda a, b, c: wildcard_runs.append(1),
            ha.MATCH_ALL, ha.MATCH_ALL)

        # Set same state should not trigger a state change/listener
        self.hass.states.set('light.Bowl', 'on')
        self.hass.pool.block_till_done()
        self.assertEqual(0, len(specific_runs))
        self.assertEqual(0, len(wildcard_runs))

        # State change off -> on
        self.hass.states.set('light.Bowl', 'off')
        self.hass.pool.block_till_done()
        self.assertEqual(1, len(specific_runs))
        self.assertEqual(1, len(wildcard_runs))

        # State change off -> off
        self.hass.states.set('light.Bowl', 'off', {"some_attr": 1})
        self.hass.pool.block_till_done()
        self.assertEqual(1, len(specific_runs))
        self.assertEqual(2, len(wildcard_runs))

        # State change off -> on
        self.hass.states.set('light.Bowl', 'on')
        self.hass.pool.block_till_done()
        self.assertEqual(1, len(specific_runs))
        self.assertEqual(3, len(wildcard_runs))

    def test_track_sunrise(self):
        """ Test track sunrise """
        latitude = 32.87336
        longitude = 117.22743

        # setup sun component
        self.hass.config.latitude = latitude
        self.hass.config.longitude = longitude
        sun.setup(self.hass, {sun.DOMAIN: {sun.CONF_ELEVATION: 0}})

        # get next sunrise/sunset
        astral = Astral()
        utc_now = dt_util.utcnow()

        mod = -1
        while True:
            next_rising = (astral.sunrise_utc(utc_now +
                           timedelta(days=mod), latitude, longitude))
            if next_rising > utc_now:
                break
            mod += 1

        # track sunrise
        runs = []
        track_sunrise(self.hass, lambda: runs.append(1))

        offset_runs = []
        offset = timedelta(minutes=30)
        track_sunrise(self.hass, lambda: offset_runs.append(1), offset)

        # run tests
        self._send_time_changed(next_rising - offset)
        self.hass.pool.block_till_done()
        self.assertEqual(0, len(runs))
        self.assertEqual(0, len(offset_runs))

        self._send_time_changed(next_rising)
        self.hass.pool.block_till_done()
        self.assertEqual(1, len(runs))
        self.assertEqual(0, len(offset_runs))

        self._send_time_changed(next_rising + offset)
        self.hass.pool.block_till_done()
        self.assertEqual(2, len(runs))
        self.assertEqual(1, len(offset_runs))

    def test_track_sunset(self):
        """ Test track sunset """
        latitude = 32.87336
        longitude = 117.22743

        # setup sun component
        self.hass.config.latitude = latitude
        self.hass.config.longitude = longitude
        sun.setup(self.hass, {sun.DOMAIN: {sun.CONF_ELEVATION: 0}})

        # get next sunrise/sunset
        astral = Astral()
        utc_now = dt_util.utcnow()

        mod = -1
        while True:
            next_setting = (astral.sunset_utc(utc_now +
                            timedelta(days=mod), latitude, longitude))
            if next_setting > utc_now:
                break
            mod += 1

        # track sunset
        runs = []
        track_sunset(self.hass, lambda: runs.append(1))

        offset_runs = []
        offset = timedelta(minutes=30)
        track_sunset(self.hass, lambda: offset_runs.append(1), offset)

        # run tests
        self._send_time_changed(next_setting - offset)
        self.hass.pool.block_till_done()
        self.assertEqual(0, len(runs))
        self.assertEqual(0, len(offset_runs))

        self._send_time_changed(next_setting)
        self.hass.pool.block_till_done()
        self.assertEqual(1, len(runs))
        self.assertEqual(0, len(offset_runs))

        self._send_time_changed(next_setting + offset)
        self.hass.pool.block_till_done()
        self.assertEqual(2, len(runs))
        self.assertEqual(1, len(offset_runs))

    def _send_time_changed(self, now):
        """ Send a time changed event. """
        self.hass.bus.fire(ha.EVENT_TIME_CHANGED, {ha.ATTR_NOW: now})
