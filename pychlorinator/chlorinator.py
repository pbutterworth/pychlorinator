"""API for Astra Pool Viron eQuilibrium pool chlorinator."""

import logging
from typing import Any

from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from Crypto.Cipher import AES

from .chlorinator_parsers import (
    ChlorinatorAction,
    ChlorinatorActions,
    ChlorinatorCapabilities,
    ChlorinatorSettings,
    ChlorinatorSetup,
    ChlorinatorState,
    ChlorinatorStatistics,
    ChlorinatorTimers,
)

UUID_ASTRALPOOL_SERVICE = "45000001-98b7-4e29-a03f-160174643001"
UUID_SLAVE_SESSION_KEY = "45000002-98b7-4e29-a03f-160174643001"
UUID_MASTER_AUTHENTICATION = "45000003-98b7-4e29-a03f-160174643001"
UUID_DEVICE_TIME = "45000006-98b7-4e29-a03f-160174643001"
UUID_DEVICE_PROFILE = "45000007-98b7-4e29-a03f-160174643001"
UUID_DEVICE_NAME = "45000008-98b7-4e29-a03f-160174643001"
UUID_DEVICE_DEBUG = "45000009-98b7-4e29-a03f-160174643001"

UUID_CHLORINATOR_STATE = "45000200-98b7-4e29-a03f-160174643001"
UUID_CHLORINATOR_CAPABILITIES = "45000201-98b7-4e29-a03f-160174643001"
UUID_CHLORINATOR_SETUP = "45000202-98b7-4e29-a03f-160174643001"
UUID_CHLORINATOR_APP_ACTION = "45000203-98b7-4e29-a03f-160174643001"
UUID_CHLORINATOR_TIMERS = "45000204-98b7-4e29-a03f-160174643001"
UUID_CHLORINATOR_STATISTICS = "45000205-98b7-4e29-a03f-160174643001"
UUID_CHLORINATOR_SETTINGS = "45000206-98b7-4e29-a03f-160174643001"
UUID_LIGHTING_STATE = "45000300-98b7-4e29-a03f-160174643001"
UUID_LIGHTING_CAPABILITIES = "45000301-98b7-4e29-a03f-160174643001"
UUID_LIGHTING_SETUP = "45000302-98b7-4e29-a03f-160174643001"
UUID_LIGHTING_APP_ACTION = "45000303-98b7-4e29-a03f-160174643001"
UUID_LIGHTING_TIMERS = "45000304-98b7-4e29-a03f-160174643001"

SECRET_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

_LOGGER = logging.getLogger(__name__)


def xor_bytes(array1, array2):
    """XOR two byte arrays, left aligned, zero padded."""
    shrt, lng = sorted((array1, array2), key=len)
    shrt = shrt.ljust(len(lng), b"\0")
    return bytes(array1 ^ array2 for (array1, array2) in zip(shrt, lng))


def encrypt_mac_key(session_key: bytes, access_code: bytes) -> bytes:
    """Encrypt the mac key."""
    xored = xor_bytes(session_key, access_code)
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return cipher.encrypt(xored)


def encrypt_characteristic(data: bytes, session_key: bytes) -> bytes:
    """Encrypt a characteristc packet."""
    xored = xor_bytes(data, session_key)
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    array = cipher.encrypt(xored[:16]) + xored[16:]
    return array[:4] + cipher.encrypt(array[4:])


def decrypt_characteristic(data: bytes, session_key: bytes) -> bytes:
    """Decrypt a GATT characteristic."""
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    array = data[:4] + cipher.decrypt(data[4:])
    array = cipher.decrypt(array[:16]) + array[16:]
    return xor_bytes(array, session_key)


class ChlorinatorAPI:
    """Represents the chlorinator device."""

    def __init__(
        self,
        ble_device: BLEDevice,
        access_code: str,
    ) -> None:
        """Initialise the chlorinator API."""
        self._ble_device = ble_device
        self._access_code = access_code
        self._session_key = None
        self._result: dict[str, Any] | None = None

    async def async_write_action(self, action: ChlorinatorActions):
        """Connect to the Chlorinator and write an action command to it."""

        client = await establish_connection(
            BleakClientWithServiceCache,  # Use BleakClientWithServiceCache for service caching
            self._ble_device,
            self._ble_device.name or "Unknown Device",
            max_attempts=4,
        )

        try:
            self._session_key = await client.read_gatt_char(UUID_SLAVE_SESSION_KEY)
            _LOGGER.debug("Got session key: %s", self._session_key.hex())

            mac = encrypt_mac_key(self._session_key, bytes(self._access_code, "utf_8"))
            _LOGGER.debug("Mac key to write: %s", mac)
            await client.write_gatt_char(UUID_MASTER_AUTHENTICATION, mac)

            # I think we need to read all the following characteristics so that we are 'authenticated'
            # Otherwise we seem to get kicked out
            await client.read_gatt_char(UUID_CHLORINATOR_STATE)
            await client.read_gatt_char(UUID_CHLORINATOR_SETUP)
            await client.read_gatt_char(UUID_CHLORINATOR_TIMERS)
            await client.read_gatt_char(UUID_CHLORINATOR_SETTINGS)
            await client.read_gatt_char(UUID_LIGHTING_STATE)
            await client.read_gatt_char(UUID_LIGHTING_SETUP)
            await client.read_gatt_char(UUID_LIGHTING_TIMERS)

            data = ChlorinatorAction(action).__bytes__()
            _LOGGER.debug("Data to write: %s", data.hex())
            data = encrypt_characteristic(data, self._session_key)
            _LOGGER.debug("Encrypted data to write: %s", data.hex())
            await client.write_gatt_char(UUID_CHLORINATOR_APP_ACTION, data)
        finally:
            await client.disconnect()

    async def async_gatherdata(self) -> dict[str, Any]:
        """Connect to the Chlorinator to get data."""
        if self._ble_device is None:
            self._result = {}
            return self._result

        self._result = {}

        parsers = {
            UUID_CHLORINATOR_STATE: ChlorinatorState,
            UUID_CHLORINATOR_SETUP: ChlorinatorSetup,
            UUID_CHLORINATOR_CAPABILITIES: ChlorinatorCapabilities,
            UUID_CHLORINATOR_TIMERS: ChlorinatorTimers,
            UUID_CHLORINATOR_STATISTICS: ChlorinatorStatistics,
            UUID_CHLORINATOR_SETTINGS: ChlorinatorSettings,
        }

        client = await establish_connection(
            BleakClientWithServiceCache,  # Use BleakClientWithServiceCache for service caching
            self._ble_device,
            self._ble_device.name or "Unknown Device",
            max_attempts=4,
        )

        try:
            self._session_key = await client.read_gatt_char(UUID_SLAVE_SESSION_KEY)
            _LOGGER.debug("Got session key: %s", self._session_key.hex())

            mac = encrypt_mac_key(self._session_key, bytes(self._access_code, "utf_8"))
            _LOGGER.debug("Mac key to write: %s", mac.hex())
            await client.write_gatt_char(UUID_MASTER_AUTHENTICATION, mac)

            for uuid, parser in parsers.items():
                databytes = decrypt_characteristic(
                    await client.read_gatt_char(uuid), self._session_key
                )
                self._result.update(vars(parser(databytes)))

            _LOGGER.debug(self._result)
        finally:
            await client.disconnect()

        return self._result
