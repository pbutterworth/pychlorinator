"""API for Astra Pool Halo pool chlorinator."""

import asyncio
import binascii
import logging
from typing import Any

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from Crypto.Cipher import AES

from .halo_parsers import (
    CapabilitiesCharacteristic2,
    CellCharacteristic2,
    ChlorinatorAction,
    ChlorinatorActions,
    DeviceProfileCharacteristic2,
    EquipmentModeCharacteristic,
    EquipmentParameterCharacteristic,
    GPOSetupCharacteristic,
    HeaterAction,
    HeaterAppActions,
    HeaterCapabilitiesCharacteristic,
    HeaterConfigCharacteristic,
    HeaterCooldownStateCharacteristic,
    HeaterStateCharacteristic,
    LightCapabilitiesCharacteristic,
    LightSetupCharacteristic,
    LightStateCharacteristic,
    MaintenanceStateCharacteristic,
    PowerBoardCharacteristic,
    ProbeCharacteristic,
    RelaySetupCharacteristic,
    SetPointCharacteristic,
    SettingsCharacteristic2,
    SolarAction,
    SolarAppActions,
    SolarCapabilitiesCharacteristic,
    SolarConfigCharacteristic,
    SolarStateCharacteristic,
    StateCharacteristic3,
    TempCharacteristic,
    ValveSetupCharacteristic,
    WaterVolumeCharacteristic,
)

UUID_ASTRALPOOL_SERVICE_2 = "45000001-98b7-4e29-a03f-160174643002"
UUID_SLAVE_SESSION_KEY_2 = "45000001-98b7-4e29-a03f-160174643002"
UUID_MASTER_AUTHENTICATION_2 = "45000002-98b7-4e29-a03f-160174643002"
UUID_TX_CHARACTERISTIC = "45000003-98b7-4e29-a03f-160174643002"
UUID_RX_CHARACTERISTIC = "45000004-98b7-4e29-a03f-160174643002"
ASTRALPOOL_HALO_BLE_NAME = "HCHLOR"

SECRET_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

_LOGGER = logging.getLogger(__name__)


def pad_byte_array(byte_array, target_length):
    """Pad bytes to length."""
    padding_needed = max(0, target_length - len(byte_array))
    return byte_array + bytes(padding_needed)


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
    array = array[:4] + cipher.encrypt(array[4:])
    return array


def decrypt_characteristic(data: bytes, session_key: bytes) -> bytes:
    """Decrypt a GATT characteristic."""
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    array = data[:4] + cipher.decrypt(data[4:])
    array = cipher.decrypt(array[:16]) + array[16:]
    xored = xor_bytes(array, session_key)
    return xored


class HaloChlorinatorAPI:
    """represents the chlorinator device."""

    def __init__(
        self,
        ble_device: BLEDevice,
        access_code: str,
    ) -> None:
        self._ble_device = ble_device
        self._access_code = access_code
        self._session_key = None
        self._result: dict[str, Any] = None
        self._connected = False

    _LOGGER.debug("Hello from HaloChlorinator API")

    async def async_write_action(self, action: ChlorinatorActions):
        """Connect to the Chlorinator and write an action command to it."""
        while self._connected:
            _LOGGER.debug("Already connected, Waiting")
            await asyncio.sleep(5)

        async with BleakClient(self._ble_device, timeout=10) as client:
            self._session_key = await client.read_gatt_char(UUID_SLAVE_SESSION_KEY_2)
            _LOGGER.debug("Got session key %s", self._session_key.hex())

            mac = encrypt_mac_key(self._session_key, bytes(self._access_code, "utf_8"))
            _LOGGER.debug("Mac key to write %s", mac)
            await client.write_gatt_char(UUID_MASTER_AUTHENTICATION_2, mac)

            data = ChlorinatorAction(action).__bytes__()
            _LOGGER.debug("Data to write %s", data.hex())
            data = encrypt_characteristic(data, self._session_key)
            _LOGGER.debug("Encrypted data to write %s", data.hex())
            await client.write_gatt_char(UUID_RX_CHARACTERISTIC, data)

    async def async_write_heater_action(self, action: HeaterAppActions):
        """Connect to the Chlorinator and write an action command to it."""
        while self._connected:
            _LOGGER.debug("Already connected, Waiting")
            await asyncio.sleep(1)

        async with BleakClient(self._ble_device, timeout=10) as client:
            self._session_key = await client.read_gatt_char(UUID_SLAVE_SESSION_KEY_2)
            _LOGGER.debug("Got session key %s", self._session_key.hex())

            mac = encrypt_mac_key(self._session_key, bytes(self._access_code, "utf_8"))
            _LOGGER.debug("Mac key to write %s", mac)
            await client.write_gatt_char(UUID_MASTER_AUTHENTICATION_2, mac)

            data = HeaterAction(action).__bytes__()
            _LOGGER.debug("Data to write %s", data.hex())
            data = encrypt_characteristic(data, self._session_key)
            _LOGGER.debug("Encrypted data to write %s", data.hex())
            await client.write_gatt_char(UUID_RX_CHARACTERISTIC, data)

    async def async_write_solar_action(self, action: SolarAppActions):
        """Connect to the Chlorinator and write an action command to it."""
        while self._connected:
            _LOGGER.debug("Already connected, Waiting")
            await asyncio.sleep(1)

        async with BleakClient(self._ble_device, timeout=10) as client:
            self._session_key = await client.read_gatt_char(UUID_SLAVE_SESSION_KEY_2)
            _LOGGER.debug("Got session key %s", self._session_key.hex())

            mac = encrypt_mac_key(self._session_key, bytes(self._access_code, "utf_8"))
            _LOGGER.debug("Mac key to write %s", mac)
            await client.write_gatt_char(UUID_MASTER_AUTHENTICATION_2, mac)

            data = SolarAction(action).__bytes__()
            _LOGGER.debug("Data to write %s", data.hex())
            data = encrypt_characteristic(data, self._session_key)
            _LOGGER.debug("Encrypted data to write %s", data.hex())
            await client.write_gatt_char(UUID_RX_CHARACTERISTIC, data)


    async def async_gatherdata(self) -> dict[str, Any]:
        """Connect to the Chlorinator to get data."""
        if self._ble_device is None:
            self._result = {}
            return self._result

        self._result = {}

        _LOGGER.debug("Starting halo_ble_client")
        self._connected = True

        async def callback_handler(_, data):
            characteristics = {
                1: DeviceProfileCharacteristic2,  # ExtractProfile
                # 2: ExtractTime,  # Extract Time
                # 3: ExtractDate,  # Extract Date
                # 5: ExtractUnknown,
                # 6: ExtractName
                9: TempCharacteristic,  # ExtractTemp
                100: SettingsCharacteristic2,  # ExtractSettings
                101: WaterVolumeCharacteristic,  # ExtractWaterVolume
                102: SetPointCharacteristic,  # ExtractSetPoint
                104: StateCharacteristic3,  # ExtractState
                105: CapabilitiesCharacteristic2,  # ExtractCapabilities
                106: MaintenanceStateCharacteristic,  # ExtractMaintenanceState
                # 107: ExtractFlexSettings,
                201: EquipmentModeCharacteristic,  # ExtractEquipmentConfig
                202: EquipmentParameterCharacteristic,  # ExtractEquipmentParameter
                300: LightStateCharacteristic,  # ExtractLightState
                301: LightCapabilitiesCharacteristic,  # ExtractLightCapabilities
                302: LightSetupCharacteristic,  # ExtractLightZoneNames,
                # 400: ExtractTimerCapabilities,
                # 401: ExtractTimerSetup,
                # 402: ExtractTimerState,
                # 403: ExtractTimerConfig,
                600: ProbeCharacteristic,  # ExtractProbeStatistics
                601: CellCharacteristic2,  # ExtractCellStatistics
                602: PowerBoardCharacteristic,  # ExtractPowerBoardStatistics
                # 603: ExtractInfoLog,
                1100: HeaterCapabilitiesCharacteristic,  # ExtractHeaterCapabilities
                1101: HeaterConfigCharacteristic,  # ExtractHeaterConfig
                1102: HeaterStateCharacteristic,  # ExtractHeaterState
                1104: HeaterCooldownStateCharacteristic,  # ExtractHeaterCooldownState
                1200: SolarCapabilitiesCharacteristic,  # ExtractSolarCapabilities
                1201: SolarConfigCharacteristic,  # ExtractSolarConfig
                1202: SolarStateCharacteristic,  # ExtractSolarState
                1300: GPOSetupCharacteristic,  # ExtractGPONames
                1301: RelaySetupCharacteristic,  # ExtractRelayNames
                1302: ValveSetupCharacteristic,  # ExtractValveNames
            }

            decrypted = decrypt_characteristic(data, self._session_key)

            cmd_type = int.from_bytes(decrypted[1:3], byteorder="little")
            cmd_data = decrypted[3:20]
            # can be [3:19], last byte seems to be a packet counter
            _LOGGER.debug(f"CMD: {cmd_type} DATA: {binascii.hexlify(cmd_data)}")

            if cmd_type in characteristics:
                characteristic_class = characteristics[cmd_type]
                rec_data = characteristic_class(cmd_data)
                if rec_data is not None:
                    self._result.update(vars(rec_data))

        async with BleakClient(self._ble_device, timeout=10) as client:
            self._session_key = await client.read_gatt_char(UUID_SLAVE_SESSION_KEY_2)
            _LOGGER.debug("Got session key %s", self._session_key.hex())

            mac = encrypt_mac_key(self._session_key, bytes(self._access_code, "utf_8"))
            # _LOGGER.debug("mac key to write %s", mac.hex())
            await client.write_gatt_char(UUID_MASTER_AUTHENTICATION_2, mac)

            await client.start_notify(UUID_TX_CHARACTERISTIC, callback_handler)
            _LOGGER.debug("Turn on notifications for %s", UUID_TX_CHARACTERISTIC)

            # await client.write_gatt_char(
            #     UUID_RX_CHARACTERISTIC,
            #     encrypt_characteristic(
            #         pad_byte_array(bytes([2, 1]), 20),
            #         self._session_key,
            #     ),
            # )  # ReadForCatchAll(1) KEEP ALIVE

            _LOGGER.debug("Perform Vomit Async")
            await client.write_gatt_char(
                UUID_RX_CHARACTERISTIC,
                encrypt_characteristic(
                    pad_byte_array(bytes([2, 107]), 20),
                    self._session_key,
                ),
            )  # ReadForCatchAll(107)

            await client.write_gatt_char(
                UUID_RX_CHARACTERISTIC,
                encrypt_characteristic(
                    pad_byte_array(bytes([2, 5]), 20),
                    self._session_key,
                ),
            )  # ReadForCatchAll(5)

            await client.write_gatt_char(
                UUID_RX_CHARACTERISTIC,
                encrypt_characteristic(
                    pad_byte_array(bytes([2, 88, 2]), 20),
                    self._session_key,
                ),
            )  # ReadForCatchAll(600)

            await client.write_gatt_char(
                UUID_RX_CHARACTERISTIC,
                encrypt_characteristic(
                    pad_byte_array(bytes([2, 89, 2]), 20),
                    self._session_key,
                ),
            )  # ReadForCatchAll(601)

            await client.write_gatt_char(
                UUID_RX_CHARACTERISTIC,
                encrypt_characteristic(
                    pad_byte_array(bytes([2, 90, 2]), 20),
                    self._session_key,
                ),
            )  # ReadForCatchAll(602)

            await client.write_gatt_char(
                UUID_RX_CHARACTERISTIC,
                encrypt_characteristic(
                    pad_byte_array(bytes([2, 91, 2]), 20),
                    self._session_key,
                ),
            )  # ReadForCatchAll(603)

            # await asyncio.sleep(4)
            # Instead of disconnecting from Halo, let the halo disconnect from us to prevent its ble from hanging
            timeout = 15  # seconds
            start_time = asyncio.get_event_loop().time()

            while client.is_connected:
                if (asyncio.get_event_loop().time() - start_time) > timeout:
                    _LOGGER.debug("Timeout reached, device did not disconnect in the expected time")
                    break
                await asyncio.sleep(0.1)  # Short sleep to yield control and prevent a busy wait




            # await client.write_gatt_char(
            #     UUID_RX_CHARACTERISTIC,
            #     encrypt_characteristic(
            #         pad_byte_array(bytes([2, 1]), 20),
            #         self._session_key,
            #     ),
            # )  # ReadForCatchAll(1) KEEP ALIVE

            # await asyncio.sleep(5)
            # await client.stop_notify(UUID_TX_CHARACTERISTIC)
            # _LOGGER.debug("Stop Notification and finish")
            # await asyncio.sleep(1)
            
            _LOGGER.debug("halo_ble_client finished: %s", self._result)
            self._connected = False
            return self._result
