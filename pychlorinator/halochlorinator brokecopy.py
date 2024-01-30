"""API for Astra Pool Halo pool chlorinator"""

import logging
from typing import Any
from bleak import BleakClient
from bleak.backends.device import BLEDevice
from Crypto.Cipher import AES
import asyncio
import time
import binascii
from pychlorinator.halo_parsers import *

UUID_ASTRALPOOL_SERVICE_2 = "45000001-98b7-4e29-a03f-160174643002"
UUID_SLAVE_SESSION_KEY_2 = "45000001-98b7-4e29-a03f-160174643002"
UUID_MASTER_AUTHENTICATION_2 = "45000002-98b7-4e29-a03f-160174643002"
UUID_TX_CHARACTERISTIC = "45000003-98b7-4e29-a03f-160174643002"
UUID_RX_CHARACTERISTIC = "45000004-98b7-4e29-a03f-160174643002"
ASTRALPOOL_HALO_BLE_NAME = "HCHLOR"

SECRET_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

_LOGGER = logging.getLogger(__name__)


def pad_byte_array(byte_array, target_length):
    padding_needed = max(0, target_length - len(byte_array))
    return byte_array + bytes(padding_needed)


def xor_bytes(array1, array2):
    """XOR two byte arrays, left aligned, zero padded"""
    shrt, lng = sorted((array1, array2), key=len)
    shrt = shrt.ljust(len(lng), b"\0")
    return bytes(array1 ^ array2 for (array1, array2) in zip(shrt, lng))


def encrypt_mac_key(session_key: bytes, access_code: bytes) -> bytes:
    """encrypt the mac key"""
    xored = xor_bytes(session_key, access_code)
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return cipher.encrypt(xored)


def encrypt_characteristic(data: bytes, session_key: bytes) -> bytes:
    """encrypt a characteristc packet"""
    xored = xor_bytes(data, session_key)
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    array = cipher.encrypt(xored[:16]) + xored[16:]
    array = array[:4] + cipher.encrypt(array[4:])
    return array


def decrypt_characteristic(data: bytes, session_key: bytes) -> bytes:
    """decrypt a GATT characteristic"""
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    array = data[:4] + cipher.decrypt(data[4:])
    array = cipher.decrypt(array[:16]) + array[16:]
    xored = xor_bytes(array, session_key)
    return xored


class HaloChlorinatorAPI:
    """represents the chlorinator device"""

    def __init__(
        self,
        ble_device: BLEDevice,
        access_code: str,
    ) -> None:
        self._ble_device = ble_device
        self._access_code = access_code
        self._session_key = None
        self._result: dict[str, Any] = None

    _LOGGER.info("Hello from HaloChlorinator API")

    async def async_gatherdata(self) -> dict[str, Any]:
        """Connect to the Chlorinator to get data."""
        if self._ble_device is None:
            self._result = {}
            return self._result

        self._result = {}

        async def halo_ble_client(queue: asyncio.Queue):
            _LOGGER.info("Starting halo_ble_client")

            async def callback_handler(_, data):
                await queue.put((time.time(), data, self._session_key))

            async with BleakClient(self._ble_device, timeout=10) as client:
                self._session_key = await client.read_gatt_char(
                    UUID_SLAVE_SESSION_KEY_2
                )
                _LOGGER.info("Got session key %s", self._session_key.hex())

                mac = encrypt_mac_key(
                    self._session_key, bytes(self._access_code, "utf_8")
                )
                _LOGGER.info("mac key to write %s", mac.hex())
                await client.write_gatt_char(UUID_MASTER_AUTHENTICATION_2, mac)

                await client.start_notify(UUID_TX_CHARACTERISTIC, callback_handler)
                _LOGGER.info("Turn on notifications for %s", UUID_TX_CHARACTERISTIC)

                _LOGGER.info("Perform Vomit Async")
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

                await asyncio.sleep(2)
                await client.stop_notify(UUID_TX_CHARACTERISTIC)
                _LOGGER.info("Stop Notification and finish")
                await asyncio.sleep(1)
                await queue.put((time.time(), None))
                _LOGGER.info("rec finish: %s", self._result)
                return self._result

        async def halo_queue_consumer(queue: asyncio.Queue):
            _LOGGER.info("Starting queue consumer")

            # def ExtractUnknown():
            #     _LOGGER.debug(f"Unknown {CmdType} {CmdData}")
            #     return None

            # def ExtractProfile():  # 1
            #     _LOGGER.info(
            #         f"ExtractProfile: {vars(DeviceProfileCharacteristic2(CmdData))}"
            #     )
            #     return DeviceProfileCharacteristic2(CmdData)

            # def ExtractName():  # 6
            #     _LOGGER.info(f"ExtractName {CmdData.decode('utf-8', errors='ignore')}")
            #     return None

            def ExtractTemp():  # 9
                _LOGGER.info(f"ExtractTemp {vars(TempCharacteristic(CmdData))}")
                return TempCharacteristic(CmdData)

            def ExtractSettings():  # 100
                _LOGGER.info(
                    f"ExtractSettings {vars(SettingsCharacteristic2(CmdData))}"
                )
                return SettingsCharacteristic2(CmdData)

            def ExtractWaterVolume():  # 101
                _LOGGER.info(
                    f"ExtractWaterVolume {vars(WaterVolumeCharacteristic(CmdData))}"
                )
                return WaterVolumeCharacteristic(CmdData)

            def ExtractSetPoint():  # 102
                _LOGGER.info(f"ExtractSetPoint {vars(SetPointCharacteristic(CmdData))}")
                return SetPointCharacteristic(CmdData)

            # def ExtractState():  # 104
            #     _LOGGER.info(f"ExtractState {vars(StateCharacteristic3(CmdData))}")
            #     return StateCharacteristic3(CmdData)

            # def ExtractCapabilities():  # 105
            #     _LOGGER.info(
            #         f"ExtractCapabilities {vars(CapabilitiesCharacteristic2(CmdData))}"
            #     )
            #     return CapabilitiesCharacteristic2(CmdData)

            # def ExtractMaintenanceState():  # 106
            #     _LOGGER.info(
            #         f"ExtractMaintenanceState {vars(MaintenanceStateCharacteristic(CmdData))}"
            #     )
            #     return MaintenanceStateCharacteristic(CmdData)

            # def ExtractFlexSettings():  # 107
            #     _LOGGER.info(f"ExtractFlexSettings")
            #     return None

            # def ExtractEquipmentConfig():  # 201
            #     _LOGGER.info(
            #         f"ExtractEquipmentConfig {vars(EquipmentModeCharacteristic(CmdData))}"
            #     )
            #     return EquipmentModeCharacteristic(CmdData)

            # def ExtractEquipmentParameter():  # 202
            #     _LOGGER.info(
            #         f"ExtractEquipmentParameter {vars(EquipmentParameterCharacteristic(CmdData))}"
            #     )
            #     return EquipmentParameterCharacteristic(CmdData)

            # def ExtractLightState():  # 300
            #     _LOGGER.info(
            #         f"ExtractLightState {vars(LightStateCharacteristic(CmdData))}"
            #     )
            #     return LightStateCharacteristic(CmdData)

            # def ExtractLightCapabilities():  # 301
            #     _LOGGER.info(
            #         f"ExtractLightCapabilities {vars(LightCapabilitiesCharacteristic(CmdData))}"
            #     )
            #     return LightCapabilitiesCharacteristic(CmdData)

            # def ExtractLightZoneNames():  # 302
            #     _LOGGER.info(
            #         f"ExtractLightZoneNames {vars(LightSetupCharacteristic(CmdData))}"
            #     )
            #     return LightSetupCharacteristic(CmdData)

            # def ExtractTimerCapabilities():  # 400
            #     _LOGGER.info(f"ExtractTimerCapabilities")

            # def ExtractTimerSetup():  # 401
            #     _LOGGER.info(f"ExtractTimerSetup")
            #     return None

            # def ExtractTimerState():  # 402
            #     _LOGGER.info(f"ExtractTimerState")
            #     return None

            # def ExtractTimerConfig():  # 403
            #     _LOGGER.info(f"ExtractTimerConfig")
            #     return None

            # def ExtractProbeStatistics():  # 600
            #     _LOGGER.info(
            #         f"ExtractProbeStatistics {vars(ProbeCharacteristic(CmdData))}"
            #     )
            #     return ProbeCharacteristic(CmdData)

            # def ExtractCellStatistics():  # 601
            #     _LOGGER.info(
            #         f"ExtractCellStatistics {vars(CellCharacteristic2(CmdData))}"
            #     )
            #     return CellCharacteristic2(CmdData)

            # def ExtractPowerBoardStatistics():  # 602
            #     _LOGGER.info(
            #         f"ExtractPowerBoardStatistics {vars(PowerBoardCharacteristic(CmdData))}"
            #     )
            #     return PowerBoardCharacteristic(CmdData)

            # def ExtractInfoLog():  # 603
            #     _LOGGER.info(f"ExtractInfoLog")
            #     return None

            # def ExtractHeaterCapabilities():  # 1100
            #     _LOGGER.info(
            #         f"ExtractHeaterCapabilities {vars(HeaterCapabilitiesCharacteristic(CmdData))}"
            #     )
            #     return HeaterCapabilitiesCharacteristic(CmdData)

            # def ExtractHeaterConfig():  # 1101
            #     _LOGGER.info(
            #         f"HeaterConfigCharacteristic {vars(HeaterConfigCharacteristic(CmdData))}"
            #     )
            #     return HeaterConfigCharacteristic(CmdData)

            # def ExtractHeaterState():  # 1102
            #     _LOGGER.info(
            #         f"ExtractHeaterState {vars(HeaterStateCharacteristic(CmdData))}"
            #     )
            #     return HeaterStateCharacteristic(CmdData)

            # def ExtractHeaterCooldownState():  # 1104
            #     _LOGGER.info(
            #         f"ExtractHeaterCooldownState {vars(HeaterCooldownStateCharacteristic(CmdData))}"
            #     )
            #     return HeaterCooldownStateCharacteristic(CmdData)

            # def ExtractSolarCapabilities():  # 1200
            #     _LOGGER.info(
            #         f"ExtractSolarCapabilities {vars(SolarCapabilitiesCharacteristic(CmdData))}"
            #     )
            #     return SolarCapabilitiesCharacteristic(CmdData)

            # def ExtractSolarConfig():  # 1201
            #     _LOGGER.info(
            #         f"ExtractSolarConfig {vars(SolarConfigCharacteristic(CmdData))}"
            #     )
            #     return SolarConfigCharacteristic(CmdData)

            # def ExtractSolarState():  # 1202
            #     _LOGGER.info(
            #         f"ExtractSolarState {vars(SolarStateCharacteristic(CmdData))}"
            #     )
            #     return SolarStateCharacteristic(CmdData)

            # def ExtractGPONames():  # 1300
            #     _LOGGER.info(f"ExtractGPONames {vars(GPOSetupCharacteristic(CmdData))}")
            #     return GPOSetupCharacteristic(CmdData)

            # def ExtractRelayNames():  # 1301
            #     _LOGGER.info(
            #         f"ExtractRelayNames {vars(RelaySetupCharacteristic(CmdData))}"
            #     )
            #     return RelaySetupCharacteristic(CmdData)

            # def ExtractValveNames():  # 1302
            #     _LOGGER.info(
            #         f"ExtractValveNames {vars(ValveSetupCharacteristic(CmdData))}"
            #     )
            #     return ValveSetupCharacteristic(CmdData)

            cmds = {
                # 1: ExtractProfile,
                # 2: ExtractUnknown,  # Extract Time (do we care?)
                # 3: ExtractUnknown,  # Extract Date (do we care?)
                # 5: ExtractUnknown,
                # 6: ExtractName,
                9: ExtractTemp,
                # 100: ExtractSettings,
                # 101: ExtractWaterVolume,
                # 102: ExtractSetPoint,
                # # 104: ExtractState,
                # 105: ExtractCapabilities,
                # 106: ExtractMaintenanceState,
                # 107: ExtractFlexSettings,
                # 201: ExtractEquipmentConfig,
                # 202: ExtractEquipmentParameter,
                # 300: ExtractLightState,
                # 301: ExtractLightCapabilities,
                # 302: ExtractLightZoneNames,
                # 400: ExtractTimerCapabilities,
                # 401: ExtractTimerSetup,
                # 402: ExtractTimerState,
                # 403: ExtractTimerConfig,
                # 600: ExtractProbeStatistics,
                # 601: ExtractCellStatistics,
                # 602: ExtractPowerBoardStatistics,
                # 603: ExtractInfoLog,
                # 1100: ExtractHeaterCapabilities,
                # 1101: ExtractHeaterConfig,
                # 1102: ExtractHeaterState,
                # 1104: ExtractHeaterCooldownState,
                # 1200: ExtractSolarCapabilities,
                # 1201: ExtractSolarConfig,
                # 1202: ExtractSolarState,
                # 1300: ExtractGPONames,
                # 1301: ExtractRelayNames,
                # 1302: ExtractValveNames,
            }

            while True:
                # Use await asyncio.wait_for(queue.get(), timeout=1.0) if you want a timeout for getting data.
                epoch, data, _session_key = await queue.get()
                if data is None:
                    _LOGGER.info(
                        "Got message from client about disconnection. Exiting consumer loop..."
                    )
                    break
                else:
                    decrypted = decrypt_characteristic(data, _session_key)
                    # logger.info("Received data at %s: %r", epoch, binascii.hexlify(decrypted))

                    CmdType = int.from_bytes(decrypted[1:3], byteorder="little")
                    CmdData = decrypted[3:20]
                    _LOGGER.info(f"CMD: {CmdType} DATA: {binascii.hexlify(CmdData)}")
                    if CmdType in cmds:
                        recData = cmds[CmdType]()
                        if recData is not None:
                            # _LOGGER.info("recdata %s", vars(recData))
                            self._result.update(vars(recData))

        queue = asyncio.Queue()
        client_task = halo_ble_client(queue)
        consumer_task = halo_queue_consumer(queue)

        await asyncio.gather(client_task, consumer_task)
