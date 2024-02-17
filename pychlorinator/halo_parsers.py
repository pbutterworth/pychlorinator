import struct

from enum import Enum, IntFlag, IntEnum

import logging

_LOGGER = logging.getLogger(__name__)


class ChlorinatorActions(IntEnum):
    NoAction = 0
    Off = 1
    Auto = 2
    On = 3
    Low = 4
    Medium = 5
    High = 6
    Pool = 7
    Spa = 8
    DismissInfoMessage = 9
    DisableAcidDosingIndefinitely = 10
    DisableAcidDosingForPeriod = 11
    ResetStatistics = 12
    TriggerCellReversal = 13
    AllOff = 14
    AllAuto = 15
    Backwash = 16
    PrimeAcid = 17
    ManualDose = 18
    ProbeCalibrationStart = 19
    ProbeCalibrationAction = 20
    AbortMaintTask = 21
    SanitiseUntilTimerTomorrow = 22
    FilterForPeriod = 23
    FilterAndCleanForPeriod = 24
    ResetToFactoryDefaults = 25
    PoolFavourite = 26
    SpaFavourite = 27
    Favourite1 = 28
    Favourite2 = 29
    ClearEventList = 30
    SanitiseForPeriod = 31
    SanitiseAndCleanForPeriod = 32
    OverrideHeaterCooldown = 33


class HeaterAppActions(IntEnum):
    NoAction = 0
    HeaterPumpOff = 1
    HeaterPumpAuto = 2
    HeaterPumpOn = 3
    HeaterOff = 4
    HeaterOn = 5
    IncreaseSetpoint = 6
    DecreaseSetpoint = 7
    Pool = 8
    Spa = 9
    DisableUseTimers = 10
    EnableUseTimers = 11
    ModeHeating = 12
    ModeCooling = 13


class SolarAppActions(IntEnum):
    NoAction = 0
    Off = 1
    Auto = 2
    On = 3
    Summer = 4
    Winter = 5
    IncreaseSetPoint = 6
    DecreaseSetPoint = 7


class LightAppActions(IntEnum):
    NoAction = 0
    SetZoneModeToManual = 1
    SetZoneModeToAuto = 2
    TurnOffZone = 3
    TurnOnZone = 4
    SetZoneColour = 5
    SynchroniseZoneColour = 6


class ChlorinatorAction:
    """Represent an action command"""

    # period_minutes only used for setting ChlorinatorActions:DisableAcidDosingForPeriod

    def __init__(
        self,
        action: ChlorinatorActions = ChlorinatorActions.NoAction,
        period_minutes: int = 0,
        header_bytes: bytes = b"\x03\xF4\x01",  # 500
    ) -> None:
        self.action = action
        self.period_minutes = period_minutes
        self.header_bytes = header_bytes

    def __bytes__(self):
        fmt = "=3s B i 12x"
        _LOGGER.info("Selected Action is %s", self.action)
        return struct.pack(fmt, self.header_bytes, self.action, self.period_minutes)


class HeaterAction:
    """Represent an Heater action command"""

    def __init__(
        self,
        action: HeaterAppActions = HeaterAppActions.NoAction,
        header_bytes: bytes = b"\x03\xF6\x01",  # 502
    ) -> None:
        self.action = action
        self.header_bytes = header_bytes

    def __bytes__(self):
        fmt = "=3s B 16x"
        _LOGGER.info("Selected Heater Action is %s", self.action)
        return struct.pack(fmt, self.header_bytes, self.action)


class SolarAction:
    """Represent an Solar action command"""

    def __init__(
        self,
        action: SolarAppActions = SolarAppActions.NoAction,
        header_bytes: bytes = b"\x03\xF7\x01",  # 503
    ) -> None:
        self.action = action
        self.header_bytes = header_bytes

    def __bytes__(self):
        fmt = "=3s B 16x"
        _LOGGER.info("Selected Solar Action is %s", self.action)
        return struct.pack(fmt, self.header_bytes, self.action)


class LightAction:
    """Represent an Light action command"""

    def __init__(
        self,
        action: LightAppActions = LightAppActions.NoAction,
        header_bytes: bytes = b"\x03\xF5\x01",  # 501
    ) -> None:
        self.action = action
        self.header_bytes = header_bytes

    def __bytes__(self):
        fmt = "=3s B 16x"
        _LOGGER.info("Selected Light Action is %s", self.action)
        return struct.pack(fmt, self.header_bytes, self.action)


class ScanResponse:
    _fmt = "<BBBBBBI4sBBBBBBB"

    def __init__(self, data) -> None:
        fields = struct.unpack(self._fmt, data[: struct.calcsize(self._fmt)])
        (
            # self.ManufacturerIdLo,
            # self.ManufacturerIdHi,
            self.DeviceType,
            self.DeviceVersion,
            self.DeviceProtocol,
            self.DeviceProtocolRevision,
            self.DeviceStatus,
            self._reserved,
            self.DeviceUniqueId,  # 4 bytes
            self.ByteAccessCode,  # 4 bytes
            self.FirmwareMajorVersion,
            self.FirmwareMinorVersion,
            self.BootloaderMajorVersion,
            self.BootloaderMinorVersion,
            self.HardwarePlatformIdLo,
            self.HardwarePlatformIdHi,
            self.TimeAlive,
        ) = fields

        self.isPairable = self.ByteAccessCode != b"\x00\x00\x00\x00"
        self.DeviceType = DeviceType(self.DeviceType)
        self.DeviceProtocol = DeviceProtocol(self.DeviceProtocol)

    def get_access_code(self) -> str:
        if not self.isPairable:
            return "0000"
        try:
            return self.ByteAccessCode.decode("utf-8")
        except UnicodeDecodeError:
            return "Invalid UTF-8 encoding"


class DeviceProfileCharacteristic2:
    def __init__(self, data, fmt="<BBBBBBBBBI"):
        (
            self.DeviceType,
            self.DeviceVersion,
            self.DeviceProtocol,
            self.DeviceProtocolRevision,
            self.FirmwareVersionMajor,
            self.FirmwareVersionMinor,
            self.BootloaderVersionMajor,
            self.BootloaderVersionMinor,
            self.HardwareVersion,
            self.SerialNumber,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        self.DeviceType = DeviceType(self.DeviceType)
        self.DeviceProtocol = DeviceProtocol(self.DeviceProtocol)


class TempCharacteristic:
    fmt = "<BBHHHHBHHB"

    def __init__(self, data) -> None:
        (
            self.IsFahrenheit,
            self.TempSupports,
            self.BoardTemp,
            self.WaterTemp,
            self.ChloroWater,
            self.SolarWater,
            self.WaterTempValid,
            self.SolarRoof,
            self.Heater,
            self.TempDisplayed,
        ) = struct.unpack(self.fmt, data[: struct.calcsize(self.fmt)])

        self.BoardTemp /= 10  # assumption Not in .net code???
        self.WaterTemp /= 10
        self.ChloroWater /= 10  # assumption as not in .net code???
        self.SolarWater /= 10  # assumption as not in .net code???
        self.SolarRoof /= 10  # assumption as not in .net code???
        self.Heater /= 10  # assumption as not in .net code???

        self.TempSupports = self.temp_supports_flags
        self.TempDisplayed = self.temp_displayed_flags
        self.WaterTempValid = self.TempValidEnum(self.WaterTempValid)

    @property
    def temp_supports_flags(self):
        return self.TempSupportsValues(self.TempSupports)

    @property
    def temp_displayed_flags(self):
        return self.TempDisplayedValues(self.TempDisplayed)

    class TempSupportsValues(IntFlag):
        BoardTemp = 1
        WaterTemp = 2
        ChloroWater = 4
        SolarWater = 8
        SolarRoof = 16
        Heater = 32

    class TempDisplayedValues(IntFlag):
        BoardTemp = 1
        WaterTemp = 2
        ChloroWater = 4
        SolarWater = 8
        SolarRoof = 16
        Heater = 32

    class TempValidEnum(Enum):
        Invalid = 0
        IsValid = 1
        WasValid = 2

        def __str__(self):
            return self.name


class SettingsCharacteristic2:
    fmt = "<HBBBBBB"

    def __init__(self, data):
        (
            self.General,
            self.CellModel,
            self.ReversalPeriod,
            self.AIWaterTurns,
            self.AcidPumpSize,
            self.FilterPumpSize,
            self.DefaultManualOnSpeed,
        ) = struct.unpack(self.fmt, data[: struct.calcsize(self.fmt)])

        self.General = self.general_values
        self.CellModel = self.CellModelValues(self.CellModel)

        self.PrePurgeEnabled = bool(self.GeneralValues.PrePurgeEnabled & self.General)
        self.PostPurgeEnabled = bool(self.GeneralValues.PostPurgeEnabled & self.General)
        self.AcidFlushEnabled = bool(self.GeneralValues.AcidFlushEnabled & self.General)
        self.AIEnabledReadlyOnly = bool(
            self.GeneralValues.AIEnabledReadOnly & self.General
        )
        self.AiModeEnabled = (
            bool(self.GeneralValues.AIEnabled & self.General)
            or self.AIEnabledReadlyOnly
        )
        self.DisplayORP = bool(self.GeneralValues.DisplayORP & self.General)
        self.IsDosingCapable = bool(self.GeneralValues.DosingEnabled & self.General)
        self.ThreespeedPumpEnabled = bool(
            self.GeneralValues.ThreeSpeedPumpEnabled & self.General
        )
        self.ThreeSpeedPumpEnabledReadOnly = bool(
            self.GeneralValues.ThreeSpeedPumpEnabledReadOnly & self.General
        )
        self.EnableCleaningInterlock = bool(
            self.GeneralValues.EnableCleaningInterlock & self.General
        )

    @property
    def general_values(self):
        return self.GeneralValues(self.General)

    class GeneralValues(IntFlag):
        PrePurgeEnabled = 1
        PostPurgeEnabled = 2
        AcidFlushEnabled = 4
        AIEnabled = 8
        AIEnabledReadOnly = 16
        DisplayORP = 32
        DosingEnabled = 64
        ThreeSpeedPumpEnabled = 128
        ThreeSpeedPumpEnabledReadOnly = 256
        PumpProtectEnable = 512
        UseTemperatureSensor = 1024
        EnableCleaningInterlock = 2048
        DisplayPH = 4096

    class CellModelValues(IntEnum):
        Model_18 = 0
        Model_25 = 1
        Model_35 = 2
        Model_45 = 3

        def __str__(self):
            return self.name


class StateCharacteristic3:
    fmt = "<BBHBBHBBB2sHB"

    def __init__(self, data):
        (
            self.Flags,
            self.RealCelllevel,
            self.CellCurrentmA,
            self.MainText,
            self.SubText1Chlorine,
            self.ORPMeasurement,
            self.SubText2Ph,
            self.PhMeasurement,
            self.SubText3TimerInfo,
            *self.SubText3BytesData,
            self.SubText4ErrorInfo,
            self.Flag,
        ) = struct.unpack(self.fmt, data[: struct.calcsize(self.fmt)])

        self.PhMeasurement /= 10
        self.ph_measurement = self.PhMeasurement  # remap

        self.IsInPoolSelection = not bool(self.FlagsValues.SpaMode & self.Flags)
        self.IsCellRunning = bool(self.FlagsValues.CellOn & self.Flags)
        self.cell_is_operating = self.IsCellRunning  # remap
        self.IsCellReversed = bool(self.FlagsValues.CellReversed & self.Flags)
        self.IsCoolingFanOn = bool(self.FlagsValues.CoolingFanOn & self.Flags)
        self.IsLightOutputOn = bool(self.FlagsValues.LightOutputOn & self.Flags)
        self.DosingPumpOn = bool(self.FlagsValues.DosingPumpOn & self.Flags)
        self.CellIsReversing = bool(self.FlagsValues.CellIsReversing & self.Flags)
        self.AIModeActive = bool(self.FlagsValues.AIModeActive & self.Flags)
        self.MainText = self.MainTextValues(self.MainText)
        self.info_message = self.MainText  # remap
        self.SubText1 = self.SubText1Values(self.SubText1Chlorine)
        self.chlorine_control_status = self.SubText1  # remap
        self.SubText2 = self.SubText2Values(self.SubText2Ph)
        self.SubText3 = self.SubText3Values(self.SubText3TimerInfo)
        self.SubText4 = self.SubText4Values(self.SubText4ErrorInfo)

    # @property
    # def flags_values(self):
    #     return self.FlagsValues(self.Flags)

    # @property
    # def maintext_values(self):
    #     return self.MainTextValues(self.MainText)

    # @property
    # def subtext1_values(self):
    #     return self.SubText1Values(self.SubText1Chlorine)

    # @property
    # def subtext2_values(self):
    #     return self.SubText2Values(self.SubText2Ph)

    # @property
    # def subtext3_values(self):
    #     return self.SubText3Values(self.SubText3TimerInfo)

    # @property
    # def subtext4_values(self):
    #     return self.SubText4Values(self.SubText4ErrorInfo)

    class FlagsValues(IntFlag):
        SpaMode = 1
        CellOn = 2
        CellReversed = 4
        CoolingFanOn = 8
        LightOutputOn = 16
        DosingPumpOn = 32
        CellIsReversing = 64
        AIModeActive = 128

    class MainTextValues(Enum):
        NoneValue = (
            -1
        )  # Using 'NoneValue' because 'None' is a reserved keyword in Python
        Off = 0
        Sanitising = 1
        AIModeSanitising = 2
        AIModeSampling = 3
        Sampling = 4
        Standby = 5
        PrePurge = 6
        PostPurg = 7
        SanitisingUntilFirstTimer = 8
        Filtering = 9
        FilteringAndCleaning = 10
        CalibratingSensor = 11
        Backwashing = 12
        PrimingAcidPump = 13
        ManualAcidDose = 14
        LowSpeedNoChlorinating = 15
        SanitisingForPeriod = 16
        SanitisingAndCleaningForPeriod = 17
        LowTemperatureReducedOutput = 18
        HeaterCooldownInProgress = 19

        def __str__(self):
            return self.name

    class SubText1Values(IntEnum):
        NoneValue = 0  # 'None' is a reserved keyword in Python, so we use 'NoneValue'
        ORPIsYellow = 1
        ORPWasYellow = 2
        ORPIsGreen = 3
        ORPWasGreen = 4
        ORPIsRed = 5
        ORPWasRed = 6
        ChlorineIsLow = 7
        ChlorineWasLow = 8
        ChlorineIsOK = 9
        ChlorineWasOK = 10
        ChlorineIsHigh = 11
        ChlorineWasHigh = 12

        def __str__(self):
            return self.name

    class SubText2Values(IntEnum):
        NoneValue = 0  # 'None' is a reserved keyword in Python
        PHIsYellow = 1
        PHWasYellow = 2
        PHIsGreen = 3
        PHWasGreen = 4
        PHIsRed = 5
        PHWasRed = 6
        PHIsLow = 7
        PHWasLow = 8
        PHIsOK = 9
        PHWasOK = 10
        PHIsHigh = 11
        PHWasHigh = 12

        def __str__(self):
            return self.name

    class SubText3Values(IntEnum):
        NoneValue = 0
        SanitisingPoolOff = 1
        SanitisingPoolUntil = 2
        SanitisingSpaOff = 3
        SanitisingSpaUntil = 4
        SanitisingOff = 5
        SanitisingUntil = 6
        PrimingFor = 7
        HeaterCooldownTimeRemaining = 8

        def __str__(self):
            return self.name

    class SubText4Values(IntEnum):
        NoneValue = 0
        IOExpander = 1
        EEPROM = 2
        RTC = 3  # EEPROM | IOExpander
        NoComPowerToUser = 4
        NoComUserToPower = 5  # NoComPowerToUser | IOExpander
        Backwashing = 6  # NoComPowerToUser | EEPROM
        SensorCalibration = 7  # Backwashing | IOExpander
        AccessoryPairing = 8
        ChlorOverheat = 9  # AccessoryPairing | IOExpander
        TempShortCir = 10  # AccessoryPairing | EEPROM
        TempOpenCir = 11  # TempShortCir | IOExpander
        FactoryReset = 12  # AccessoryPairing | NoComPowerToUser
        UpdateSuccess = 50
        UpdateFailed = 51  # UpdateSuccess | IOExpander
        UpdateAvailable = 52
        LostCom = 100
        LowVoltage = 101  # LostCom | IOExpander
        PumpHighTemp = 102  # LostCom | EEPROM
        OverCurrent = 103  # PumpHighTemp | IOExpander
        BlockedInlet = 104
        PumpGnlFault = 150
        PumpLimitFault = 151  # PumpGnlFault | IOExpander
        PumpVoltFault = 152
        PumpCommFault = 153  # PumpVoltFault | IOExpander
        PumpTempFault = 154  # PumpVoltFault | EEPROM
        PumpSoftFault = 155  # PumpTempFault | IOExpander
        PumpFailedStart = 156  # PumpVoltFault | NoComPowerToUser
        PumpCommErr = 157  # PumpFailedStart | IOExpander
        PumpBlocked = 158  # PumpFailedStart | EEPROM
        pHComLost = 200
        ORPComLost = 201  # pHComLost | IOExpander
        pHHigh = 202  # pHComLost | EEPROM
        ORPHigh = 203  # pHHigh | IOExpander
        pHLow = 204  # pHComLost | NoComPowerToUser
        ORPLow = 205  # pHLow | IOExpander
        pHACErr = 206  # pHLow | EEPROM
        ORPACErr = 207  # pHACErr | IOExpander
        NoComHeater = 300
        LowWaterTemp = 301  # NoComHeater | IOExpander
        HighWaterTemp = 302  # NoComHeater | EEPROM
        MechOverheat = 303  # HighWaterTemp | IOExpander
        TherShortCir = 304
        FlameRollOut = 305  # TherShortCir | IOExpander
        FlueOverheat = 306  # TherShortCir | EEPROM
        CondensateOverflow = 307  # FlueOverheat | IOExpander
        HXTherOpenCir = 308  # TherShortCir | NoComPowerToUser
        HXTherShortCir = 309  # HXTherOpenCir | IOExpander
        WtrSsrSrted = 310  # HXTherOpenCir | EEPROM
        WtrSsrOpen = 311  # WtrSsrSrted | IOExpander
        HeaterHighTemp = 312  # TherShortCir | AccessoryPairing
        LowRefPrs = 313  # HeaterHighTemp | IOExpander
        HighRefPrs = 314  # HeaterHighTemp | EEPROM
        SrtedCoilSsr = 315  # HighRefPrs | IOExpander
        OpenCoilSsr = 316  # HeaterHighTemp | NoComPowerToUser
        Interlock = 317  # OpenCoilSsr | IOExpander
        HighLimit = 318  # OpenCoilSsr | EEPROM
        AirSsrSrted = 319  # HighLimit | IOExpander
        GPO1ComLost = 400
        GPO2ComLost = 401  # GPO1ComLost | IOExpander
        Light1LostCom = 500  # GPO1ComLost | LostCom
        Light2LostCom = 501  # Light1LostCom | IOExpander
        SlrRoofSsrSrted = 600
        SlrRoofSsrDis = 601  # SlrRoofSsrSrted | IOExpander
        SlrWtrSsrSrted = 602  # SlrRoofSsrSrted | EEPROM
        SlrWtrSsrDis = 603  # SlrWtrSsrSrted | IOExpander
        NoFlow = 700
        HighSalt = 701  # NoFlow | IOExpander
        LowSalt = 702  # NoFlow | EEPROM
        WaterTooCold = 703  # LowSalt | IOExpander
        DownRate2 = 705
        DownRate1 = 706
        SamplingOnly = 707  # DownRate1 | IOExpander
        DosingDisabled = 708
        DlyAcidDoseLimit = 709  # DosingDisabled | IOExpander
        CellDis = 710  # DosingDisabled | EEPROM
        pHBatteryLow = 900
        ORPBatteryLow = 901  # pHBatteryLow | IOExpander
        pHRequired = 902  # pHBatteryLow | EEPROM
        ConnectionError = 1400
        Unknown = 65535

        def __str__(self):
            return self.name


class WaterVolumeCharacteristic:
    def __init__(self, data, fmt="<BIHIHB"):
        (
            self.VolumeUnits,
            self.PoolVolume,
            self.SpaVolume,
            self.PoolLeftFilter,
            self.SpaLeftFilter,
            self.WaterVolumeFlag,  # renamed to remove clash
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])
        self.WaterVolumeFlag = self.flag_values
        self.VolumeUnits = self.VolumeUnit_value

        self.PoolEnabled = bool(self.FlagValues.PoolEnabled & self.WaterVolumeFlag)
        self.SpaEnabled = bool(self.FlagValues.SpaEnabled & self.WaterVolumeFlag)
        self.PoolSpaEnabled = self.PoolEnabled & self.SpaEnabled

    @property
    def flag_values(self):
        return self.FlagValues(self.WaterVolumeFlag)

    @property
    def VolumeUnit_value(self):
        return self.VolumeUnitsValues(self.VolumeUnits)

    class FlagValues(IntFlag):
        PoolEnabled = 1
        SpaEnabled = 2

    class VolumeUnitsValues(Enum):
        Litres = 0
        UsGallons = 1
        ImperialGallons = 2


class SetPointCharacteristic:
    def __init__(self, data, fmt="<BHBBB"):
        (
            self.PhControlSetpoint,
            self.OrpControlSetpoint,
            self.PoolChlorineControlSetpoint,
            self.AcidControlSetpoint,
            self.SpaChlorineControlSetpoint,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        self.PhControlSetpoint /= 10
        self.ph_control_setpoint = self.PhControlSetpoint
        self.chlorine_control_setpoint = self.OrpControlSetpoint


class CapabilitiesCharacteristic2:
    def __init__(self, data, fmt="<BB"):
        (
            self.PhControlType,
            self.OrpControlType,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        # Minimum setpoints
        self.MinimumManualAcidSetpoint = 0
        self.MinimumManualChlorineSetpoint = 0
        self.MinimumOrpSetpoint = 100
        self.MinimumPhSetpoint = 3.0

        # Maximum setpoints
        self.MaximumManualAcidSetpoint = 10
        self.MaximumManualChlorineSetpoint = 8
        self.MaximumOrpSetpoint = 800
        self.MaximumPhSetpoint = 10.0

        self.PhControlType = self.PhControlType_value
        self.ph_control_type = self.PhControlType  # remap
        self.ChlorineControlType = self.ChlorineControlType_value
        self.OrpControlType = self.ChlorineControlType_value  # remap
        self.chlorine_control_type = self.OrpControlType  # remap

    @property
    def PhControlType_value(self):
        return self.PhControlTypes(self.PhControlType)

    @property
    def ChlorineControlType_value(self):
        return self.ChlorineControlTypes(self.OrpControlType)

    class PhControlTypes(Enum):
        NoneType = 0
        Manual = 1
        Automatic = 2

        def __str__(self):
            return self.name

    class ChlorineControlTypes(Enum):
        NoneType = 0
        Manual = 1
        Automatic = 2

        def __str__(self):
            return self.name


class EquipmentModeCharacteristic:
    def __init__(self, data, fmt="<BBBBBBBBBBBBHH"):
        (
            self.EquipmentEnabled,
            self.FilterPumpMode,
            self.ModeGPO1,
            self.ModeGPO2,
            self.ModeGPO3,
            self.ModeGPO4,
            self.ModeValve1,
            self.ModeValve2,
            self.ModeValve3,
            self.ModeValve4,
            self.ModeRelay1,
            self.ModeRelay2,
            self.StateBitfield,
            self.AutoEnabledBitfield,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        self.mode = Mode(self.FilterPumpMode)
        self.EquipmentEnabled == 1  # is this correct?
        self.StateFilterPump = bool(
            self.StateBitfieldValues.FilterPump & self.StateBitfield
        )
        self.pump_is_operating = self.StateFilterPump  ## remap name
        self.AutoEnabledFilterPump = bool(
            self.AutoEnabledBitfieldValues.FilterPump & self.AutoEnabledBitfield
        )

        self.GPO1_Mode = GPOMode(self.ModeGPO1)
        self.GPO1_State = bool(self.StateBitfieldValues.GPO1 & self.StateBitfield)
        self.GPO1_AutoEnabled = bool(
            self.StateBitfieldValues.GPO1 & self.AutoEnabledBitfield
        )
        self.GPO2_Mode = GPOMode(self.ModeGPO2)
        self.GPO2_State = bool(self.StateBitfieldValues.GPO2 & self.StateBitfield)
        self.GPO2_AutoEnabled = bool(
            self.StateBitfieldValues.GPO2 & self.AutoEnabledBitfield
        )
        self.GPO3_Mode = GPOMode(self.ModeGPO3)
        self.GPO3_State = bool(self.StateBitfieldValues.GPO3 & self.StateBitfield)
        self.GPO3_AutoEnabled = bool(
            self.StateBitfieldValues.GPO3 & self.AutoEnabledBitfield
        )
        self.GPO4_Mode = GPOMode(self.ModeGPO4)
        self.GPO4_State = bool(self.StateBitfieldValues.GPO4 & self.StateBitfield)
        self.GPO4_AutoEnabled = bool(
            self.StateBitfieldValues.GPO4 & self.AutoEnabledBitfield
        )

        self.Valve1_Mode = GPOMode(self.ModeValve1)
        self.Valve1_State = bool(self.StateBitfieldValues.Valve1 & self.StateBitfield)
        self.Valve1_AutoEnabled = bool(
            self.StateBitfieldValues.Valve1 & self.AutoEnabledBitfield
        )
        self.Valve2_Mode = GPOMode(self.ModeValve2)
        self.Valve2_State = bool(self.StateBitfieldValues.Valve2 & self.StateBitfield)
        self.Valve2_AutoEnabled = bool(
            self.StateBitfieldValues.Valve2 & self.AutoEnabledBitfield
        )
        self.Valve3_Mode = GPOMode(self.ModeValve3)
        self.Valve3_State = bool(self.StateBitfieldValues.Valve3 & self.StateBitfield)
        self.Valve3_AutoEnabled = bool(
            self.StateBitfieldValues.Valve3 & self.AutoEnabledBitfield
        )
        self.Valve4_Mode = GPOMode(self.ModeValve4)
        self.Valve4_State = bool(self.StateBitfieldValues.Valve4 & self.StateBitfield)
        self.Valve4_AutoEnabled = bool(
            self.StateBitfieldValues.Valve4 & self.AutoEnabledBitfield
        )

        self.Relay1_Mode = GPOMode(self.ModeRelay1)
        self.Relay1_State = bool(self.StateBitfieldValues.Relay1 & self.StateBitfield)
        self.Relay1_AutoEnabled = bool(
            self.StateBitfieldValues.Relay1 & self.AutoEnabledBitfield
        )
        self.Relay2_Mode = GPOMode(self.ModeRelay2)
        self.Relay2_State = bool(self.StateBitfieldValues.Relay2 & self.StateBitfield)
        self.Relay2_AutoEnabled = bool(
            self.StateBitfieldValues.Relay2 & self.AutoEnabledBitfield
        )

    @property
    def state_bitfield_values(self):
        return self.StateBitfieldValues(self.StateBitfield)

    @property
    def test_value_for_flag(self, value, flag_enum):
        return flag_enum.value & value != 0

    class StateBitfieldValues(IntFlag):
        FilterPump = 1
        GPO1 = 2
        GPO2 = 4
        GPO3 = 8
        GPO4 = 16
        Valve1 = 32
        Valve2 = 64
        Valve3 = 128
        Valve4 = 256
        Relay1 = 512
        Relay2 = 1024

    class AutoEnabledBitfieldValues(IntFlag):
        FilterPump = 1
        GPO1 = 2
        GPO2 = 4
        GPO3 = 8
        GPO4 = 16
        Valve1 = 32
        Valve2 = 64
        Valve3 = 128
        Valve4 = 256
        Relay1 = 512
        Relay2 = 1024


class LightStateCharacteristic:
    def __init__(self, data, fmt="<4s4sB"):
        (
            self.ZoneModes,
            self.ZoneColours,
            self.ZoneStateFlags,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        self.LightingMode_1 = Mode(self.ZoneModes[0])
        self.LightingMode_2 = Mode(self.ZoneModes[1])
        self.LightingMode_3 = Mode(self.ZoneModes[2])
        self.LightingMode_4 = Mode(self.ZoneModes[3])
        self.LightingState_1 = self.ZoneStateFlagsValues(self.ZoneStateFlags & 0)
        self.LightingState_2 = self.ZoneStateFlagsValues(self.ZoneStateFlags & 1)
        self.LightingState_3 = self.ZoneStateFlagsValues(self.ZoneStateFlags & 2)
        self.LightingState_4 = self.ZoneStateFlagsValues(self.ZoneStateFlags & 3)
        self.LightingColour_1 = self.ZoneColours[0]
        self.LightingColour_2 = self.ZoneColours[1]
        self.LightingColour_3 = self.ZoneColours[2]
        self.LightingColour_4 = self.ZoneColours[3]
        """ Mapping of colours is located in namespace AstralPoolService.BusinessObjects.Light """
        """ Each model brand type of Light has its own colour. Too much logic to map out here """

    @property
    def zone_state_flags_values(self):
        return self.ZoneStateFlagsValues(self.ZoneStateFlags)

    class ZoneStateFlagsValues(IntFlag):
        Zone1On = 1
        Zone2On = 2
        Zone3On = 4
        Zone4On = 8


class LightCapabilitiesCharacteristic:
    def __init__(self, data, fmt="<5B"):
        (
            self.LightingEnabled,
            self.OnBoardLightEnabled,
            self.Model,
            self.NumZonesInUse,
            self.ZoneIsMulticolourFlags,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        self.ZoneIsMulticolourFlags = self.ZoneIsMulticolourFlagsValues(
            self.ZoneIsMulticolourFlags
        )

    @property
    def zone_is_multicolour_flags_values(self):
        return self.ZoneIsMulticolourFlagsValues(self.ZoneIsMulticolourFlags)

    class ZoneIsMulticolourFlagsValues(
        IntFlag
    ):  # There might be a bug in the .net code, as it is 1/2/3/4, not 1/2/4/8
        Zone1IsMulticolour = 1
        Zone2IsMulticolour = 2
        Zone3IsMulticolour = 4
        Zone4IsMulticolour = 8


class LightSetupCharacteristic:
    def __init__(self, data, fmt="<4s"):
        (self.ZoneNames,) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        self.LightingZoneName_1 = self.ZoneNamesValues(self.ZoneNames[0])
        self.LightingZoneName_2 = self.ZoneNamesValues(self.ZoneNames[1])
        self.LightingZoneName_3 = self.ZoneNamesValues(self.ZoneNames[2])
        self.LightingZoneName_4 = self.ZoneNamesValues(self.ZoneNames[3])

    class ZoneNamesValues(IntEnum):
        Pool = 0
        Spa = 1
        PoolAndSpa = 2
        Waterfall1 = 3
        Waterfall2 = 4
        Waterfall3 = 5
        Garden = 6
        Other = 7


class MaintenanceStateCharacteristic:
    def __init__(self, data, fmt="<BHBBIHBB"):
        (
            self.Flags,
            self.DoseDisableTimeMins,
            self.MaintenanceTaskState,
            self.MaintenanceTaskReturnCode,
            self.TaskTimeRemaining,
            self.ValueToDisplay,
            self.CalibrateState,
            self.ModeAfterComplete,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        self.AcidDosingDisabled = bool(self.FlagValues.AcidDosingDisabled & self.Flags)
        self.MaintenanceTaskState = self.TaskStatesValues(self.MaintenanceTaskState)
        self.MaintenanceTaskReturnCode = self.TaskReturnCodesValues(
            self.MaintenanceTaskReturnCode
        )
        self.CalibrateState = self.CalibrateStatesValues(self.CalibrateState)
        self.ModeAfterComplete = Mode(self.ModeAfterComplete)

    @property
    def flag_values(self):
        return self.FlagValues(self.Flags)

    class FlagValues(IntEnum):
        AcidDosingDisabled = 1
        DayRolledOver = 2

    class TaskStatesValues(IntEnum):
        NoState = -1  # 0xFFFFFFFF
        NoTask = 0
        SanitiseUntilTimer = 1
        FilterForPeriod = 2
        FilterAndCleanForPeriod = 3
        Backwash = 4
        CalibratePH = 5
        CalibrateORP = 6
        PrimeAcid = 7
        DoseAcid = 8
        SanitiseForPeriod = 9
        SanitiseAndCleanForPeriod = 10

    class TaskReturnCodesValues(IntEnum):
        OK = 0
        FailedSetStartConditions = 1
        TaskOverriddenByUser = 2
        FailedSetSystemMode = 3
        TaskAbortedByUser = 4
        TaskComplete = 5

    class CalibrateStatesValues(Enum):
        Idle = 0
        ProbeCalStarting = 1
        ConnectToProbe = 2
        ConnectionFailed = 3
        ReadCalValue = 4
        ReadCalValueFailed = 5
        RunningPump = 6
        TakingMeasurement = 7
        MeasurementFailed = 8
        WaitNewCalValue = 9
        TimeOutWaitingCalibration = 10
        WritingCalibrationValue = 11
        CalibrationFailedToWrite = 12
        CalibrationSuccessful = 13
        CalAbort = 14


class HeaterCapabilitiesCharacteristic:
    def __init__(self, data, fmt="<BBBBB"):
        (
            self.HeaterEnabled,
            self.FilterPumpThreeSpeed,
            self.HeaterPumpThreeSpeed,
            self.HeaterPumpInstalled,
            self.HeaterPumpTimerBit,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])


class HeaterConfigCharacteristic:
    def __init__(self, data, fmt="<BB"):
        (self.HeaterPumpEnabled, self.HeaterMinPumpSpeed) = struct.unpack(
            fmt, data[: struct.calcsize(fmt)]
        )

        self.HeaterMinPumpSpeed = self.SpeedLevels(self.HeaterMinPumpSpeed)

    class SpeedLevels(IntEnum):
        NotSet = -1
        Low = 0
        Medium = 1
        High = 2
        AI = 3

        def __str__(self):
            return self.name


class HeaterStateCharacteristic:
    def __init__(self, data, fmt="<BBBBBBBBBHB"):
        (
            self.HeaterStatusFlag,
            self.HeaterPumpMode,
            self.HeaterMode,
            self.HeaterSetpoint,
            self.HeatPumpMode,
            self.HeaterForced,
            self.HeaterForcedTimeHrs,
            self.HeaterForcedTimeMins,
            self.HeaterWaterTempValid,
            self.HeaterWaterTemp,
            self.HeaterError,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        self.HeaterOn = bool(
            self.HeaterStatusFlagValues.HeaterOn & self.HeaterStatusFlag
        )
        self.HeaterPressure = bool(
            self.HeaterStatusFlagValues.Pressure & self.HeaterStatusFlag
        )
        self.HeaterGasValve = bool(
            self.HeaterStatusFlagValues.GasValve & self.HeaterStatusFlag
        )
        self.HeaterFlame = bool(
            self.HeaterStatusFlagValues.Flame & self.HeaterStatusFlag
        )
        self.HeaterLockout = bool(
            self.HeaterStatusFlagValues.Lockout & self.HeaterStatusFlag
        )
        self.GeneralServiceRequired = bool(
            self.HeaterStatusFlagValues.GeneralServiceRequired & self.HeaterStatusFlag
        )
        self.IgnitionServiceRequired = bool(
            self.HeaterStatusFlagValues.IgnitionServiceRequired & self.HeaterStatusFlag
        )
        self.CoolingAvailable = bool(
            self.HeaterStatusFlagValues.CoolingAvailable & self.HeaterStatusFlag
        )
        self.HeaterMode = self.HeaterModeValues(
            self.HeaterMode
        )  ##Looks like just on / off
        self.HeaterPumpMode = Mode(self.HeaterPumpMode)
        self.HeatPumpMode = self.HeatpumpModeValues(self.HeatPumpMode)
        self.HeaterForced = self.HeaterForcedEnum(self.HeaterForced)
        self.HeaterWaterTempValid = self.TempValidEnum(self.HeaterWaterTempValid)
        self.HeaterWaterTemp /= 10

    @property
    def heater_status_flags(self):
        return HeaterStateCharacteristic.HeaterStatusFlagValues(self.HeaterStatusFlag)

    class HeaterModeValues(Enum):
        Off = 0
        On = 1

        def __str__(self):
            return self.name

    class HeaterStatusFlagValues(IntFlag):
        HeaterOn = 1
        Pressure = 2
        GasValve = 4
        Flame = 8
        Lockout = 16
        GeneralServiceRequired = 32
        IgnitionServiceRequired = 64
        CoolingAvailable = 128

    class HeatpumpModeValues(Enum):
        Cooling = 0
        Heating = 1
        Auto = 2

    class HeaterForcedEnum(Enum):
        NotForced = 0
        ForcedOn = 1
        ForcedOff = 2

    class TempValidEnum(Enum):
        Invalid = 0
        IsValid = 1
        WasValid = 2


class EquipmentParameterCharacteristic:
    def __init__(self, data, fmt="BBBBBBBBBBB"):
        (
            self.FilterPumpSpeed,
            self.ParameterGPO1,
            self.ParameterGPO2,
            self.ParameterGPO3,
            self.ParameterGPO4,
            self.ParameterValve1,
            self.ParameterValve2,
            self.ParameterValve3,
            self.ParameterValve4,
            self.ParameterRelay1,
            self.ParameterRelay2,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])
        self.FilterPumpSpeed = self.SpeedLevels(self.FilterPumpSpeed)
        self.pump_speed = self.SpeedLevels(self.FilterPumpSpeed)  # remap

    class SpeedLevels(Enum):
        NotSet = -1
        Low = 0
        Medium = 1
        High = 2
        AI = 3

        def __str__(self):
            return self.name


class DeviceType(Enum):
    """ScanResponse Device Type"""

    Unknown = -1  # 0xFFFFFFFF
    Pump = 0
    Chlorinator = 1
    Doser = 2
    Light = 3
    Probe = 4
    ChlorinatorEmulator = 129  # 0x00000081

    def __str__(self):
        return self.name


class ProbeCharacteristic:
    def __init__(self, data, fmt="<BBHH"):
        (
            self.HighestPhMeasured,
            self.LowestPhMeasured,
            self.HighestOrpMeasured,
            self.LowestOrpMeasured,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])
        self.HighestPhMeasured /= 10
        self.LowestPhMeasured /= 10


class CellCharacteristic2:
    def __init__(self, data, fmt="<HIIBHH"):
        (
            self.CellReversalCount,  # count
            self.CellRunningTime,  # hrs
            self.LowSaltCellRunningTime,  # hrs
            self.PreviousDaysCellLoad,  # % yesterday
            self.DosingPumpSecs,  # ml today
            self.FilterPumpMins,  # mins today
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])
        # self.CellRunningTime /= 3600 #??  TimeSpan.FromHours
        # self.LowSaltCellRunningTime /= 3600 #??


class PowerBoardCharacteristic:
    """Represents characteristics of a power board.

    Attributes:
        PowerBoardRuntime (int): The runtime of the power board in hours.

    """

    def __init__(self, data, fmt="<I"):
        (
            self.PowerBoardRuntime,  # hrs
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])
        # self.PowerBoardRuntime /= 3600 #??


class HeaterCooldownStateCharacteristic:
    def __init__(self, data, fmt="<BBBBHH"):
        (
            self.HeaterCooldownEventOccurredFlag,
            self.HeaterCooldownState,
            self.Ignore,
            self.TargetMode,
            self.RemainingCooldownTime,
            self.TotalHeaterCooldownTime,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])


class SolarCapabilitiesCharacteristic:
    def __init__(self, data, fmt="<B"):
        self.SolarEnabled = struct.unpack(fmt, data[: struct.calcsize(fmt)])[0]


class SolarConfigCharacteristic:
    def __init__(self, data, fmt="<BBBBBBBHB"):
        (
            self.SolarPumpStartHR,
            self.SolarPumpStartMin,
            self.SolarPumpStopHR,
            self.SolarPumpStopMin,
            self.SolarEnableFlush,
            self.SolarFlushTimeHR,
            self.SolarFlushTimeMin,
            self.SolarDifferential,  # renamed
            self.SolarEnableExclPeriod,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])


class SolarStateCharacteristic:
    def __init__(self, data, fmt="<HHHBBBBBHB"):
        (
            self.SolarRoofTemp,
            self.SolarWaterTemp,
            self.SolarTemp,
            self.SolarSeason,
            self.SolarMode,
            self.SolarFlag,
            self.SolarRoofTempValid,
            self.SolarWaterTempValid,
            self.SolarSpecTemp,
            self.SolarMessage,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        self.SolarWaterTemp /= 10
        self.SolarRoofTemp /= 10

        self.SolarIsSummerMode = self.SolarSeason
        self.SolarIsWinterMode = not self.SolarSeason

        self.SolarMode = Mode(self.SolarMode)
        self.SolarPumpState = bool(self.SolarFlagValues.SolarPumpState & self.SolarFlag)
        self.SolarFlushActive = bool(
            self.SolarFlagValues.SolarFlushActive & self.SolarFlag
        )
        self.SolarRoofTempValid = self.TempValidEnum(self.SolarRoofTempValid)
        self.SolarWaterTempValid = self.TempValidEnum(self.SolarWaterTempValid)
        self.SolarMessage = self.SolarMessageValues(self.SolarMessage)

    class SolarFlagValues(IntFlag):
        SolarPumpState = 1
        SolarFlushActive = 2

        def __str__(self):
            return self.name

    class SolarMessageValues(Enum):
        DisplayNothing = 0
        Standby = 1
        SolarHeatingActive = 2
        SolarFlushActive = 3
        SolarExcPerActive = 4
        SolarSystemflushed = 5
        PumpWillRunFor = 6

        def __str__(self):
            return self.name

    class TempValidEnum(Enum):
        Invalid = 0
        IsValid = 1
        WasValid = 2

        def __str__(self):
            return self.name


class GPOSetupCharacteristic:
    def __init__(self, data, fmt="<BBBBBBB"):
        (
            device_type_val,
            self.Index,
            outlet_enabled,
            gpo_function_val,
            gpo_name_val,
            gpo_lighting_zone,
            use_timers,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        # Convert enum values to meaningful names
        gpo_function = self.GPOFunctionValues(gpo_function_val)
        gpo_name = self.GPONameValues(gpo_name_val)

        # Custom logic for base attribute name
        base_attr_number = self.get_base_attr_number(device_type_val, self.Index)

        # Dynamically set attributes
        setattr(self, f"GPO{base_attr_number}_OutletEnabled", outlet_enabled)
        setattr(self, f"GPO{base_attr_number}_Function", gpo_function)
        setattr(self, f"GPO{base_attr_number}_Name", gpo_name)
        setattr(self, f"GPO{base_attr_number}_LightingZone", gpo_lighting_zone)
        setattr(self, f"GPO{base_attr_number}_UseTimers", use_timers)

    def get_base_attr_number(self, device_type, index):
        if device_type == self.GPODeviceTypeValues.Connect1.value:
            return 1 + index
        elif device_type == self.GPODeviceTypeValues.Connect2.value:
            return 3 + index
        else:
            return 0  # or other logic for non-Connect device types

    class GPODeviceTypeValues(Enum):
        FilterPump = 0
        PHProbe = 1
        OrpProbe = 2
        Heater = 3
        Light1 = 4
        Light2 = 5
        LightFAB = 6
        Connect1 = 7
        Connect2 = 8

        def __str__(self):
            return self.name

    class GPOFunctionValues(Enum):
        Equipment = 0
        Lighting = 1
        Solar = 2
        Heating = 3

        def __str__(self):
            return self.name

    class GPONameValues(Enum):
        NoName = 0
        Other = 1
        CleaningPump = 2
        HeaterPump = 3
        BoosterPump = 4
        WaterfallPump = 5
        FountainPump = 6
        Blower = 7
        Jets = 8

        def __str__(self):
            return self.name


class RelaySetupCharacteristic:
    def __init__(self, data, fmt="<BBBBB"):
        (
            self.Index,
            relay_enabled,
            relay_name_val,
            relay_action,
            use_timers,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        # Convert relay name byte to RelayNameValue enum
        relay_name = self.RelayNameValue(relay_name_val)

        # Dynamically set attributes based on the Index
        setattr(self, f"Relay{self.Index + 1}_Name", relay_name)
        setattr(self, f"Relay{self.Index + 1}_Enabled", relay_enabled)
        setattr(self, f"Relay{self.Index + 1}_Action", relay_action)
        setattr(self, f"Relay{self.Index + 1}_UseTimers", use_timers)

    class RelayNameValue(Enum):
        Relay1 = 0
        Relay2 = 1

        def __str__(self):
            return self.name


class ValveSetupCharacteristic:
    def __init__(self, data, fmt="<BBBB"):
        (
            self.Index,
            valve_enabled,
            valve_name_val,
            use_timers,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        # Convert valve name byte to ValveNameValue enum
        valve_name = self.ValveNameValue(valve_name_val)

        # Dynamically set attributes based on the Index
        setattr(self, f"Valve{self.Index + 1}_Name", valve_name)
        setattr(self, f"Valve{self.Index + 1}_Enabled", valve_enabled)
        setattr(self, f"Valve{self.Index + 1}_UseTimers", use_timers)

    class ValveNameValue(Enum):
        NoneValue = 0
        Other = 1
        Pool = 2
        Spa = 3
        WaterFeature = 4
        Waterfall = 5

        def __str__(self):
            return self.name


class GPOCustomNameStruct:
    def __init__(self, data, fmt="<BBBB12s"):
        # Format: 4 bytes followed by a 12-byte string
        (
            self.DeviceType,
            self.Index,
            self.MessageNumber,
            self.CustomNameLength,
            self.CustomNameFragment,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        # Decode the custom name fragment, removing any null bytes
        self.CustomNameFragment = self.CustomNameFragment.decode("utf-8").rstrip("\x00")


class RelayCustomNameStruct:
    def __init__(self, data, fmt="<BBB13s"):
        # Format: 4 bytes followed by a 12-byte string
        (
            self.Index,
            self.MessageNumber,
            self.CustomNameLength,
            self.CustomNameFragment,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        # Decode the custom name fragment, removing any null bytes
        self.CustomNameFragment = self.CustomNameFragment.decode("utf-8").rstrip("\x00")


class ValveCustomNameStruct:
    def __init__(self, data, fmt="<BBB13s"):
        # Format: 4 bytes followed by a 12-byte string
        (
            self.Index,
            self.MessageNumber,
            self.CustomNameLength,
            self.CustomNameFragment,
        ) = struct.unpack(fmt, data[: struct.calcsize(fmt)])

        # Decode the custom name fragment, removing any null bytes
        self.CustomNameFragment = self.CustomNameFragment.decode("utf-8").rstrip("\x00")


class DeviceProtocol(Enum):
    """ScanResponse Device Protocol"""

    Unknown = -1
    Protocol0 = 0
    Firmware57 = 1
    NextGen = 2

    def __str__(self):
        return self.name


class Mode(Enum):
    Off = 0
    Auto = 1
    On = 2

    def __str__(self):
        return self.name


class GPOMode(Enum):
    Off = 0
    Auto = 1
    On = 2
    NotEnabled = 255

    def __str__(self):
        return self.name
