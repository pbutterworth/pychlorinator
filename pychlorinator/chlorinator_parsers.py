"""protocol parsers and types for chlorinator API"""

import datetime
import struct
from enum import Enum, IntFlag, IntEnum


class ChlorinatorActions(IntEnum):
    NoAction = 0
    Off = 1
    Auto = 2
    Manual = 3
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


class Modes(Enum):
    """Mode enum"""

    Off = 0
    ManualOn = 1
    Auto = 2

    def __str__(self):
        return self.name


class SpeedLevels(Enum):
    """Speed levels enum"""

    Low = 0
    Medium = 1
    High = 2
    AI = 3
    NotSet = -1

    def __str__(self):
        return self.name


class InfoMessages(Enum):
    """Information messages enum"""

    NoMessage = 0
    PhProbeNoComms = 1
    PhProbeOtherError = 2
    PhProbeCleanCalibrate = 3
    OrpProbeNoComms = 4
    OrpProbeOtherError = 5
    OrpProbeCleanCalibrate = 6
    G4CommsFailure = 7
    NoWaterFlow = 8
    RtccFault = 128
    OrpProbeFittedPhProbeMissing = 129
    AiPumpSpeed = 130
    LowSalt = 131
    Unspecified = 132
    WARNING_LEVEL_IF_EQUAL_OR_GREATER_THAN_THIS_VALUE = 128

    def __str__(self):
        return self.name


class ChlorineControlStatuses(Enum):
    """Chlorine control status enum"""

    Unknown = -1
    Invalid_NoMeasurement = 0
    VeryVeryLow = 1
    VeryLow = 2
    Low = 3
    Ok = 4
    High = 5
    VeryHigh = 6
    VeryVeryHigh = 7

    def __str__(self):
        return self.name


class SetupFlags(IntFlag):
    """Setup flags bit masks"""

    NoTimerModel = 1
    TimerMasterIsPresentInSystem = 2

    def __str__(self):
        return self.name


class StateFlags(IntFlag):
    """State flags bit masks"""

    ChemistryValuesCurrent = 1
    ChemsitryValuesValid = 2
    SpaSelection = 4
    PumpIsPriming = 8
    PumpIsOperating = 0x10
    CellIsOperating = 0x20
    UserSettingsHasChanged = 0x40
    SanitisingUntilNextTimerTomorrow = 0x80

    def __str__(self):
        return self.name


class PhControlTypes(Enum):
    """pH control types enum"""

    NoPhControl = 0
    Manual = 1
    Automatic = 2

    def __str__(self):
        return self.name


class ChlorineControlTypes(Enum):
    """Chlorine control types enum"""

    NoChloringControl = 0
    Manual = 1
    Automatic = 2

    def __str__(self):
        return self.name


class VolumeUnitsTypes(Enum):
    """Volume units enum"""

    Litres = 0
    UsGallons = 1
    ImperialGallons = 2

    def __str__(self):
        return self.name


class CapabilitiesFlags(IntFlag):
    """Capabilities flags bit masks"""

    ThreespeedPumpEnabled = 1
    AiModeEnabled = 2
    VolumeUnitMask = 0xC
    VolumeUnitLitres = 0
    VolumeUnitUsGallons = 4
    VolumeUnitImperialgallons = 8
    LightingEnabled = 0x10
    DosingCapableUnit = 0x20


class AcidDosingInhibitStatuses(Enum):
    """Acid dosing inhibit status enum"""

    NotInhibited = 0
    InhibitedIndefinitely = 1
    InhibitedForAPeriod = 2

    def __str__(self):
        return self.name


class TimerFlags(IntFlag):
    """Timer flags bit masks"""

    StartHourMask = 0x1F
    TimerEnabled = 0x20
    SpeelLevelMask = 0xC0


NUMBER_OF_PUMP_TIMERS_SUPPORTED = 4


class PumpTimer:
    """Represent a single pump timer"""

    enabled = False
    start_time = datetime.timedelta()
    stop_time = datetime.timedelta()
    speed_level = SpeedLevels.NotSet

    def is_invalid(self):
        """Logical test to check that timer parameters are valid"""
        if not self.enabled:
            return False
        if self.start_time > datetime.timedelta(
            days=1
        ) or self.stop_time > datetime.timedelta(days=1):
            return True
        if self.start_time >= self.stop_time:
            return True
        if self.speed_level == SpeedLevels.NotSet:
            return True
        return False


class ChlorinatorAction:
    """Represent an action command"""

    # period_minutes only used for setting ChlorinatorActions:DisableAcidDosingForPeriod

    def __init__(
        self,
        action: ChlorinatorActions = ChlorinatorActions.NoAction,
        period_minutes: int = 0,
    ) -> None:
        self.action = action
        self.period_minutes = period_minutes

    def __bytes__(self):
        fmt = "=B i 15x"
        return struct.pack(fmt, self.action, self.period_minutes)


class ChlorinatorSetup:
    """Parser class for the Chlorinator Setup characteristic"""

    fmt = "@BBHB"

    def __init__(self, data_bytes) -> None:
        fields = struct.unpack(self.fmt, data_bytes[: struct.calcsize(self.fmt)])
        (
            self.default_manual_on_speed,
            self.ph_control_setpoint,
            self.chlorine_control_setpoint,
            self.flags,
        ) = fields
        self.default_manual_on_speed = SpeedLevels(self.default_manual_on_speed)
        self.ph_control_setpoint /= 10
        self.is_no_timer_model = bool(SetupFlags.NoTimerModel & self.flags)
        self.is_timer_master_present_in_system = bool(
            SetupFlags.TimerMasterIsPresentInSystem & self.flags
        )


class ChlorinatorState:
    """Parser class for the Chlorinator State characteristic"""

    fmt = "@BBBBBBBBBBB"

    def __init__(self, data_bytes) -> None:
        fields = struct.unpack(self.fmt, data_bytes[: struct.calcsize(self.fmt)])
        (
            self.mode,
            self.pump_speed,
            self.active_timer,
            self.info_message,
            self._reserved,
            self.flags,
            self.ph_measurement,
            self.chlorine_control_status,
            self.time_hours,
            self.time_minutes,
            self.time_seconds,
        ) = fields
        self.mode = Modes(self.mode)
        self.pump_speed = SpeedLevels(self.pump_speed)
        self.info_message = InfoMessages(self.info_message)
        self.ph_measurement /= 10
        self.chlorine_control_status = ChlorineControlStatuses(
            self.chlorine_control_status
        )
        self.chemistry_values_current = bool(
            StateFlags.ChemistryValuesCurrent & self.flags
        )
        self.chemistry_values_valid = bool(StateFlags.ChemsitryValuesValid & self.flags)
        self.spa_selection = bool(StateFlags.SpaSelection & self.flags)
        self.pump_is_priming = bool(StateFlags.PumpIsPriming & self.flags)
        self.pump_is_operating = bool(StateFlags.PumpIsOperating & self.flags)
        self.cell_is_operating = bool(StateFlags.CellIsOperating & self.flags)
        self.user_settings_has_changed = bool(
            StateFlags.UserSettingsHasChanged & self.flags
        )
        self.sanitising_until_next_timer_tomorrow = bool(
            StateFlags.SanitisingUntilNextTimerTomorrow & self.flags
        )


class ChlorinatorCapabilities:
    """Parser class for the Chlorinator Capabilities characteristic"""

    fmt = "@BBBBBBBBBBBBBBB3sH"

    def __init__(self, data_bytes) -> None:
        fields = struct.unpack(self.fmt, data_bytes[: struct.calcsize(self.fmt)])
        (
            self.minimum_manual_acid_setpoint,
            self.maximum_manual_acid_setpoint,
            self.minimum_manual_chlorine_setpoint,
            self.maximum_manual_chlorine_setpoint,
            self.minimum_ph_setpoint,
            self.maximum_ph_setpoint,
            self.minimum_orp_setpoint,
            self.maximum_orp_setpoint,
            self.ph_control_type,
            self.chlorine_control_type,
            self.flags,
            self.cell_size,
            self.acid_pump_size,
            self.filter_pump_size,
            self.reversal_period,
            self.pool_volume,
            self.spa_volume,
        ) = fields

        self.minimum_ph_setpoint /= 10
        self.maximum_ph_setpoint /= 10
        self.minimum_orp_setpoint *= 10
        self.maximum_orp_setpoint *= 10
        self.ph_control_type = PhControlTypes(self.ph_control_type)
        self.chlorine_control_type = ChlorineControlTypes(self.chlorine_control_type)
        self.threespeed_pump_enabled = bool(
            CapabilitiesFlags.ThreespeedPumpEnabled & self.flags
        )
        self.ai_mode_enabled = bool(CapabilitiesFlags.AiModeEnabled & self.flags)

        if CapabilitiesFlags.VolumeUnitMask & self.flags:
            if CapabilitiesFlags.VolumeUnitUsGallons & self.flags:
                self.volume_units = VolumeUnitsTypes.UsGallons
            elif CapabilitiesFlags.VolumeUnitUsGallons & self.flags:
                self.volume_units = VolumeUnitsTypes.ImperialGallons
        else:
            self.volume_units = VolumeUnitsTypes.Litres

        self.lighting_enabled = bool(CapabilitiesFlags.LightingEnabled & self.flags)
        self.dosing_capable_unit = bool(
            CapabilitiesFlags.DosingCapableUnit & self.flags
        )
        self.filter_pump_size /= 10


class ChlorinatorSettings:
    """Parser class for the Chlorinator Settings characteristic"""

    fmt = "@HB"

    def __init__(self, data_bytes) -> None:
        fields = struct.unpack(self.fmt, data_bytes[: struct.calcsize(self.fmt)])
        (
            self.acid_dosing_inhibit_time_remaining,
            self.acid_dosing_inhibit_status,
        ) = fields
        self.acid_dosing_inhibit_status = AcidDosingInhibitStatuses(
            self.acid_dosing_inhibit_status
        )


class ChlorinatorStatistics:
    """Parser class for the Chlorinator Statistics characteristic"""

    fmt = "@BBHHHIIB"

    def __init__(self, data_bytes) -> None:
        fields = struct.unpack(self.fmt, data_bytes[: struct.calcsize(self.fmt)])
        (
            self.highest_ph_measured,
            self.lowest_ph_measured,
            self.highest_orp_measured,
            self.lowest_orp_measured,
            self.cell_reversal_count,
            self.cell_running_time,
            self.low_salt_cell_running_time,
            self.previous_days_cell_load,
        ) = fields

        self.highest_ph_measured /= 10
        self.lowest_ph_measured /= 10
        self.cell_running_time = datetime.timedelta(hours=self.cell_running_time)
        self.low_salt_cell_running_time = datetime.timedelta(
            hours=self.low_salt_cell_running_time
        )


class ChlorinatorTimers:
    """Parser class for the Chlorinator Timers characteristic"""

    fmt = "@BBBB"

    def __init__(self, data_bytes) -> None:
        self.pump_timers = []
        fmt_size = struct.calcsize(self.fmt)
        for i in range(NUMBER_OF_PUMP_TIMERS_SUPPORTED):
            fields = struct.unpack(
                self.fmt,
                data_bytes[i * fmt_size : (i * fmt_size + struct.calcsize(self.fmt))],
            )
            (start_hour_and_flags, start_minute, stop_hour, stop_minute) = fields

            timer = PumpTimer()
            timer.start_time = datetime.timedelta(
                hours=TimerFlags.StartHourMask & start_hour_and_flags,
                minutes=start_minute,
            )
            timer.stop_time = datetime.timedelta(hours=stop_hour, minutes=stop_minute)
            timer.enabled = bool(TimerFlags.TimerEnabled & start_hour_and_flags)
            timer.speed_level = SpeedLevels(
                (TimerFlags.SpeelLevelMask & start_hour_and_flags) >> 6
            )
            self.pump_timers.append(timer)
