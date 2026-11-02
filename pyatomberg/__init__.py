"""pyatomberg: Python library for Atomberg smart home authentication, discovery, and protocol codecs."""

from pyatomberg.auth.cognito import CognitoOAuthHandler
from pyatomberg.auth.developer import DeveloperTokenHandler
from pyatomberg.client import AtombergClient
from pyatomberg.exceptions import (
    AtombergAuthError,
    AtombergBLEError,
    AtombergConnectionError,
    AtombergCryptoError,
    AtombergDeviceOfflineError,
    AtombergError,
    AtombergPairingError,
)
from pyatomberg.fan.device import AtombergFan
from pyatomberg.fan.udp_listener import AtombergUDPListener
from pyatomberg.lock.cloud_sync import AtombergCloudSync
from pyatomberg.lock.hsj_protocol import (
    DEFAULT_SLOT_MAPPINGS,
    LiveEvent,
    build_hsj_packet,
    format_ist_time,
    parse_hsj_packet,
    parse_live_event,
    parse_log_record,
    slot_name,
)
from pyatomberg.lock.pairing import (
    PairingResult,
    extract_keys_from_btsnoop,
)
from pyatomberg.models.device import (
    AtombergDeviceModel,
    DeviceType,
    FanState,
    LockState,
    WaterPurifierState,
)

__version__ = "0.1.0"

__all__ = [
    "PairingResult",
    "extract_keys_from_btsnoop",
    "AtombergCloudSync",
    "LiveEvent",
    "build_hsj_packet",
    "parse_hsj_packet",
    "parse_live_event",
    "parse_log_record",
    "slot_name",
    "format_ist_time",
    "DEFAULT_SLOT_MAPPINGS",
    "AtombergClient",
    "AtombergFan",
    "AtombergUDPListener",
    "DeveloperTokenHandler",
    "CognitoOAuthHandler",
    "AtombergError",
    "AtombergAuthError",
    "AtombergConnectionError",
    "AtombergDeviceOfflineError",
    "AtombergBLEError",
    "AtombergCryptoError",
    "AtombergPairingError",
    "AtombergDeviceModel",
    "DeviceType",
    "FanState",
    "LockState",
    "WaterPurifierState",
]
