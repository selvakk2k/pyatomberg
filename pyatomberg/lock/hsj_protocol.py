"""Haosj (HSJ) BLE protocol implementation for Atomberg SL1 / SL1 Pro smart locks.

Based on protocol reverse engineering by dreadedlama (https://github.com/dreadedlama/atomberg-lock)
under GNU General Public License v3.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import time
from typing import Any
from zoneinfo import ZoneInfo

from pyatomberg.const import HSJ_FACTORY_KEY, HSJ_HEADER
from pyatomberg.crypto import calculate_modbus_crc16, decrypt_aes_ecb, encrypt_aes_ecb
from pyatomberg.exceptions import AtombergCryptoError

_LOGGER = logging.getLogger(__name__)

# Characteristic UUIDs
WRITE_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"

# Opcodes
OP_PROBE_HANDSHAKE = bytes.fromhex("00f0")
OP_KEY_EXCHANGE = bytes.fromhex("00f1")
OP_CONTEXT_SYNC = bytes.fromhex("00f2")
OP_TIME_SYNC = bytes.fromhex("0007")
OP_UNLOCK = bytes.fromhex("0001")
OP_BATTERY = bytes.fromhex("000d")
OP_LOG_COUNT = bytes.fromhex("0008")
OP_LOG_PAGE = bytes.fromhex("0009")
OP_LIVE_EVENT = 0x000A

DEFAULT_SLOT_MAPPINGS: dict[int, str] = {}


def slot_name(slot: int, slot_mappings: dict[int, str] | None = None) -> str:
    """Resolve slot ID to user friendly name."""
    mappings = slot_mappings or DEFAULT_SLOT_MAPPINGS
    return mappings.get(slot, f"Slot {slot}")


def format_ist_time(ts: int) -> str:
    """Format Unix timestamp to IST date string."""
    from datetime import timedelta

    try:
        ist_tz = timezone(timedelta(hours=5, minutes=30))
        return (
            datetime.fromtimestamp(ts, timezone.utc)
            .astimezone(ist_tz)
            .strftime("%Y-%m-%d %I:%M:%S %p")
        )
    except Exception:
        return "N/A"


def build_hsj_packet(payload: bytes, key: bytes, frame_seq: int = 2) -> bytes:
    """Construct an encrypted HSJ protocol frame.

    Packet format:
      [HSJ Header (3B)] + [Total Len (2B BE)] + [Frame Seq (2B BE)]
      + [Encrypted Payload (NB)] + [CRC16 (2B BE)]
    """
    encrypted = encrypt_aes_ecb(payload, key, pad=True)
    total_len = 3 + 2 + 2 + len(encrypted) + 2

    header = (
        HSJ_HEADER
        + total_len.to_bytes(2, byteorder="big")
        + frame_seq.to_bytes(2, byteorder="big")
    )
    body = header + encrypted
    crc = calculate_modbus_crc16(body)
    return body + crc.to_bytes(2, byteorder="big")


def parse_hsj_packet(frame: bytes, key: bytes) -> bytes:
    """Validate and decrypt an incoming HSJ frame.

    Returns the decrypted plaintext payload.
    """
    if len(frame) < 9:
        raise AtombergCryptoError(f"Frame too short: {len(frame)} bytes")

    if not frame.startswith(HSJ_HEADER):
        raise AtombergCryptoError(f"Invalid HSJ header: {frame[:3]!r}")

    declared_len = int.from_bytes(frame[3:5], byteorder="big")
    if declared_len != len(frame):
        raise AtombergCryptoError(
            f"Frame length mismatch: declared {declared_len}, received {len(frame)}"
        )

    body = frame[:-2]
    received_crc = int.from_bytes(frame[-2:], byteorder="big")
    expected_crc = calculate_modbus_crc16(body)
    if received_crc != expected_crc:
        raise AtombergCryptoError(
            f"Modbus CRC mismatch: expected 0x{expected_crc:04X}, received 0x{received_crc:04X}"
        )

    ciphertext = frame[7:-2]
    return decrypt_aes_ecb(ciphertext, key, unpad=True)


@dataclass
class LiveEvent:
    """Structured live event received over unsolicited 0x000A notification."""
    battery: int
    event: str
    credential_type: str
    slot_id: int
    pin_code: str
    timestamp: str
    raw_timestamp: int
    is_unlocked: bool = False
    is_auto_lock: bool = False
    is_tamper: bool = False


def parse_live_event(dec: bytes, slot_mappings: dict[int, str] | None = None) -> LiveEvent | None:
    """Parse real-time live notification payload (opcode 0x000A)."""
    if len(dec) < 20:
        return None

    cmd_id = (dec[5] << 8) | dec[6]
    if cmd_id != OP_LIVE_EVENT:
        return None

    battery = dec[13]
    event_cat = dec[15]
    ts = (dec[16] << 24) | (dec[17] << 16) | (dec[18] << 8) | dec[19]

    event_name = ""
    cred_type_name = ""
    pin_str = ""
    slot_id = 0
    is_unlocked = False
    is_auto_lock = False
    is_tamper = False

    # 0x36: Access Denied / Tamper Attempt
    if event_cat == 0x36:
        is_tamper = True
        event_name = "False / Denied Attempt"
        fail_cred = dec[22] if len(dec) > 22 else 0
        if fail_cred == 0x01:
            cred_type_name = "Unregistered Fingerprint"
        elif fail_cred == 0x02:
            cred_type_name = "Wrong Keypad PIN"
            pin_len = dec[26] if len(dec) > 26 else 0
            if 0 < pin_len <= 16 and len(dec) >= (27 + pin_len):
                pin_str = dec[27 : 27 + pin_len].decode("ascii", errors="ignore")
        elif fail_cred == 0x04:
            cred_type_name = "Unregistered NFC Card"
        else:
            cred_type_name = "Rejected Credential"

    # 0x3D: Auto-Lock / Latch Engaged
    elif event_cat == 0x3D:
        is_auto_lock = True
        event_name = "Auto-Lock / Latch"
        cred_type_name = "System Auto-Lock"

    # 0x04: Unlocked Successfully
    elif event_cat == 0x04:
        is_unlocked = True
        event_name = "Unlocked Successfully"
        cred_type = dec[22] if len(dec) > 22 else 0
        slot_id = ((dec[23] << 8) | dec[24]) if len(dec) > 24 else 0

        if cred_type == 0x01:
            cred_type_name = "Fingerprint"
        elif cred_type == 0x04:
            cred_type_name = "NFC Card"
        elif cred_type == 0x02:
            cred_type_name = "PIN Code"
            pin_len = dec[32] if len(dec) > 32 else 0
            if 0 < pin_len <= 16 and len(dec) >= (33 + pin_len):
                pin_str = dec[33 : 33 + pin_len].decode("ascii", errors="ignore")
        elif cred_type == 0x00 or slot_id == 0:
            cred_type_name = "Atomberg App"
        else:
            cred_type_name = "Other Credential"

    return LiveEvent(
        battery=battery,
        event=event_name,
        credential_type=cred_type_name,
        slot_id=slot_id,
        pin_code=pin_str if pin_str else "N/A",
        timestamp=format_ist_time(ts),
        raw_timestamp=ts,
        is_unlocked=is_unlocked,
        is_auto_lock=is_auto_lock,
        is_tamper=is_tamper,
    )


def parse_log_record(rec: bytes, slot_mappings: dict[int, str] | None = None) -> dict[str, Any]:
    """Parse 32-byte hardware event log record."""
    if len(rec) != 32:
        raise ValueError(f"Expected 32-byte record, got {len(rec)}")

    ts = int.from_bytes(rec[0:4], "big")
    event_cat = rec[4]
    battery = rec[5]
    user_id = int.from_bytes(rec[7:9], "big")
    cred_type = rec[9]
    slot_id = int.from_bytes(rec[10:12], "big")

    event = "Hardware Event"
    cred_type_name = ""
    detail = ""
    pin_str = ""
    slot = slot_id

    if event_cat == 0x36:
        event = "False / Denied Attempt"
        if cred_type == 0x01:
            cred_type_name = "Unregistered Fingerprint"
            detail = "Unregistered Fingerprint"
        elif cred_type == 0x02:
            cred_type_name = "Wrong Keypad PIN"
            pin_len = rec[26] if len(rec) > 26 else 0
            if 0 < pin_len <= 12 and len(rec) >= (27 + pin_len):
                pin_str = rec[27 : 27 + pin_len].decode("latin1", errors="ignore")
            detail = f"Wrong Keypad PIN: {pin_str}" if pin_str else "Wrong Keypad PIN"
        elif cred_type == 0x04:
            cred_type_name = "Unregistered NFC Card"
            detail = "Unregistered NFC Card"
        else:
            cred_type_name = "Rejected Credential"
            detail = f"Rejected Credential Type 0x{cred_type:02X}"

    elif event_cat == 0x04:
        event = "Unlocked Successfully"
        if b"MX" in rec[18:]:
            cred_type_name = "Atomberg App"
            detail = "Atomberg Mobile App (BLE)"
        elif cred_type == 0x01:
            cred_type_name = "Fingerprint"
            detail = f"Unlocked by - {slot_name(slot, slot_mappings)}"
        elif cred_type == 0x04:
            card_uid = rec[18:22].hex()
            cred_type_name = "NFC Card"
            detail = f"Unlocked by - {slot_name(slot, slot_mappings)} (UID {card_uid})"
        elif cred_type == 0x02:
            cred_type_name = "PIN Code"
            code_str = rec[18:24].decode("latin1", errors="ignore").rstrip("\x00")
            pin_str = code_str
            detail = f"Unlocked by - PIN: {code_str}" if code_str else "Unlocked by - PIN"
        elif cred_type == 0x00 or slot == 0:
            cred_type_name = "Atomberg App"
            detail = "Unlocked by - Atomberg App"
        else:
            cred_type_name = f"Credential 0x{cred_type:02X}"
            detail = f"Unlocked by - {slot_name(slot, slot_mappings)}"

    elif event_cat == 0x37:
        event = "Unlocked (Manual)"
        cred_type_name = "Physical Thumbturn"
        detail = "Unlocked by - Physical Thumbturn"
        slot = 0

    elif event_cat == 0x08:
        event = "Credential Enrolled"
        cred_type_name = "Credential Enrollment"
        slot = int.from_bytes(rec[11:13], "big")
        detail = f"Enrolled - {slot_name(slot, slot_mappings)}"

    elif event_cat == 0x3D:
        event = "Auto-Lock / Latch"
        cred_type_name = "System Auto-Lock"
        detail = "Auto-Lock / Latch Engaged"
        slot = 0

    return {
        "datetime": format_ist_time(ts),
        "event": event,
        "detail": detail,
        "battery": battery,
        "credential_type": cred_type_name,
        "slot": slot,
        **({"pin": pin_str} if pin_str else {}),
    }
