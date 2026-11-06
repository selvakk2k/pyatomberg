"""Tests for Haosj (HSJ) BLE protocol framing, live event parsing, and log decoding."""

import pytest
from pyatomberg.const import HSJ_FACTORY_KEY
from pyatomberg.exceptions import AtombergCryptoError
from pyatomberg.lock.hsj_protocol import (
    build_hsj_packet,
    format_ist_time,
    parse_hsj_packet,
    parse_live_event,
    parse_log_record,
    slot_name,
)


def test_hsj_packet_roundtrip():
    """Verify build_hsj_packet and parse_hsj_packet roundtrip integrity."""
    payload = b"SampleLockPayload12345"
    packet = build_hsj_packet(payload, key=HSJ_FACTORY_KEY, frame_seq=2)

    assert packet.startswith(b"HSJ")
    assert len(packet) > 9

    decrypted = parse_hsj_packet(packet, key=HSJ_FACTORY_KEY)
    assert decrypted == payload


def test_hsj_packet_corrupted_crc():
    """Verify CRC mismatch raises AtombergCryptoError."""
    payload = b"ValidPayload"
    packet = bytearray(build_hsj_packet(payload, key=HSJ_FACTORY_KEY))

    # Corrupt last byte (CRC)
    packet[-1] ^= 0xFF

    with pytest.raises(AtombergCryptoError, match="Modbus CRC mismatch"):
        parse_hsj_packet(bytes(packet), key=HSJ_FACTORY_KEY)


def test_hsj_packet_invalid_header():
    """Verify missing HSJ header raises AtombergCryptoError."""
    with pytest.raises(AtombergCryptoError, match="Invalid HSJ header"):
        parse_hsj_packet(b"XYZ\x00\x19\x00\x02" + b"\x00" * 16 + b"\x00\x00", key=HSJ_FACTORY_KEY)


def test_hsj_packet_wrong_key():
    """Verify decryption with wrong key raises AtombergCryptoError."""
    payload = b"SecretUnlockPayload"
    packet = build_hsj_packet(payload, key=HSJ_FACTORY_KEY)

    wrong_key = b"0123456789ABCDEF"
    with pytest.raises(AtombergCryptoError):
        parse_hsj_packet(packet, key=wrong_key)


def test_parse_live_event_unlock():
    """Verify parse_live_event for successful unlock (0x04) via fingerprint."""
    # Build a simulated 0x000A live notification decrypted payload
    # dec[5:7] = 0x000A
    # dec[13] = battery (85%)
    # dec[15] = event_cat (0x04)
    # dec[16:20] = timestamp
    # dec[22] = credential_type (0x01 = fingerprint)
    # dec[23:25] = slot_id (17 = Left Thumb)
    dec = bytearray(30)
    dec[5] = 0x00
    dec[6] = 0x0A
    dec[13] = 85
    dec[15] = 0x04
    dec[16:20] = (1700000000).to_bytes(4, "big")
    dec[22] = 0x01
    dec[23] = 0x00
    dec[24] = 17

    event = parse_live_event(bytes(dec))
    assert event is not None
    assert event.is_unlocked is True
    assert event.battery == 85
    assert event.credential_type == "Fingerprint"
    assert event.slot_id == 17
    assert event.raw_timestamp == 1700000000


def test_parse_live_event_tamper():
    """Verify parse_live_event for false attempt (0x36) with wrong PIN."""
    dec = bytearray(35)
    dec[5] = 0x00
    dec[6] = 0x0A
    dec[13] = 90
    dec[15] = 0x36
    dec[16:20] = (1700000000).to_bytes(4, "big")
    dec[22] = 0x02  # Wrong Keypad PIN
    dec[26] = 6     # PIN length
    dec[27:33] = b"123456"

    event = parse_live_event(bytes(dec))
    assert event is not None
    assert event.is_tamper is True
    assert event.credential_type == "Wrong Keypad PIN"
    assert event.pin_code == "123456"


def test_parse_live_event_auto_lock():
    """Verify parse_live_event for auto-lock latch engaged (0x3D)."""
    dec = bytearray(25)
    dec[5] = 0x00
    dec[6] = 0x0A
    dec[13] = 95
    dec[15] = 0x3D
    dec[16:20] = (1700000000).to_bytes(4, "big")

    event = parse_live_event(bytes(dec))
    assert event is not None
    assert event.is_auto_lock is True
    assert event.is_unlocked is False


def test_parse_log_record():
    """Verify parsing of 32-byte hardware event record."""
    rec = bytearray(32)
    rec[0:4] = (1700000000).to_bytes(4, "big")  # ts
    rec[4] = 0x04                               # event_cat (unlock)
    rec[5] = 88                                 # battery
    rec[7:9] = (1).to_bytes(2, "big")           # user_id
    rec[9] = 0x01                               # fingerprint
    rec[10:12] = (20).to_bytes(2, "big")        # slot_id (Right Thumb)

    parsed = parse_log_record(bytes(rec), slot_mappings={20: "Right Thumb"})
    assert parsed["battery"] == 88
    assert parsed["event"] == "Unlocked Successfully"
    assert "Right Thumb" in parsed["detail"]
    assert parsed["slot"] == 20


def test_parse_log_record_tamper_pin():
    """Verify parsing of 32-byte log record for wrong PIN attempt."""
    rec = bytearray(32)
    rec[0:4] = (1700000000).to_bytes(4, "big")
    rec[4] = 0x36
    rec[5] = 90
    rec[7:9] = (0).to_bytes(2, "big")
    rec[9] = 0x02
    rec[10:12] = (0).to_bytes(2, "big")
    rec[26] = 5
    rec[27:32] = b"98765"

    parsed = parse_log_record(bytes(rec))
    assert parsed["event"] == "False / Denied Attempt"
    assert parsed["credential_type"] == "Wrong Keypad PIN"
    assert "98765" in parsed["detail"]
