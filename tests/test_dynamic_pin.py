"""Tests for Atomberg dynamic PIN and OTP generation."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
import pytest

from pyatomberg.exceptions import AtombergConnectionError
from pyatomberg.lock.dynamic_pin import AtombergDynamicPinClient


@pytest.mark.asyncio
async def test_generate_remote_otp() -> None:
    """Test generating an immediate single-use Remote OTP."""
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={
        "status": True,
        "message": {
            "data": {
                "pin": "583921",
                "device_id": "test_lock_123",
            }
        }
    })

    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
    mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)

    pin_client = AtombergDynamicPinClient(
        api_key="test_api_key",
        access_token="test_access_token",
        session=mock_session,
    )

    result = await pin_client.generate_remote_otp(
        device_id="test_lock_123",
        arrival_window_minutes=15,
    )

    assert result["otp"] == "583921"
    assert result["type"] == "remote_one_time"
    assert result["device_id"] == "test_lock_123"
    assert result["expires_at"] > result["created_at"]
    assert mock_session.post.called


@pytest.mark.asyncio
async def test_generate_timed_otp() -> None:
    """Test generating a single-use Timed OTP with custom duration."""
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={
        "status": True,
        "message": {
            "data": {
                "dynamic_pin": "992144",
                "device_id": "test_lock_456",
            }
        }
    })

    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
    mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)

    pin_client = AtombergDynamicPinClient(
        api_key="test_api_key",
        access_token="test_access_token",
        session=mock_session,
    )

    result = await pin_client.generate_timed_otp(
        device_id="test_lock_456",
        duration_hours=4.0,
        start_time=1700000000,
    )

    assert result["otp"] == "992144"
    assert result["type"] == "timed"
    assert result["device_id"] == "test_lock_456"
    assert result["created_at"] == 1700000000
    assert result["expires_at"] == 1700000000 + (4 * 3600)
    assert result["duration_hours"] == 4.0


@pytest.mark.asyncio
async def test_generate_otp_api_failure() -> None:
    """Test handling of API error response."""
    mock_response = MagicMock()
    mock_response.status = 400
    mock_response.json = AsyncMock(return_value={
        "status": False,
        "message": "Device not found or not in pairing mode",
    })

    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
    mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)

    pin_client = AtombergDynamicPinClient(
        api_key="test_api_key",
        access_token="test_access_token",
        session=mock_session,
    )

    with pytest.raises(AtombergConnectionError, match="Failed to generate lock PIN"):
        await pin_client.generate_remote_otp(device_id="invalid_lock")


def test_quantize_expiration_time() -> None:
    """Test rounding up to nearest half-hour and hour boundaries in IST."""
    import datetime
    from pyatomberg.lock.dynamic_pin import quantize_expiration_time

    tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    # Vector 1 generation at 21:31:08 IST -> 22:00:00 IST
    t1 = datetime.datetime(2026, 10, 27, 21, 31, 8, tzinfo=tz)
    assert quantize_expiration_time(t1, duration_hours=0.5) == datetime.datetime(2026, 10, 27, 22, 0, 0, tzinfo=tz)

    # Vector 2 generation at 03:50:58 IST -> 04:00:00 IST
    t2 = datetime.datetime(2026, 10, 28, 3, 50, 58, tzinfo=tz)
    assert quantize_expiration_time(t2, duration_hours=0.5) == datetime.datetime(2026, 10, 28, 4, 0, 0, tzinfo=tz)

    # Half-hour boundary at 03:12:00 IST -> 03:30:00 IST
    t3 = datetime.datetime(2026, 10, 28, 3, 12, 0, tzinfo=tz)
    assert quantize_expiration_time(t3, duration_hours=0.5) == datetime.datetime(2026, 10, 28, 3, 30, 0, tzinfo=tz)


def test_calculate_offline_otp_hardware_vectors() -> None:
    """Test offline OTP calculation against hardware verified vectors."""
    import datetime
    from pyatomberg.lock.dynamic_pin import calculate_offline_otp

    tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    auth_code = "482B2C89"
    aes_key = "AgABfsR33DdoSdMe"
    mac = "63c9c483b94a"

    # Hardware Vector 1: 2026-10-27 22:00:00 IST -> 23385749
    dt1 = datetime.datetime(2026, 10, 27, 22, 0, 0, tzinfo=tz)
    otp1 = calculate_offline_otp(auth_code=auth_code, aes_key=aes_key, target_dt=dt1, lock_mac=mac)
    assert otp1 == "23385749"
    assert len(otp1) == 8

    # Hardware Vector 2: 2026-10-28 04:00:00 IST -> 08959209
    dt2 = datetime.datetime(2026, 10, 28, 4, 0, 0, tzinfo=tz)
    otp2 = calculate_offline_otp(auth_code=auth_code, aes_key=aes_key, target_dt=dt2, lock_mac=mac)
    assert otp2 == "08959209"
    assert len(otp2) == 8


def test_calculate_offline_otp_slot_variation() -> None:
    """Test generating distinct codes for the same time period using slot indices."""
    import datetime
    from pyatomberg.lock.dynamic_pin import calculate_offline_otp

    tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    auth_code = "482B2C89"
    aes_key = "AgABfsR33DdoSdMe"
    mac = "63c9c483b94a"
    dt = datetime.datetime(2026, 10, 28, 4, 0, 0, tzinfo=tz)

    otp_slot0 = calculate_offline_otp(auth_code=auth_code, aes_key=aes_key, target_dt=dt, lock_mac=mac, slot_index=0)
    otp_slot1 = calculate_offline_otp(auth_code=auth_code, aes_key=aes_key, target_dt=dt, lock_mac=mac, slot_index=1)
    otp_slot2 = calculate_offline_otp(auth_code=auth_code, aes_key=aes_key, target_dt=dt, lock_mac=mac, slot_index=2)

    assert len(otp_slot0) == 8
    assert len(otp_slot1) == 8
    assert len(otp_slot2) == 8
    assert otp_slot0 != otp_slot1
    assert otp_slot1 != otp_slot2


@pytest.mark.asyncio
async def test_cloud_sync_get_dynamic_otp() -> None:
    """Test fetching active dynamic 6-digit OTP from cloud sync client."""
    from pyatomberg.lock.cloud_sync import AtombergCloudSync

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={
        "status": True,
        "message": {
            "data": {
                "otp": "482913",
            }
        }
    })

    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)

    sync = AtombergCloudSync(access_token="test_jwt_token", session=mock_session)
    res = await sync.get_dynamic_otp(device_id="63:c9:c4:83:b9:4a")

    assert res["otp"] == "482913"
    assert res["end_time"] > res["start_time"]
    assert mock_session.post.called


@pytest.mark.asyncio
async def test_fetch_cloud_history() -> None:
    """Test fetching and parsing lock history from Cloud Firestore."""
    from pyatomberg.lock.cloud_sync import AtombergCloudSync

    mock_auth_resp = MagicMock()
    mock_auth_resp.status = 200
    mock_auth_resp.json = AsyncMock(return_value={"idToken": "fake_fb_token"})

    mock_fs_resp = MagicMock()
    mock_fs_resp.status = 200
    mock_fs_resp.json = AsyncMock(return_value={
        "fields": {
            "locks": {
                "mapValue": {
                    "fields": {
                        "history": {
                            "arrayValue": {
                                "values": [
                                    {
                                        "mapValue": {
                                            "fields": {
                                                "recordTime": {"stringValue": "1792234393"},
                                                "recordType": {"stringValue": "4"},
                                                "keyType": {"stringValue": "1"},
                                                "lockKeyId": {"integerValue": "14"},
                                                "type": {"stringValue": "unlock"},
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }
    })

    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_auth_resp)
    mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_fs_resp)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    sync = AtombergCloudSync(access_token="test_token", session=mock_session)
    events = await sync.fetch_cloud_history(
        device_id="63:c9:c4:83:b9:4a",
        slot_mappings={14: "Left Thumb"},
    )

    assert len(events) == 1
    ev = events[0]
    assert ev["event"] == "Unlocked Successfully"
    assert ev["credential_type"] == "Fingerprint"
    assert "Left Thumb" in ev["detail"]
    assert ev["slot"] == 14
    assert ev["raw_timestamp"] == 1792234393
    assert ev["source"] == "cloud"



