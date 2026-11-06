"""Tests for AtombergClient and fan state synchronization."""

import pytest
from pyatomberg.auth.developer import DeveloperTokenHandler
from pyatomberg.client import AtombergClient
from pyatomberg.exceptions import AtombergAuthError
from pyatomberg.fan.device import AtombergFan


def test_client_init_validation():
    """Verify client rejects initialization without auth."""
    with pytest.raises(AtombergAuthError, match="must be provided"):
        AtombergClient()

    client = AtombergClient(developer_token="sample_dev_token", api_key="sample_api_key")
    assert isinstance(client.auth_handler, DeveloperTokenHandler)
    assert client.auth_handler.refresh_token == "sample_dev_token"
    assert client.auth_handler.api_key == "sample_api_key"


def test_fan_state_update_from_udp():
    """Verify local UDP packet automatically updates fan state."""
    client = AtombergClient(developer_token="token123")
    fan = AtombergFan(
        device_id="ab_fan_room1",
        name="Living Room Fan",
        client=client,
    )
    client.fans["ab_fan_room1"] = fan

    callback_called = False

    def on_fan_change(updated_fan: AtombergFan):
        nonlocal callback_called
        callback_called = True

    fan.register_callback(on_fan_change)

    # Simulate arrival of UDP packet payload
    packet = {
        "device_id": "ab_fan_room1",
        "power": 1,
        "speed": 5,
        "sleep": 1,
        "timer": 2,
    }
    client._handle_udp_state("ab_fan_room1", packet)

    assert fan.state.power is True
    assert fan.state.speed == 5
    assert fan.state.sleep is True
    assert fan.state.timer_hours == 2
    assert callback_called is True


@pytest.mark.asyncio
async def test_cloud_sync_parsing():
    """Verify AtombergCloudSync correctly parses production app_open response."""
    from unittest.mock import AsyncMock, MagicMock
    from pyatomberg.lock.cloud_sync import AtombergCloudSync

    mock_resp_data = {
        "status": "Success",
        "message": {
            "user_details": {
                "families": [
                    {
                        "family_id": "test_fam_1",
                        "devices": [
                            {
                                "device_id": "63c9c483b94a",
                                "friendly_name": "Entrance Lock",
                                "model": "smart_lock_black",
                                "metadata": {
                                    "adminAuthCode": "00A00EC9",
                                    "aes": "AgABfsR33DdoSdMe",
                                    "bleProtocolVersion": "32",
                                    "description": "Smart Lock",
                                    "generalAuthCode": "482B2C89",
                                    "lockMac": "63c9c483b94a",
                                    "tempAuthCode": "04820A68",
                                },
                            }
                        ],
                    }
                ]
            }
        },
    }

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=mock_resp_data)

    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    client = AtombergCloudSync(access_token="test_access_token", session=mock_session)
    locks = await client.fetch_account_locks()

    assert len(locks) == 1
    lock = locks[0]
    assert lock.mac_address == "63:C9:C4:83:B9:4A"
    assert lock.name == "Entrance Lock"
    assert lock.model == "smart_lock_black"
    assert lock.master_key == b"AgABfsR33DdoSdMe"
    assert lock.salt == bytes.fromhex("00A00EC9")


def test_client_init_with_cognito_handler():
    """Verify client initializes with CognitoOAuthHandler."""
    from pyatomberg.auth.cognito import CognitoOAuthHandler

    cognito = CognitoOAuthHandler(client_id="test_client", access_token="test_tok")
    client = AtombergClient(cognito_handler=cognito)
    assert client.auth_handler is cognito


@pytest.mark.asyncio
async def test_cloud_sync_skips_malformed_lock():
    """Verify fetch_account_locks skips malformed device without aborting valid ones."""
    from unittest.mock import AsyncMock, MagicMock
    from pyatomberg.lock.cloud_sync import AtombergCloudSync

    mock_resp_data = {
        "message": {
            "user_details": {
                "families": [
                    {
                        "devices": [
                            {"metadata": None, "device_id": "bad_dev"},
                            {
                                "device_id": "good_dev",
                                "name": "Good Lock",
                                "metadata": {
                                    "aes": "AgABfsR33DdoSdMe",
                                    "adminAuthCode": "00A00EC9",
                                    "lockMac": "63c9c483b94a",
                                },
                            },
                        ]
                    }
                ]
            }
        }
    }
    mock_resp = MagicMock(status=200, json=AsyncMock(return_value=mock_resp_data))
    mock_session = MagicMock(closed=False)
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    client = AtombergCloudSync(access_token="tok", session=mock_session)
    locks = await client.fetch_account_locks()
    assert len(locks) == 1
    assert locks[0].name == "Good Lock"


@pytest.mark.asyncio
async def test_cloud_history_empty_firebase_token():
    """Verify fetch_cloud_history does not send Cognito token to Firestore when Firebase auth fails."""
    from unittest.mock import AsyncMock, MagicMock
    from pyatomberg.lock.cloud_sync import AtombergCloudSync

    mock_auth_resp = MagicMock(status=400, json=AsyncMock(return_value={}))
    mock_session = MagicMock(closed=False)
    mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_auth_resp)
    mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)

    client = AtombergCloudSync(access_token="cognito_secret_token", session=mock_session)
    events = await client.fetch_cloud_history("63c9c483b94a")
    assert events == []
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_request_401_retry_developer_token():
    """Verify 401 response triggers token refresh and single retry for DeveloperTokenHandler."""
    from unittest.mock import AsyncMock, MagicMock
    from pyatomberg.auth.developer import DeveloperTokenHandler
    from pyatomberg.client import AtombergClient

    auth = DeveloperTokenHandler("dev_refresh_tok")
    auth.get_auth_headers = AsyncMock(return_value={"Authorization": "Bearer t"})
    auth.refresh_access_token = AsyncMock(return_value="new_token")

    resp_401 = MagicMock(status=401)
    resp_200 = MagicMock(status=200, json=AsyncMock(return_value={"status": True, "devices": []}))

    session = MagicMock(closed=False)
    session.request.side_effect = [
        MagicMock(__aenter__=AsyncMock(return_value=resp_401), __aexit__=AsyncMock(return_value=None)),
        MagicMock(__aenter__=AsyncMock(return_value=resp_200), __aexit__=AsyncMock(return_value=None)),
    ]

    client = AtombergClient(developer_token="dev_refresh_tok", session=session)
    client._auth_handler = auth

    data = await client._request("GET", "get_list_of_devices")
    assert data == {"status": True, "devices": []}
    auth.refresh_access_token.assert_awaited_once()


@pytest.mark.asyncio
async def test_request_401_retry_cognito():
    """Verify 401 response triggers token refresh and single retry for CognitoOAuthHandler."""
    from unittest.mock import AsyncMock, MagicMock
    from pyatomberg.auth.cognito import CognitoOAuthHandler
    from pyatomberg.client import AtombergClient

    auth = CognitoOAuthHandler(client_id="cid", refresh_token="cog_refresh_tok")
    auth.get_auth_headers = AsyncMock(return_value={"Authorization": "Bearer t"})
    auth.refresh_tokens = AsyncMock(return_value={"access_token": "new_tok"})

    resp_401 = MagicMock(status=401)
    resp_200 = MagicMock(status=200, json=AsyncMock(return_value={"status": True, "data": []}))

    session = MagicMock(closed=False)
    session.request.side_effect = [
        MagicMock(__aenter__=AsyncMock(return_value=resp_401), __aexit__=AsyncMock(return_value=None)),
        MagicMock(__aenter__=AsyncMock(return_value=resp_200), __aexit__=AsyncMock(return_value=None)),
    ]

    client = AtombergClient(cognito_handler=auth, session=session)

    data = await client._request("GET", "get_list_of_devices")
    assert data == {"status": True, "data": []}
    auth.refresh_tokens.assert_awaited_once()


@pytest.mark.asyncio
async def test_request_consecutive_401_raises_auth_error():
    """Verify second consecutive 401 response aborts and raises AtombergAuthError without looping."""
    from unittest.mock import AsyncMock, MagicMock
    from pyatomberg.auth.developer import DeveloperTokenHandler
    from pyatomberg.client import AtombergClient
    from pyatomberg.exceptions import AtombergAuthError

    auth = DeveloperTokenHandler("dev_refresh_tok")
    auth.get_auth_headers = AsyncMock(return_value={"Authorization": "Bearer t"})
    auth.refresh_access_token = AsyncMock(return_value="new_token")

    resp_401 = MagicMock(status=401)

    session = MagicMock(closed=False)
    session.request.return_value.__aenter__ = AsyncMock(return_value=resp_401)
    session.request.return_value.__aexit__ = AsyncMock(return_value=None)

    client = AtombergClient(developer_token="dev_refresh_tok", session=session)
    client._auth_handler = auth

    with pytest.raises(AtombergAuthError, match="Authentication failed \\(HTTP 401\\)"):
        await client._request("GET", "get_list_of_devices")

    assert auth.refresh_access_token.await_count == 1
    assert session.request.call_count == 2


@pytest.mark.asyncio
async def test_request_invalid_json_raises_connection_error():
    """Verify invalid JSON response raises AtombergConnectionError."""
    from unittest.mock import AsyncMock, MagicMock
    from pyatomberg.client import AtombergClient
    from pyatomberg.exceptions import AtombergConnectionError

    resp = MagicMock(status=200, json=AsyncMock(side_effect=ValueError("Malformed JSON")))
    session = MagicMock(closed=False)
    session.request.return_value.__aenter__ = AsyncMock(return_value=resp)
    session.request.return_value.__aexit__ = AsyncMock(return_value=None)

    client = AtombergClient(developer_token="tok", session=session)
    client.auth_handler.get_auth_headers = AsyncMock(return_value={"Authorization": "Bearer t"})
    with pytest.raises(AtombergConnectionError, match="Invalid JSON received"):
        await client._request("GET", "get_list_of_devices")


@pytest.mark.asyncio
async def test_request_non_dict_body_raises_connection_error():
    """Verify non-dict JSON body raises AtombergConnectionError."""
    from unittest.mock import AsyncMock, MagicMock
    from pyatomberg.client import AtombergClient
    from pyatomberg.exceptions import AtombergConnectionError

    resp = MagicMock(status=200, json=AsyncMock(return_value=["item1", "item2"]))
    session = MagicMock(closed=False)
    session.request.return_value.__aenter__ = AsyncMock(return_value=resp)
    session.request.return_value.__aexit__ = AsyncMock(return_value=None)

    client = AtombergClient(developer_token="tok", session=session)
    client.auth_handler.get_auth_headers = AsyncMock(return_value={"Authorization": "Bearer t"})
    with pytest.raises(AtombergConnectionError, match="Unexpected response structure"):
        await client._request("GET", "get_list_of_devices")


@pytest.mark.asyncio
async def test_cloud_history_hardware_event_formatting():
    """Verify hardware diagnostic events receive no unlock or app labels."""
    from unittest.mock import AsyncMock, MagicMock
    from pyatomberg.lock.cloud_sync import AtombergCloudSync

    mock_auth_resp = MagicMock(
        status=200,
        json=AsyncMock(return_value={"idToken": "fb_tok", "expiresIn": 3600}),
    )
    mock_doc = {
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
                                                "recordTime": {"stringValue": "1700000000"},
                                                "recordType": {"stringValue": "99"},
                                                "type": {"stringValue": "status_ping"},
                                                "keyType": {"stringValue": "1"},
                                                "lockKeyId": {"integerValue": 5},
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
    }
    mock_fs_resp = MagicMock(status=200, json=AsyncMock(return_value=mock_doc))

    session = MagicMock(closed=False)
    session.post.return_value.__aenter__ = AsyncMock(return_value=mock_auth_resp)
    session.post.return_value.__aexit__ = AsyncMock(return_value=None)
    session.get.return_value.__aenter__ = AsyncMock(return_value=mock_fs_resp)
    session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    client = AtombergCloudSync(access_token="tok", session=session)
    events = await client.fetch_cloud_history("63c9c483b94a")
    assert len(events) == 1
    assert events[0]["event"] == "Hardware Event"
    assert events[0]["credential_type"] == "Hardware Status"
    assert events[0]["detail"] == "System / Diagnostic Event"
    assert "Unlocked by" not in events[0]["detail"]
