"""Unified Atomberg client for device discovery, commands, and telemetry."""

import asyncio
import logging
from typing import Any

import aiohttp

from pyatomberg.auth.cognito import CognitoOAuthHandler
from pyatomberg.auth.developer import DeveloperTokenHandler
from pyatomberg.const import DEVELOPER_API_BASE
from pyatomberg.exceptions import AtombergAuthError, AtombergConnectionError
from pyatomberg.fan.device import AtombergFan
from pyatomberg.fan.udp_listener import AtombergUDPListener

_LOGGER = logging.getLogger(__name__)


class AtombergClient:
    """Unified client for Atomberg smart home devices."""

    def __init__(
        self,
        developer_token: str | None = None,
        api_key: str | None = None,
        cognito_handler: CognitoOAuthHandler | None = None,
        session: aiohttp.ClientSession | None = None,
        base_url: str = DEVELOPER_API_BASE,
        enable_udp_listener: bool = False,
    ) -> None:
        """Initialize AtombergClient."""
        self._base_url = base_url.rstrip("/")
        self._session = session
        self._owns_session = session is None
        self._fans: dict[str, AtombergFan] = {}

        if developer_token:
            self._auth_handler: DeveloperTokenHandler | CognitoOAuthHandler = (
                DeveloperTokenHandler(
                    refresh_token=developer_token,
                    api_key=api_key,
                    session=self._session,
                    base_url=self._base_url,
                )
            )
        elif cognito_handler:
            self._auth_handler = cognito_handler
        else:
            raise AtombergAuthError("Either developer_token or cognito_handler must be provided")

        self._udp_listener: AtombergUDPListener | None = None
        if enable_udp_listener:
            self._udp_listener = AtombergUDPListener(callback=self._handle_udp_state)

    @property
    def auth_handler(self) -> DeveloperTokenHandler | CognitoOAuthHandler:
        """Return the active authentication handler."""
        return self._auth_handler

    @property
    def fans(self) -> dict[str, AtombergFan]:
        """Return dictionary of known fans keyed by device_id."""
        return self._fans

    async def __aenter__(self) -> "AtombergClient":
        """Async context manager entry."""
        if self._session is None:
            self._session = aiohttp.ClientSession()
            if isinstance(self._auth_handler, DeveloperTokenHandler):
                self._auth_handler._session = self._session
        if self._udp_listener:
            await self._udp_listener.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close client sessions and background listeners."""
        if self._udp_listener and self._udp_listener.is_running:
            await self._udp_listener.stop()
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()

    def _handle_udp_state(self, device_id: str, payload: dict[str, Any]) -> None:
        """Handle real-time UDP broadcast packets received from local network."""
        fan = self._fans.get(device_id)
        if fan:
            fan.update_from_dict(payload)
            _LOGGER.debug("Updated fan %s from local UDP broadcast", device_id)
        else:
            _LOGGER.debug("Received broadcast for unregistered fan: %s", device_id)

    async def start_udp_listener(self) -> None:
        """Start local UDP broadcast listener on port 5625."""
        if not self._udp_listener:
            self._udp_listener = AtombergUDPListener(callback=self._handle_udp_state)
        await self._udp_listener.start()

    async def stop_udp_listener(self) -> None:
        """Stop local UDP broadcast listener."""
        if self._udp_listener:
            await self._udp_listener.stop()

    async def _get_session(self) -> aiohttp.ClientSession:
        """Ensure active aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
            self._owns_session = True
            if isinstance(self._auth_handler, DeveloperTokenHandler):
                self._auth_handler._session = self._session
            elif isinstance(self._auth_handler, CognitoOAuthHandler):
                self._auth_handler._session = self._session
        return self._session

    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        retry_on_auth_fail: bool = True,
    ) -> dict[str, Any]:
        """Execute an authenticated HTTP request with automatic 401 retry and error mapping."""
        session = await self._get_session()
        headers = await self._auth_handler.get_auth_headers()
        url = f"{self._base_url}/{endpoint.lstrip('/')}"

        try:
            async with session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status in (401, 403):
                    if retry_on_auth_fail and isinstance(self._auth_handler, (DeveloperTokenHandler, CognitoOAuthHandler)):
                        _LOGGER.debug(
                            "Received HTTP %s from %s, attempting token refresh and retry",
                            resp.status,
                            endpoint,
                        )
                        if isinstance(self._auth_handler, DeveloperTokenHandler):
                            await self._auth_handler.refresh_access_token()
                        else:
                            await self._auth_handler.refresh_tokens()
                        return await self._request(
                            method,
                            endpoint,
                            params=params,
                            json=json,
                            retry_on_auth_fail=False,
                        )
                    raise AtombergAuthError(f"Authentication failed (HTTP {resp.status}) for {endpoint}")

                try:
                    data = await resp.json(content_type=None)
                except (ValueError, TypeError, aiohttp.ContentTypeError) as err:
                    raise AtombergConnectionError(
                        f"Invalid JSON received from {endpoint} (HTTP {resp.status}): {err}"
                    ) from err

                if not isinstance(data, dict):
                    raise AtombergConnectionError(
                        f"Unexpected response structure from {endpoint}: expected dict, got {type(data).__name__}"
                    )

                if resp.status != 200 or not data.get("status", True):
                    error_msg = data.get("message") or f"HTTP {resp.status}"
                    raise AtombergConnectionError(f"Request to {endpoint} failed: {error_msg}")

                return data
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            raise AtombergConnectionError(f"Network error communicating with {endpoint}: {err}") from err

    async def get_fans(self, update_states: bool = True) -> list[AtombergFan]:
        """Discover and retrieve registered ceiling fans."""
        data = await self._request("GET", "get_list_of_devices")

        inner_data = data.get("data")
        devices_raw = (
            data.get("devices")
            or (inner_data.get("devices") if isinstance(inner_data, dict) else None)
            or (inner_data if isinstance(inner_data, list) else None)
            or []
        )

        discovered_fans: list[AtombergFan] = []
        for item in devices_raw:
            if not isinstance(item, dict):
                continue
            raw_id = item.get("device_id") or item.get("id")
            if not raw_id:
                continue
            device_id = str(raw_id)
            name = str(item.get("device_name") or item.get("name") or device_id)
            model_name = item.get("model") or item.get("series")

            if device_id in self._fans:
                fan = self._fans[device_id]
                fan.name = name
                fan.model_name = model_name
            else:
                fan = AtombergFan(
                    device_id=device_id,
                    name=name,
                    client=self,
                    model_name=model_name,
                    raw_data=item,
                )
                self._fans[device_id] = fan
            discovered_fans.append(fan)

        if update_states and discovered_fans:
            try:
                await self.get_device_states("all")
            except Exception as err:
                _LOGGER.warning("Could not refresh initial device states: %s", err)

        return discovered_fans

    async def get_device_states(self, device_id: str = "all") -> dict[str, Any]:
        """Query state for a specific device or all devices."""
        data = await self._request("GET", "get_device_state", params={"device_id": str(device_id)})

        state_data = data.get("data") or data.get("state") or data
        if isinstance(state_data, dict):
            # Check if multi-device dictionary or single device
            target_id = str(device_id)
            if target_id != "all" and target_id in self._fans:
                self._fans[target_id].update_from_dict(state_data)
            else:
                for d_id, d_state in state_data.items():
                    str_d_id = str(d_id)
                    if isinstance(d_state, dict) and str_d_id in self._fans:
                        self._fans[str_d_id].update_from_dict(d_state)
        elif isinstance(state_data, list):
            for d_state in state_data:
                if isinstance(d_state, dict):
                    raw_d_id = d_state.get("device_id") or d_state.get("id")
                    if raw_d_id:
                        str_d_id = str(raw_d_id)
                        if str_d_id in self._fans:
                            self._fans[str_d_id].update_from_dict(d_state)

        return data

    async def send_command(self, device_id: str, command: dict[str, Any]) -> dict[str, Any]:
        """Send control command to a device via developer API."""
        payload = {
            "device_id": str(device_id),
            "command": command,
        }
        return await self._request("POST", "send_command", json=payload)
