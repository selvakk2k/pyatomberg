"""Atomberg mobile cloud sync client for importing registered smart locks."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from typing import Any, Awaitable, Callable

import aiohttp

from pyatomberg.const import (
    FIREBASE_API_KEY,
    FIREBASE_PROJECT_ID,
    SERVER_API_BASE,
)
from pyatomberg.exceptions import AtombergAuthError, AtombergConnectionError
from pyatomberg.lock.pairing import PairingResult

_LOGGER = logging.getLogger(__name__)

_CREDENTIAL_TYPE_NAMES: dict[int, str] = {
    1: "Fingerprint",
    2: "PIN Code",
    4: "NFC Card",
}


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode JWT payload without verifying signature to read claims like exp."""
    try:
        parts = token.strip().split(".")
        if len(parts) >= 2:
            payload_b64 = parts[1]
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        pass
    return {}


class AtombergCloudSync:
    """Fetches already-paired lock encryption keys and metadata from the Atomberg mobile backend."""

    def __init__(
        self,
        access_token: str | None = None,
        id_token: str | None = None,
        refresh_token: str | None = None,
        oauth_handler: Any | None = None,
        session: aiohttp.ClientSession | None = None,
        base_url: str = SERVER_API_BASE,
        firebase_api_key: str = FIREBASE_API_KEY,
        firebase_project_id: str = FIREBASE_PROJECT_ID,
        on_token_refreshed: Callable[[str, str | None], Awaitable[None]] | None = None,
    ) -> None:
        """Initialize cloud sync client with Cognito tokens or OAuth handler."""
        token = access_token or id_token
        if not token and oauth_handler and hasattr(oauth_handler, "id_token"):
            token = oauth_handler.id_token or oauth_handler.access_token

        if not token and not refresh_token and not oauth_handler:
            raise AtombergAuthError("Cognito token, refresh token, or oauth_handler is required for cloud sync")

        self._token = token or ""
        self._refresh_token = refresh_token
        self._oauth_handler = oauth_handler
        self._session = session
        self._owns_session = session is None
        self._base_url = base_url.rstrip("/")
        self._firebase_api_key = firebase_api_key
        self._firebase_project_id = firebase_project_id
        self._fb_token: str | None = None
        self._fb_token_expires_at: float = 0.0
        self._on_token_refreshed = on_token_refreshed

    @property
    def token(self) -> str:
        """Return the active Bearer token."""
        return self._token

    @property
    def refresh_token(self) -> str | None:
        """Return the active refresh token."""
        return self._refresh_token

    def is_token_expired(self, skew_seconds: int = 60) -> bool:
        """Check if current token is expired or about to expire within skew_seconds."""
        if not self._token:
            return True
        payload = decode_jwt_payload(self._token)
        exp = payload.get("exp")
        if exp is not None:
            return time.time() >= (float(exp) - skew_seconds)
        return False

    async def async_ensure_valid_token(self) -> str:
        """Ensure active token is valid, refreshing if expired or expiring soon."""
        if self.is_token_expired():
            await self.async_refresh_token()
        return self._token

    async def async_refresh_token(self) -> str:
        """Refresh Cognito tokens using OAuth handler or stored refresh token."""
        if self._oauth_handler is None and self._refresh_token:
            from pyatomberg.auth.cognito import CognitoOAuthHandler

            self._oauth_handler = CognitoOAuthHandler(
                refresh_token=self._refresh_token,
                session=self._session,
            )

        if self._oauth_handler is None:
            _LOGGER.debug("No OAuth handler or refresh token available to refresh token")
            return self._token

        try:
            tokens = await self._oauth_handler.refresh_tokens()
            new_token = tokens.get("id_token") or tokens.get("access_token")
            if new_token:
                self._token = new_token
                new_refresh = tokens.get("refresh_token") or self._refresh_token
                if new_refresh:
                    self._refresh_token = new_refresh
                _LOGGER.info("Successfully refreshed Atomberg Cognito token")
                if self._on_token_refreshed:
                    try:
                        res = self._on_token_refreshed(new_token, self._refresh_token)
                        if asyncio.iscoroutine(res):
                            await res
                    except Exception as cb_err:
                        _LOGGER.warning("Token refresh callback failed: %s", cb_err)
                return self._token
        except Exception as err:
            _LOGGER.error("Failed to refresh Cognito token: %s", err)
            raise AtombergAuthError(f"Cognito token refresh failed: {err}") from err

        return self._token

    async def fetch_account_locks(self) -> list[PairingResult]:
        """Fetch all smart locks registered to this Atomberg account with encryption parameters."""
        await self.async_ensure_valid_token()
        url = f"{self._base_url}/app_open"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "Atomberg/7.7.2",
            "Accept": "application/json",
        }

        session = self._session
        if session is None or session.closed:
            session = aiohttp.ClientSession()
            self._session = session

        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status in (401, 403):
                    raise AtombergAuthError(f"Cloud server returned HTTP {resp.status} (authentication failed)")
                if resp.status != 200:
                    raise AtombergConnectionError(f"Cloud server returned HTTP {resp.status}")

                data: dict[str, Any] = await resp.json(content_type=None)

                # Extract devices list from all possible schemas
                devices: list[dict[str, Any]] = []

                # Primary production schema: message.user_details.families[].devices[]
                user_details = (data.get("message") or {}).get("user_details") or {}
                families = user_details.get("families") or []
                for fam in families:
                    if isinstance(fam, dict):
                        for dev in (fam.get("devices") or []):
                            if isinstance(dev, dict):
                                devices.append(dev)

                # Fallback flat lists
                if not devices:
                    devices = (
                        data.get("devices")
                        or (data.get("data") or {}).get("devices")
                        or (data.get("data") or {}).get("locks")
                        or data.get("locks")
                        or []
                    )

                results: list[PairingResult] = []
                for item in devices:
                    if not isinstance(item, dict):
                        continue

                    try:
                        meta = item.get("metadata") or {}
                        friendly_name = item.get("friendly_name") or item.get("name") or "Atomberg Smart Lock"
                        model = item.get("model") or item.get("series") or "smart_lock"

                        # 1. Primary Atomberg lock metadata schema (aes + adminAuthCode/generalAuthCode)
                        if "aes" in meta and ("adminAuthCode" in meta or "generalAuthCode" in meta):
                            mac_raw = meta.get("lockMac") or item.get("device_id") or ""
                            mac_clean = str(mac_raw).replace(":", "").replace("-", "").upper()
                            if len(mac_clean) == 12:
                                mac = ":".join(mac_clean[i : i + 2] for i in range(0, 12, 2))
                            else:
                                mac = str(mac_raw).upper()

                            key_str = str(meta["aes"]).strip()
                            key_bytes = key_str.encode("utf-8") if len(key_str) == 16 else bytes.fromhex(key_str)

                            salt_hex = str(meta.get("adminAuthCode") or meta.get("generalAuthCode", "")).strip()
                            salt_bytes = bytes.fromhex(salt_hex)

                            temp_code = meta.get("tempAuthCode")
                            gen_code = meta.get("generalAuthCode")

                            results.append(
                                PairingResult(
                                    mac_address=mac,
                                    master_key=key_bytes,
                                    salt=salt_bytes,
                                    name=friendly_name,
                                    model=model,
                                    temp_auth_code=str(temp_code).strip() if temp_code else None,
                                    general_auth_code=str(gen_code).strip() if gen_code else None,
                                )
                            )
                            continue

                        # 2. Legacy / generic fallback schema
                        dev_type = str(item.get("device_type", item.get("type", ""))).lower()
                        desc = str(meta.get("description", "")).lower()
                        if "lock" not in dev_type and "sitana" not in dev_type and "lock" not in desc and "lock" not in model.lower():
                            continue

                        mac_val = item.get("mac_address") or item.get("mac") or item.get("device_id")
                        raw_key = item.get("master_key") or item.get("static_key") or item.get("key") or meta.get("key")
                        raw_salt = item.get("salt") or item.get("lock_salt") or meta.get("salt")

                        if not mac_val or not raw_key or not raw_salt:
                            continue

                        if isinstance(raw_key, str):
                            raw_key_str = raw_key.strip()
                            key_bytes = bytes.fromhex(raw_key_str) if len(raw_key_str) == 32 else raw_key_str.encode("utf-8")
                        else:
                            key_bytes = bytes(raw_key)

                        if isinstance(raw_salt, str):
                            salt_clean = raw_salt.strip().replace(" ", "").replace("0x", "")
                            salt_bytes = bytes.fromhex(salt_clean)
                        else:
                            salt_bytes = bytes(raw_salt)

                        results.append(
                            PairingResult(
                                mac_address=str(mac_val).upper(),
                                master_key=key_bytes,
                                salt=salt_bytes,
                                name=friendly_name,
                                model=model,
                            )
                        )
                    except Exception as dev_err:
                        dev_id = item.get("device_id") or item.get("id") or "unknown"
                        _LOGGER.warning("Skipping malformed lock device record (%s): %s", dev_id, dev_err)

                return results
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            raise AtombergConnectionError(f"Network error querying app_open: {err}") from err
        finally:
            if self._owns_session and self._session and not self._session.closed:
                await self._session.close()



    async def fetch_cloud_history(
        self,
        device_id: str,
        slot_mappings: dict[int, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch lock history events from Firestore cloud document."""
        session = self._session
        if session is None or session.closed:
            session = aiohttp.ClientSession()
            self._session = session

        clean_id = device_id.replace(":", "").replace("-", "").lower()

        # Step 1: Obtain anonymous Firebase token using mobile client key
        fb_token = None
        if self._fb_token and time.time() < (self._fb_token_expires_at - 60):
            fb_token = self._fb_token
        else:
            auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self._firebase_api_key}"
            try:
                async with session.post(
                    auth_url,
                    json={"returnSecureToken": True},
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as auth_resp:
                    if auth_resp.status == 200:
                        auth_data = await auth_resp.json(content_type=None)
                        fb_token = auth_data.get("idToken")
                        if fb_token:
                            self._fb_token = fb_token
                            expires_in = float(auth_data.get("expiresIn", 3600))
                            self._fb_token_expires_at = time.time() + expires_in
            except Exception as err:
                _LOGGER.debug("Could not get Firebase token: %s", err)

        if not fb_token:
            _LOGGER.debug("No Firebase token available; skipping cloud history query")
            return []

        # Step 2: Fetch Firestore doc for this lock
        fs_url = f"https://firestore.googleapis.com/v1/projects/{self._firebase_project_id}/databases/(default)/documents/lock_history/{clean_id}"
        headers = {"Authorization": f"Bearer {fb_token}", "Accept": "application/json"}

        try:
            async with session.get(
                fs_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    _LOGGER.debug("Cloud history returned HTTP %s for lock %s", resp.status, clean_id)
                    return []
                doc = await resp.json(content_type=None)
        except Exception as ex:
            _LOGGER.debug("Failed to query cloud history for lock %s: %s", clean_id, ex)
            return []

        # Step 3: Parse records array
        from pyatomberg.lock.hsj_protocol import format_ist_time, slot_name

        events: list[dict[str, Any]] = []
        locks_field = doc.get("fields", {}).get("locks", {}).get("mapValue", {}).get("fields", {})
        history_list = locks_field.get("history", {}).get("arrayValue", {}).get("values", [])

        for val in history_list:
            item = val.get("mapValue", {}).get("fields", {})
            if not item:
                continue

            record_time_str = item.get("recordTime", {}).get("stringValue", "0")
            ts = int(record_time_str) if record_time_str.isdigit() else 0
            rec_type = item.get("recordType", {}).get("stringValue", "0")
            key_type_str = item.get("keyType", {}).get("stringValue", "0")
            key_type = int(key_type_str) if key_type_str.isdigit() else 0
            slot_id_val = item.get("lockKeyId", {})
            slot_id = int(slot_id_val.get("integerValue") or slot_id_val.get("stringValue") or 0)
            event_type = item.get("type", {}).get("stringValue", "")

            event_name = "Unlocked Successfully" if (rec_type == "4" or event_type == "unlock") else "Hardware Event"
            if event_type == "addKey" or rec_type == "8":
                event_name = "Credential Enrolled"

            if event_name == "Unlocked Successfully":
                if key_type in _CREDENTIAL_TYPE_NAMES:
                    cred_type_name = _CREDENTIAL_TYPE_NAMES[key_type]
                    detail = f"Unlocked by - {slot_name(slot_id, slot_mappings)}"
                elif key_type == 128 or slot_id == 0:
                    cred_type_name = "Atomberg App"
                    detail = "Atomberg Mobile App (BLE)"
                else:
                    cred_type_name = f"Credential Type {key_type}" if key_type else "Physical Credential"
                    detail = f"Unlocked by - {slot_name(slot_id, slot_mappings)}"
            elif event_name == "Credential Enrolled":
                if key_type in _CREDENTIAL_TYPE_NAMES:
                    cred_type_name = _CREDENTIAL_TYPE_NAMES[key_type]
                    detail = f"Enrolled - {slot_name(slot_id, slot_mappings)}"
                else:
                    cred_type_name = f"Credential Type {key_type}" if key_type else "Physical Credential"
                    detail = f"Enrolled - {slot_name(slot_id, slot_mappings)}"
            else:
                cred_type_name = "Hardware Status"
                detail = "System / Diagnostic Event"

            events.append({
                "datetime": format_ist_time(ts),
                "timestamp": format_ist_time(ts),
                "event": event_name,
                "detail": detail,
                "credential_type": cred_type_name,
                "slot": slot_id,
                "slot_id": slot_id,
                "raw_record_type": rec_type,
                "raw_timestamp": ts,
                "source": "cloud",
            })

        events.sort(key=lambda x: x.get("raw_timestamp", 0), reverse=True)
        return events


