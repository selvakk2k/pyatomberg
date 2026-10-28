"""Atomberg mobile cloud sync client for importing registered smart locks."""

from __future__ import annotations

import logging
import time
from typing import Any

import aiohttp

from pyatomberg.const import SERVER_API_BASE
from pyatomberg.exceptions import AtombergAuthError, AtombergConnectionError
from pyatomberg.lock.pairing import PairingResult

_LOGGER = logging.getLogger(__name__)


class AtombergCloudSync:
    """Fetches already-paired lock encryption keys and metadata from the Atomberg mobile backend."""

    def __init__(
        self,
        access_token: str | None = None,
        id_token: str | None = None,
        session: aiohttp.ClientSession | None = None,
        base_url: str = SERVER_API_BASE,
    ) -> None:
        """Initialize cloud sync client with Cognito access token or ID token."""
        token = access_token or id_token
        if not token:
            raise AtombergAuthError("Cognito access token or ID token is required for cloud sync")

        self._token = token
        self._session = session
        self._owns_session = session is None
        self._base_url = base_url.rstrip("/")

    @property
    def token(self) -> str:
        """Return the active Bearer token."""
        return self._token

    async def fetch_account_locks(self) -> list[PairingResult]:
        """Fetch all smart locks registered to this Atomberg account with encryption parameters."""
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
                if resp.status != 200:
                    raise AtombergConnectionError(f"Cloud server returned HTTP {resp.status}")

                data: dict[str, Any] = await resp.json(content_type=None)

                # Extract devices list from all possible schemas
                devices: list[dict[str, Any]] = []

                # Primary production schema: message.user_details.families[].devices[]
                user_details = data.get("message", {}).get("user_details", {})
                families = user_details.get("families", [])
                for fam in families:
                    if isinstance(fam, dict):
                        for dev in fam.get("devices", []):
                            if isinstance(dev, dict):
                                devices.append(dev)

                # Fallback flat lists
                if not devices:
                    devices = (
                        data.get("devices")
                        or data.get("data", {}).get("devices")
                        or data.get("data", {}).get("locks")
                        or data.get("locks")
                        or []
                    )

                results: list[PairingResult] = []
                for item in devices:
                    if not isinstance(item, dict):
                        continue

                    meta = item.get("metadata", {})
                    friendly_name = item.get("friendly_name") or item.get("name") or "Atomberg Smart Lock"
                    model = item.get("model") or item.get("series") or "smart_lock"

                    # 1. Primary Atomberg lock metadata schema (aes + adminAuthCode/generalAuthCode)
                    if "aes" in meta and ("adminAuthCode" in meta or "generalAuthCode" in meta):
                        mac_raw = meta.get("lockMac") or item.get("device_id") or ""
                        mac_clean = mac_raw.replace(":", "").replace("-", "").upper()
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
                    dev_type = item.get("device_type", item.get("type", "")).lower()
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

                return results
        except aiohttp.ClientError as err:
            raise AtombergConnectionError(f"Network error querying app_open: {err}") from err
        finally:
            if self._owns_session and self._session and not self._session.closed:
                await self._session.close()

    async def get_dynamic_otp(
        self,
        device_id: str,
        start_time: int | None = None,
        end_time: int | None = None,
    ) -> dict[str, Any]:
        """Fetch an active 6-digit dynamic OTP for an SL1/Azhero smart lock from the cloud."""
        headers = {
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "Atomberg/7.7.2",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        session = self._session
        if session is None or session.closed:
            session = aiohttp.ClientSession()
            self._session = session

        now_ts = int(time.time())
        s_time = start_time if start_time is not None else now_ts
        e_time = end_time if end_time is not None else (now_ts + 1800)

        clean_id = device_id.replace(":", "").replace("-", "").lower()
        payload = {
            "device_id": clean_id,
            "start_time": s_time,
            "end_time": e_time,
        }

        urls = [
            f"{self._base_url}/lrp/get_otp",
            f"{self._base_url}/get_lock_dynamic_pin",
            f"{self._base_url}/lrp/get_dynamic_password",
        ]

        last_error: str | None = None
        for url in urls:
            try:
                async with session.post(
                    url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data: dict[str, Any] = await resp.json(content_type=None)
                        otp_val = None
                        if isinstance(data, dict):
                            msg_data = data.get("message", {}).get("data", {})
                            if isinstance(msg_data, dict):
                                otp_val = msg_data.get("otp") or msg_data.get("password") or msg_data.get("pin")
                            if not otp_val and isinstance(data.get("data"), dict):
                                otp_val = data["data"].get("otp") or data["data"].get("password")
                            if not otp_val:
                                otp_val = data.get("otp") or data.get("password") or data.get("pin")

                        if otp_val:
                            _LOGGER.info("Retrieved active cloud OTP for lock %s: %s", clean_id, otp_val)
                            return {
                                "otp": str(otp_val),
                                "start_time": s_time,
                                "end_time": e_time,
                                "raw_response": data,
                            }
                    else:
                        last_error = f"HTTP {resp.status}"
            except Exception as ex:
                last_error = str(ex)
                continue

        raise AtombergConnectionError(f"Failed to fetch dynamic OTP from cloud: {last_error}")

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
        api_key = "AIzaSyBowISrLGjKvmHN95NEvylMjgdR0ExPlUo"
        auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
        fb_token = None
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
        except Exception as err:
            _LOGGER.debug("Could not get Firebase token: %s", err)

        if not fb_token:
            fb_token = self._token

        # Step 2: Fetch Firestore doc for this lock
        fs_url = f"https://firestore.googleapis.com/v1/projects/firestore-test-65c75/databases/(default)/documents/lock_history/{clean_id}"
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

            cred_type_name = "Physical Credential"
            detail = ""
            if key_type == 1:
                cred_type_name = "Fingerprint"
                detail = f"Unlocked by - {slot_name(slot_id, slot_mappings)}"
            elif key_type == 2:
                cred_type_name = "PIN Code"
                detail = f"Unlocked by - {slot_name(slot_id, slot_mappings)}"
            elif key_type == 4:
                cred_type_name = "NFC Card"
                detail = f"Unlocked by - {slot_name(slot_id, slot_mappings)}"
            elif key_type == 128 or slot_id == 0:
                cred_type_name = "Atomberg App"
                detail = "Atomberg Mobile App (BLE)"
            else:
                cred_type_name = f"Credential Type {key_type}"
                detail = f"Unlocked by - {slot_name(slot_id, slot_mappings)}"

            events.append({
                "datetime": format_ist_time(ts),
                "event": event_name,
                "detail": detail,
                "credential_type": cred_type_name,
                "slot": slot_id,
                "raw_timestamp": ts,
                "source": "cloud",
            })

        events.sort(key=lambda x: x.get("raw_timestamp", 0), reverse=True)
        return events


