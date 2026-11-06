"""AWS Cognito Hosted UI OAuth2 authentication handler."""

import base64
import hashlib
import os
import secrets
import time
import urllib.parse
from typing import Any

import aiohttp

from pyatomberg.const import (
    COGNITO_AUTHORIZE_URL,
    COGNITO_CLIENT_ID,
    COGNITO_REDIRECT_URI,
    COGNITO_TOKEN_URL,
)
from pyatomberg.exceptions import AtombergAuthError, AtombergConnectionError


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE (code_verifier, code_challenge) tuple using S256."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
    challenge_bytes = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(challenge_bytes).decode("utf-8").rstrip("=")
    return verifier, challenge


class CognitoOAuthHandler:
    """Manages OAuth2 authorization code flow with AWS Cognito Hosted UI.

    Supports third-party identity providers such as Google Sign-In and Apple Sign-In
    federated via auth.atomberg-iot.com.
    """

    def __init__(
        self,
        client_id: str = COGNITO_CLIENT_ID,
        redirect_uri: str = COGNITO_REDIRECT_URI,
        refresh_token: str | None = None,
        access_token: str | None = None,
        id_token: str | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        """Initialize the Cognito OAuth handler."""
        self._client_id = client_id
        self._redirect_uri = redirect_uri
        self._refresh_token = refresh_token
        self._id_token = id_token
        self._access_token = access_token
        self._expires_at: float = (time.time() + 3600) if access_token else 0.0
        self._session = session

        # Active PKCE verifier for pending flow
        self._pending_verifier: str | None = None
        self._pending_state: str | None = None

    @property
    def refresh_token(self) -> str | None:
        """Return the Cognito refresh token."""
        return self._refresh_token

    @property
    def id_token(self) -> str | None:
        """Return the Cognito ID token used for API requests."""
        return self._id_token

    @property
    def access_token(self) -> str | None:
        """Return the Cognito Access token."""
        return self._access_token

    @property
    def is_authenticated(self) -> bool:
        """Check if an access token is cached and not expired."""
        return self._access_token is not None and time.time() < (self._expires_at - 60)

    def get_authorization_url(
        self,
        redirect_uri: str | None = None,
        identity_provider: str | None = None,
        scope: str = "aws.cognito.signin.user.admin openid email",
    ) -> tuple[str, str, str]:
        """Generate the Cognito Hosted UI authorization URL with PKCE.

        Returns (auth_url, state, code_verifier).
        """
        if redirect_uri:
            self._redirect_uri = redirect_uri

        verifier, challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(16)
        self._pending_verifier = verifier
        self._pending_state = state

        params: dict[str, str] = {
            "client_id": self._client_id,
            "response_type": "code",
            "scope": scope,
            "redirect_uri": self._redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if identity_provider:
            params["identity_provider"] = identity_provider

        url = f"{COGNITO_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
        return url, state, verifier

    async def exchange_code_for_tokens(
        self,
        code: str,
        code_verifier: str | None = None,
        redirect_uri: str | None = None,
    ) -> dict[str, Any]:
        """Exchange authorization code for Cognito tokens."""
        verifier = code_verifier or self._pending_verifier
        if not verifier:
            raise AtombergAuthError("No PKCE code_verifier provided or found in pending state")

        r_uri = redirect_uri or self._redirect_uri
        payload = {
            "grant_type": "authorization_code",
            "client_id": self._client_id,
            "code": code,
            "redirect_uri": r_uri,
            "code_verifier": verifier,
        }

        return await self._post_token_request(payload)

    async def refresh_tokens(self) -> dict[str, Any]:
        """Refresh tokens using the stored refresh_token."""
        if not self._refresh_token:
            raise AtombergAuthError("No refresh token available to refresh Cognito session")

        payload = {
            "grant_type": "refresh_token",
            "client_id": self._client_id,
            "refresh_token": self._refresh_token,
        }
        return await self._post_token_request(payload)

    async def get_access_token(self, force_refresh: bool = False) -> str:
        """Retrieve a valid access token, refreshing if necessary."""
        if not force_refresh and self.is_authenticated and self._access_token:
            return self._access_token

        if not self._refresh_token:
            raise AtombergAuthError("Cognito authentication expired and no refresh token available")

        await self.refresh_tokens()
        if not self._access_token:
            raise AtombergAuthError("Cognito refresh did not return a valid access token")
        return self._access_token

    async def get_auth_headers(self) -> dict[str, str]:
        """Return HTTP authorization headers with a valid Bearer token."""
        token = await self.get_access_token()
        auth_token = self._id_token or token
        return {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }

    async def _post_token_request(self, payload: dict[str, str]) -> dict[str, Any]:
        """Post request to Cognito token endpoint."""
        close_session = False
        session = self._session
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            async with session.post(
                COGNITO_TOKEN_URL,
                data=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data: dict[str, Any] = await resp.json(content_type=None)
                if resp.status != 200:
                    err = data.get("error_description") or data.get("error") or f"HTTP {resp.status}"
                    raise AtombergAuthError(f"Cognito token request failed: {err}")

                self._access_token = data.get("access_token")
                self._id_token = data.get("id_token")
                if "refresh_token" in data:
                    self._refresh_token = data["refresh_token"]

                expires_in = data.get("expires_in", 3600)
                self._expires_at = time.time() + float(expires_in)
                return data
        except aiohttp.ClientError as err:
            raise AtombergConnectionError(f"Network error communicating with Cognito: {err}") from err
        finally:
            if close_session:
                await session.close()
