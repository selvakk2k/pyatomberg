"""Tests for authentication handlers."""

import pytest
from pyatomberg.auth.cognito import CognitoOAuthHandler, generate_pkce_pair
from pyatomberg.auth.developer import DeveloperTokenHandler
from pyatomberg.exceptions import AtombergAuthError


def test_developer_token_validation():
    """Verify empty developer refresh token raises AtombergAuthError."""
    with pytest.raises(AtombergAuthError, match="cannot be empty"):
        DeveloperTokenHandler("")

    handler = DeveloperTokenHandler("sample_refresh_token_123")
    assert handler.refresh_token == "sample_refresh_token_123"
    assert handler.has_valid_access_token is False


def test_pkce_generation():
    """Verify PKCE code_verifier and code_challenge format."""
    verifier, challenge = generate_pkce_pair()
    assert len(verifier) >= 43
    assert len(challenge) >= 43
    # Check urlsafe base64
    assert not any(c in verifier for c in "+/=")
    assert not any(c in challenge for c in "+/=")


def test_cognito_authorization_url():
    """Verify Cognito authorization URL generation with PKCE and state."""
    handler = CognitoOAuthHandler(
        client_id="test_client_id",
        redirect_uri="http://localhost:8080/callback",
    )
    url, state, verifier = handler.get_authorization_url(identity_provider="Google")

    assert "https://auth.atomberg-iot.com/oauth2/authorize" in url
    assert "client_id=test_client_id" in url
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback" in url
    assert "response_type=code" in url
    assert "code_challenge_method=S256" in url
    assert "identity_provider=Google" in url
    assert f"state={state}" in url
    assert len(verifier) >= 43


def test_cognito_universal_authorization_url():
    """Verify universal authorization URL omits identity_provider for all sign-in options."""
    handler = CognitoOAuthHandler(
        client_id="test_client_id",
        redirect_uri="https://app.atomberg-iot.com",
    )
    url, state, verifier = handler.get_authorization_url(identity_provider=None)

    assert "https://auth.atomberg-iot.com/oauth2/authorize" in url
    assert "client_id=test_client_id" in url
    assert "identity_provider" not in url
    assert "scope=aws.cognito.signin.user.admin+openid+email" in url
    assert f"state={state}" in url
    assert len(verifier) >= 43


@pytest.mark.asyncio
async def test_cognito_auth_headers_with_cached_token():
    """Verify CognitoOAuthHandler returns proper auth headers when token is cached."""
    handler = CognitoOAuthHandler(
        client_id="test_client",
        access_token="test_access_token_123",
        id_token="test_id_token_456",
    )
    assert handler.is_authenticated is True
    token = await handler.get_access_token()
    assert token == "test_access_token_123"

    headers = await handler.get_auth_headers()
    assert headers["Authorization"] == "Bearer test_id_token_456"
    assert headers["Content-Type"] == "application/json"
