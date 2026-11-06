"""Interactive Google OAuth setup script for Atomberg accounts.

Enables users to sign in with Google in their browser and automatically
exchanges the resulting authorization code for permanent Cognito refresh and ID tokens.
"""

from __future__ import annotations

import asyncio
from typing import Any
import urllib.parse

from pyatomberg.auth.cognito import CognitoOAuthHandler
from pyatomberg.const import COGNITO_CLIENT_ID, COGNITO_REDIRECT_URI
from pyatomberg.lock.cloud_sync import AtombergCloudSync


async def run_interactive_login() -> tuple[dict[str, str], list[Any]]:
    """Run interactive CLI Google login and return tokens and discovered locks."""
    handler = CognitoOAuthHandler(
        client_id=COGNITO_CLIENT_ID,
        redirect_uri=COGNITO_REDIRECT_URI,
    )

    auth_url, state, verifier = handler.get_authorization_url(identity_provider=None)

    print("\n" + "=" * 70)
    print(" ATOMBERG UNIVERSAL ACCOUNT LOGIN (EMAIL / GOOGLE / APPLE / FACEBOOK)")
    print("=" * 70)
    print("\n1. Open the following URL in your web browser:\n")
    print(auth_url)
    print("\n2. Sign in with your Atomberg email & password, Google, Apple, or Facebook.")
    print("3. After signing in, your browser will redirect to https://app.atomberg-iot.com/?code=...")
    print("4. Copy the entire URL (or just the code value) from your browser address bar.")
    print("=" * 70 + "\n")

    user_response = input("Paste the redirected URL or authorization code here: ").strip()
    if not user_response:
        print("[!] No input provided. Aborting.")
        return {}, []

    # Extract authorization code
    auth_code = user_response
    if "code=" in user_response:
        parsed = urllib.parse.urlparse(user_response)
        params = urllib.parse.parse_qs(parsed.query)
        code_list = params.get("code")
        if code_list:
            auth_code = code_list[0]
        else:
            # Maybe in fragment or raw string
            for part in user_response.split("&"):
                if part.startswith("code=") or "code=" in part:
                    auth_code = part.split("code=")[-1]
                    break

    print(f"\n[*] Exchanging authorization code for Cognito tokens...")
    tokens = await handler.exchange_code_for_tokens(
        code=auth_code,
        code_verifier=verifier,
        redirect_uri=COGNITO_REDIRECT_URI,
    )

    access_token = tokens.get("access_token", "")
    id_token = tokens.get("id_token", "")
    refresh_token = tokens.get("refresh_token", "")

    print("\n[+] Authentication successful!")
    print(f"    Refresh Token:                  {refresh_token}")
    print(f"    Access Token (first 20 chars):  {access_token[:20]}...")
    print(f"    ID Token (first 20 chars):      {id_token[:20]}...")

    print("\n[*] Querying Atomberg cloud account (server.atomberg-iot.com/app_open) for smart locks...")
    sync_client = AtombergCloudSync(access_token=access_token)
    try:
        locks = await sync_client.fetch_account_locks()
        if not locks:
            print("[-] No smart locks found in this Atomberg account.")
        else:
            print(f"[+] Discovered {len(locks)} smart lock(s) registered in your account:\n")
            for idx, lock in enumerate(locks, 1):
                print(f"    Lock #{idx}:")
                print(f"      Name:        {lock.name or 'Atomberg Smart Lock'}")
                print(f"      Model:       {lock.model or 'smart_lock'}")
                print(f"      MAC Address: {lock.mac_address}")
                print(f"      Master Key:  {lock.master_key_hex}")
                print(f"      Salt:        {lock.salt_hex}")
        return tokens, locks
    except Exception as err:
        print(f"[!] Error syncing account locks: {err}")
        return tokens, []


def main() -> None:
    """Entry point for CLI command."""
    asyncio.run(run_interactive_login())


if __name__ == "__main__":
    main()
