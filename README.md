# Atomberg Devices Python Library (`pyatomberg`)

[![Hardware Verified](https://img.shields.io/badge/Hardware-Verified%20(SL1%20Pro)-success.svg)](#hardware-compatibility-matrix)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/pyatomberg.svg)](https://pypi.org/project/pyatomberg/)
[![AI-Assisted](https://img.shields.io/badge/AI%20Assisted-Antigravity%20%7C%20Claude-blueviolet?style=flat-square&logo=google)](https://github.com/selvakk2k)

An asynchronous Python client library for authentication, discovery, and control of **Atomberg smart home appliances** (smart door locks, smart ceiling fans, and connected appliances).

> [!NOTE]
> **Ceiling Fan Integration**:
> For Home Assistant users seeking control of Atomberg smart ceiling fans, an integration supporting both Cloud, Local and IR control is already available at [`dasshubham762/atomberg-integration`](https://github.com/dasshubham762/atomberg-integration).

---

## Table of Contents

- [Overview & Reverse-Engineering Context](#overview--reverse-engineering-context)
- [Hardware Compatibility Matrix](#hardware-compatibility-matrix)
- [Installation & Requirements](#installation--requirements)
- [Authentication Pathways](#authentication-pathways)
  - [Method A: Universal Cognito OAuth2 + PKCE (Recommended)](#method-a-universal-cognito-oauth2--pkce-recommended)
  - [Method B: Official Developer API Token](#method-b-official-developer-api-token)
- [Quick Start by Device Category](#quick-start-by-device-category)
  - [1. Universal Multi-Device Discovery](#1-universal-multi-device-discovery)
  - [2. Smart Door Locks: Key Extraction & Protocol Primitives](#2-smart-door-locks-key-extraction--protocol-primitives)
  - [3. Smart Ceiling Fans: Local UDP Broadcast & Cloud Control](#3-smart-ceiling-fans-local-udp-broadcast--cloud-control)
  - [4. Connected Appliances: Water Purifiers](#4-connected-appliances-water-purifiers)
- [Supported Capabilities vs. Known Limitations](#supported-capabilities-vs-known-limitations)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Credits & License](#credits--license)
  - [Disclaimer](#disclaimer)
  - [Author & Contributors](#author--contributors)

---

## Overview & Reverse-Engineering Context

Atomberg provides an official Developer Portal and API (`https://api.developer.atomberg-iot.com`). However, relying exclusively on this official API presents several practical constraints:

1. **Mandatory Ceiling Fan Dependency**: In the official Atomberg Android/iOS application (`com.atomberg.app`), the Developer Options menu (`DeveloperOptionsScreen`) is strictly hidden unless the user has at least one smart ceiling fan registered to their account. Users who own only smart locks or smart appliances cannot activate developer mode or generate developer tokens.
2. **Missing Local BLE Credentials**: The official cloud API does not provide Bluetooth Low Energy (BLE) authentication keys or master credentials for smart door locks.
3. **Appliance Ecosystem Unification**: `pyatomberg` bridges the gap across the Atomberg device ecosystem, enabling third-party Home Assistant integrations and custom automation engines to interface directly with fans, locks, and appliances.

To overcome these barriers, `atomberg-py` reverse-engineers the official Atomberg application protocol and combines two distinct control tiers:

* **Universal Cloud Layer**: Uses native AWS Cognito OAuth2 with PKCE (supporting Email, Google, Apple, and Facebook logins) to discover all registered appliances across any user account.
* **100% Offline Local Layer**: Provides protocol frame serialization (`HSJProtocol`), AES-128 cryptographic primitives, live notification parsing, and local network UDP broadcast listeners for smart ceiling fans.

---

## Hardware Compatibility Matrix

| Category | Models / Series | Key Functions & Sensors | Integration Mode | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Authentication** | AWS Cognito OAuth2 | Email, Google, Apple, Facebook | Cloud REST + OAuth2 / PKCE | `✅ Hardware Verified` |
| **Authentication** | Official Developer API | Refresh Token Exchange (`v2`) | Cloud REST (`api.developer.atomberg-iot.com`) | `✅ Hardware Verified` |
| **Smart Door Locks** | SL1, SL1 Pro (`smart_lock_black`) | AES-128 Encryption, Packet Codecs, BTSnoop Key Extraction, Live Events | Offline Protocol / Cloud Sync | `✅ Hardware Verified` |
| **Smart Door Locks** | Cypheo Elite (`G1`) | Clock-Derived Rolling PINs | Cloud API / Algorithmic Derivation | `⚠️ API Modeled` |
| **Smart Ceiling Fans** | Renesa, Studio, Aris, Wave | State Tracking (Speed, Power, Timer, Breeze, Sleep) | Local UDP Broadcast (Port 5625) | `✅ Hardware Verified` |
| **Smart Ceiling Fans** | All Wi-Fi Series | Speed Selection (1–6), Mode Switching, Power Toggle | Cloud REST via Developer API / Cognito | `✅ Hardware Verified` |
| **Water Purifiers** | Connected Purifiers | Dispense State, Filter Health, TDS Telemetry | Cloud REST / Internal State Dict | `⚠️ API Modeled` |

---

## Installation & Requirements

Install `pyatomberg` directly using `pip`:

```bash
pip install pyatomberg
```

For local development or testing from source:

```bash
git clone https://github.com/selvakk2k/pyatomberg.git
cd pyatomberg
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

---

## Authentication Pathways

`atomberg-py` supports two authentication methods depending on your account setup:

### Method A: Universal Cognito OAuth2 + PKCE (Recommended)

This method mirrors the official mobile app and works for **all** Atomberg accounts, whether you own a lock, a fan, or another connected appliance:

```python
import asyncio
from pyatomberg.auth.cognito import CognitoOAuthHandler

async def main():
    auth = CognitoOAuthHandler()
    
    # 1. Generate the authorization URL for user login
    login_url = auth.get_authorization_url()
    print(f"Open this URL in your browser:\n{login_url}\n")
    
    # 2. After logging in, copy the redirect URL (starts with https://app.atomberg-iot.com/?code=...)
    redirect_url = input("Paste the redirected URL: ")
    
    # 3. Exchange code for access tokens
    tokens = await auth.exchange_code_for_tokens(redirect_url)
    print("Authentication successful! Access Token acquired.")

asyncio.run(main())
```

### Method B: Official Developer API Token

If you own an Atomberg smart ceiling fan and have activated the Developer Options in the Atomberg app:

```python
from pyatomberg.auth.developer import DeveloperTokenHandler

handler = DeveloperTokenHandler(
    refresh_token="your_developer_refresh_token_from_app",
    api_key="your_optional_api_key",
)
```

---

## Quick Start by Device Category

### 1. Universal Multi-Device Discovery

Query your Atomberg account to list all registered locks, fans, and appliances:

```python
import asyncio
from pyatomberg.client import AtombergClient

async def main():
    # Initialize with either developer_token or a configured cognito_handler
    async with AtombergClient(developer_token="your_refresh_token") as client:
        # Discover registered ceiling fans
        fans = await client.get_fans()
        for fan in fans:
            print(f"Fan: {fan.name} (ID: {fan.device_id}, Model: {fan.model_name})")

asyncio.run(main())
```

---

### 2. Smart Door Locks: Key Extraction & Protocol Primitives

`atomberg-py` handles the cryptographic encoding, packet serialization, and credential extraction for SL1 / SL1 Pro smart locks:

```python
from pyatomberg.lock.pairing import extract_keys_from_btsnoop
from pyatomberg.lock.hsj_protocol import build_hsj_packet, parse_hsj_packet

# 1. Extract offline BLE credentials from an Android Bluetooth HCI log
keys = extract_keys_from_btsnoop("path/to/btsnoop_hci.log")
print(f"Lock MAC: {keys.mac_address}")
print(f"Master Key: {keys.master_key_hex}")
print(f"Lock Salt: {keys.salt_hex}")

# 2. Serialize secure encrypted frame for GATT dispatch
payload = bytes.fromhex("000000000200f000000000000c")  # Probe handshake
packet = build_hsj_packet(payload, key=keys.master_key, frame_seq=2)
print(f"Serialized Frame (length {len(packet)}): {packet.hex()}")
```

> [!NOTE]
> **Live Bluetooth GATT Connectivity**:
> To control and automate the lock over Bluetooth Low Energy, the companion Home Assistant integration [`ha-atomberg-lock`](https://github.com/selvakk2k/ha-atomberg-lock) implements the native GATT client and auto-relock lifecycle using Home Assistant's Bluetooth engine.

---

### 3. Smart Ceiling Fans: Local UDP Broadcast & Cloud Control

#### Real-Time Local UDP Broadcast Listener
Atomberg Wi-Fi ceiling fans broadcast unencrypted JSON/HAProxy status packets across the local subnet on UDP port 5625:

```python
import asyncio
from pyatomberg.fan.udp_listener import AtombergUDPListener

def on_packet(device_id: str, data: dict):
    print(f"Fan {device_id} broadcast -> Speed: {data.get('speed')}, Power: {data.get('power')}")

async def main():
    listener = AtombergUDPListener(callback=on_packet, port=5625)
    await listener.start()
    print("Listening for local fan UDP broadcasts on port 5625...")
    await asyncio.sleep(60)
    await listener.stop()

asyncio.run(main())
```

#### Cloud API Control
```python
import asyncio
from pyatomberg.client import AtombergClient

async def main():
    async with AtombergClient(developer_token="your_refresh_token") as client:
        # Set fan speed (1 to 6)
        await client.send_command("device_id_here", {"power": 1, "speed": 4})
        
        # Turn off fan
        await client.send_command("device_id_here", {"power": 0})

asyncio.run(main())
```

---

### 4. Connected Appliances: Water Purifiers

The library provides abstract state models for Atomberg's connected appliance ecosystem:

```python
from pyatomberg.models.device import DeviceType, WaterPurifierState

# Modeled state structure from mobile app reverse engineering
purifier = WaterPurifierState(
    is_dispensing=False,
    tds_in=450,
    tds_out=38,
    filter_life_remaining_percent=85,
)
print(f"Filter Health: {purifier.filter_life_remaining_percent}% (TDS: {purifier.tds_out} ppm)")
```

---

## Supported Capabilities vs. Known Limitations

To set clear expectations, here are the architectural boundaries of the library:

| Functionality | Supported | Architectural Reason / Detail |
| :--- | :--- | :--- |
| **Direct BLE Lock Control** | Integration | `atomberg-py` provides protocol packet serialization, AES-128 crypto, and key extraction. Live GATT connectivity is managed natively by [`ha-atomberg-lock`](https://github.com/selvakk2k/ha-atomberg-lock). |
| **Offline Lock OTPs** | Yes | Calculated offline via HMAC-SHA256 and IST half-hour time quantization matching lock firmware. |
| **Lock Remote Unlock over Wi-Fi** | No | Atomberg SL1 / SL1 Pro hardware has no onboard Wi-Fi chip. Remote access requires an active BLE proxy (e.g. ESPHome Bluetooth Proxy or local Bluetooth adapter). |
| **Developer API without a Fan** | No | Atomberg mobile app enforces a UI restriction that hides Developer Options if no fan is enrolled. Use Cognito OAuth2 instead. |
| **Fan Local UDP Telemetry** | Yes | Fans broadcast real-time state packets on UDP port 5625. |
| **Water Purifier Cloud Control** | Modeled | Data schemas and models are defined from app disassembly; live hardware verification is pending. |

---

## Testing & Quality Assurance

The test suite contains automated tests covering crypto primitives, CRC16 verification, packet serialization, time quantization, and hardware test vectors:

```bash
# Run pytest test suite
pytest tests/ -v
```

---

## Credits & License

### Disclaimer
`pyatomberg` is an independent, open-source project and is not affiliated with, endorsed by, or sponsored by Atomberg Technologies Pvt. Ltd. All product names, trademarks, and registered trademarks are property of their respective owners.

### Author & Contributors
* **Architecture & Lead Engineering**: [@selvakk2k](https://github.com/selvakk2k)
* **Code Implementation & Engineering**: **Antigravity** (Google DeepMind)
* **Code Review & Pre-Release Auditing**: **Claude** (Anthropic)

Licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See [LICENSE](LICENSE) for details.
