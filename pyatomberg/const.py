"""Constants for pyatomberg."""

from typing import Final

# Cloud & Authentication Endpoints
COGNITO_REGION: Final[str] = "ap-south-1"
COGNITO_USER_POOL_ID: Final[str] = "ap-south-1_fMZyKIlR2"
COGNITO_CLIENT_ID: Final[str] = "3cr9rf3urr1jvpn46fsd377uv0"
COGNITO_DOMAIN: Final[str] = "auth.atomberg-iot.com"
COGNITO_AUTHORIZE_URL: Final[str] = f"https://{COGNITO_DOMAIN}/oauth2/authorize"
COGNITO_TOKEN_URL: Final[str] = f"https://{COGNITO_DOMAIN}/oauth2/token"
COGNITO_REDIRECT_URI: Final[str] = "https://app.atomberg-iot.com"

SERVER_API_BASE: Final[str] = "https://server.atomberg-iot.com"
DEVELOPER_API_BASE: Final[str] = "https://api.developer.atomberg-iot.com/v2"

# Firebase Firestore Cloud History
FIREBASE_API_KEY: Final[str] = "AIzaSyBowISrLGjKvmHN95NEvylMjgdR0ExPlUo"
FIREBASE_PROJECT_ID: Final[str] = "firestore-test-65c75"

# Fan Local Subnet UDP Port
FAN_UDP_PORT: Final[int] = 5625
FAN_UDP_MAGIC_PREFIX: Final[bytes] = b"PROXY TCP4 "

# Smart Lock (Haosj BLE) GATT Profile
LOCK_SERVICE_UUID: Final[str] = "0000fff0-0000-1000-8000-00805f9b34fb"
LOCK_WRITE_CHAR_UUID: Final[str] = "0000fff1-0000-1000-8000-00805f9b34fb"
LOCK_NOTIFY_CHAR_UUID: Final[str] = "0000fff2-0000-1000-8000-00805f9b34fb"

# Haosj HSJ Cryptography and Framing
HSJ_HEADER: Final[bytes] = b"HSJ"
HSJ_FACTORY_KEY: Final[bytes] = b"mQ3cJOATdERLW1a5"

# HSJ Command Categories
HSJ_CMD_HEARTBEAT: Final[int] = 0x0001
HSJ_CMD_STATUS: Final[int] = 0x0002
HSJ_CMD_UNLOCK: Final[int] = 0x0003
HSJ_CMD_EVENT_LOG: Final[int] = 0x000A
HSJ_CMD_PAIRING: Final[int] = 0x000F

# HSJ Unlock Credential Categories
HSJ_EVENT_APP_REMOTE: Final[int] = 0x00
HSJ_EVENT_FINGERPRINT: Final[int] = 0x01
HSJ_EVENT_PIN: Final[int] = 0x02
HSJ_EVENT_NFC: Final[int] = 0x04
HSJ_EVENT_ACCESS_DENIED: Final[int] = 0x36
HSJ_EVENT_AUTO_LOCK: Final[int] = 0x3D
