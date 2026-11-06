"""Atomberg smart BLDC ceiling fan device controller."""

import logging
from typing import TYPE_CHECKING, Any, Callable

from pyatomberg.models.device import AtombergDeviceModel, DeviceType, FanState

if TYPE_CHECKING:
    from pyatomberg.client import AtombergClient

_LOGGER = logging.getLogger(__name__)


class AtombergFan(AtombergDeviceModel):
    """Represents an Atomberg smart ceiling fan (Renesa, Aris, Studio+, etc.)."""

    def __init__(
        self,
        device_id: str,
        name: str,
        client: "AtombergClient | None" = None,
        model_name: str | None = None,
        is_online: bool = True,
        raw_data: dict[str, Any] | None = None,
    ) -> None:
        """Initialize an AtombergFan instance."""
        super().__init__(
            device_id=device_id,
            name=name,
            device_type=DeviceType.FAN,
            is_online=is_online,
            model_name=model_name,
            raw_data=raw_data or {},
        )
        self.client = client
        self.state = FanState()
        self._update_callbacks: list[Callable[["AtombergFan"], None]] = []

        if raw_data:
            self.update_from_dict(raw_data)

    def register_callback(self, callback: Callable[["AtombergFan"], None]) -> None:
        """Register a callback for state changes."""
        if callback not in self._update_callbacks:
            self._update_callbacks.append(callback)

    def unregister_callback(self, callback: Callable[["AtombergFan"], None]) -> None:
        """Unregister a state change callback."""
        if callback in self._update_callbacks:
            self._update_callbacks.remove(callback)

    def _notify_callbacks(self) -> None:
        """Notify registered listeners of a state change."""
        for cb in self._update_callbacks:
            try:
                cb(self)
            except Exception as ex:
                _LOGGER.exception(
                    "Error executing fan state change callback for device %s: %s",
                    self.device_id,
                    ex,
                )

    def update_from_dict(self, data: dict[str, Any]) -> None:
        """Update live state from cloud response or local UDP broadcast packet."""
        if "power" in data:
            self.state.power = bool(data["power"])

        if "speed" in data:
            try:
                self.state.speed = int(data["speed"])
            except (ValueError, TypeError):
                pass

        if "sleep" in data:
            self.state.sleep = bool(data["sleep"])

        if "timer" in data or "timer_hours" in data:
            val = data.get("timer_hours", data.get("timer", 0))
            try:
                self.state.timer_hours = int(val)
            except (ValueError, TypeError):
                pass

        if "led" in data or "led_brightness" in data:
            val = data.get("led_brightness", data.get("led"))
            try:
                self.state.led_brightness = int(val) if val is not None else None
            except (ValueError, TypeError):
                pass

        if "light_mode" in data:
            self.state.light_mode = str(data["light_mode"])

        if "last_seen" in data:
            try:
                self.state.last_seen = float(data["last_seen"])
            except (ValueError, TypeError):
                pass

        if "online" in data:
            self.is_online = bool(data["online"])

        self._notify_callbacks()

    async def send_command(self, command: dict[str, Any]) -> dict[str, Any]:
        """Dispatch command to this fan via client."""
        if not self.client:
            raise RuntimeError("AtombergFan has no associated client to send commands")
        return await self.client.send_command(self.device_id, command)

    async def turn_on(self, speed: int | None = None) -> None:
        """Turn the fan on, optionally setting speed (1-6)."""
        cmd: dict[str, Any] = {"power": True}
        if speed is not None:
            cmd["speed"] = max(1, min(6, speed))
        await self.send_command(cmd)
        self.state.power = True
        if speed is not None:
            self.state.speed = cmd["speed"]
        self._notify_callbacks()

    async def turn_off(self) -> None:
        """Turn the fan off."""
        await self.send_command({"power": False})
        self.state.power = False
        self._notify_callbacks()

    async def set_speed(self, speed: int) -> None:
        """Set the fan speed between 1 and 6."""
        valid_speed = max(1, min(6, speed))
        await self.send_command({"power": True, "speed": valid_speed})
        self.state.power = True
        self.state.speed = valid_speed
        self._notify_callbacks()

    async def set_sleep(self, sleep: bool) -> None:
        """Toggle sleep mode."""
        await self.send_command({"sleep": sleep})
        self.state.sleep = sleep
        self._notify_callbacks()

    async def set_timer(self, hours: int) -> None:
        """Set fan shutdown timer in hours (0 to disable)."""
        await self.send_command({"timer_hours": hours})
        self.state.timer_hours = hours
        self._notify_callbacks()

    async def set_led(self, brightness: int, light_mode: str | None = None) -> None:
        """Set LED brightness (0-100) and optional light mode."""
        cmd: dict[str, Any] = {"led": max(0, min(100, brightness))}
        if light_mode:
            cmd["light_mode"] = light_mode
        await self.send_command(cmd)
        self.state.led_brightness = cmd["led"]
        if light_mode:
            self.state.light_mode = light_mode
        self._notify_callbacks()
