import asyncio
import logging
import os
import time
from typing import Any, Callable, Optional
import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)


class IoTTelemetryListener:
    """
    Background subscriber listening to MQTT broker telemetry from virtual IoT nodes
    and forwarding message frames to the SOC SSE broadcaster.
    """

    def __init__(
        self,
        broker_host: str = "172.20.0.10",
        broker_port: int = 1883,
        topic: str = "home/#",
        loop: Optional[asyncio.AbstractEventLoop] = None,
        on_message_callback: Optional[Callable[[str, str, float], Any]] = None,
    ) -> None:
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.topic = topic
        self.loop = loop
        self.on_message_callback = on_message_callback
        self.client: Optional[mqtt.Client] = None
        self._running: bool = False

    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        """Initializes the non-blocking background network loop and connects to the broker."""
        if self._running:
            return
        if loop:
            self.loop = loop

        self._running = True
        try:
            if hasattr(mqtt, "CallbackAPIVersion"):
                self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id="iot_soc_listener")
            else:
                self.client = mqtt.Client(client_id="iot_soc_listener")

            self.client.on_connect = self._on_connect
            self.client.on_message = self._on_message
            # connect_async avoids blocking startup if the broker is booting
            self.client.connect_async(self.broker_host, self.broker_port, keepalive=60)
            self.client.loop_start()
            logger.info("IoT Telemetry MQTT subscriber started -> %s:%d (%s)", self.broker_host, self.broker_port, self.topic)
        except Exception as e:
            logger.warning("IoT Telemetry MQTT subscriber initialization failed: %s", e)

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: int) -> None:
        if rc == 0:
            logger.info("Connected to MQTT broker at %s:%d. Subscribing to '%s'", self.broker_host, self.broker_port, self.topic)
            try:
                client.subscribe(self.topic)
            except Exception as e:
                logger.error("Failed to subscribe to MQTT topic %s: %s", self.topic, e)
        else:
            logger.warning("MQTT broker connection returned status code %d", rc)

    def _on_message(self, client: Any, userdata: Any, msg: Any) -> None:
        if not self._running:
            return
        try:
            payload = msg.payload.decode("utf-8", errors="replace")
            topic = msg.topic
            ts = time.time()

            if self.on_message_callback:
                if self.loop and self.loop.is_running():
                    res = self.on_message_callback(topic, payload, ts)
                    if asyncio.iscoroutine(res):
                        asyncio.run_coroutine_threadsafe(res, self.loop)
                else:
                    self.on_message_callback(topic, payload, ts)
        except Exception as e:
            logger.error("Error processing incoming MQTT message: %s", e)

    def stop(self) -> None:
        """Gracefully disconnects and terminates the background loop."""
        self._running = False
        if self.client:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass
            self.client = None
        logger.info("IoT Telemetry MQTT subscriber stopped.")

