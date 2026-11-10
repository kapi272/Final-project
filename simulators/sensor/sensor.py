import json
import logging
import os
import random
import signal
import sys
import time
from typing import Any, Dict

import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SensorSim] %(message)s"
)
logger = logging.getLogger(__name__)

BROKER_HOST: str = os.getenv("MQTT_BROKER_HOST", "172.20.0.10")
BROKER_PORT: int = int(os.getenv("MQTT_BROKER_PORT", "1883"))
DEVICE_ID: str = os.getenv("DEVICE_ID", "temp_sensor_01")
TOPIC: str = os.getenv("MQTT_TOPIC", "home/sensors/temperature")
PUBLISH_INTERVAL: float = float(os.getenv("PUBLISH_INTERVAL", "2.0"))

running: bool = True


def handle_shutdown(signum: int, frame: Any) -> None:
    global running
    logger.info("Shutdown signal received (%s). Exiting...", signum)
    running = False


signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)


def create_mqtt_client() -> mqtt.Client:
    if hasattr(mqtt, "CallbackAPIVersion"):
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=DEVICE_ID)
    else:
        client = mqtt.Client(client_id=DEVICE_ID)
    return client


def main() -> None:
    logger.info("Starting Temperature Sensor Simulator [%s]", DEVICE_ID)
    client = create_mqtt_client()

    connected = False
    while running and not connected:
        try:
            logger.info("Connecting to MQTT broker at %s:%d...", BROKER_HOST, BROKER_PORT)
            client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
            client.loop_start()
            connected = True
            logger.info("Connected to broker successfully.")
        except Exception as e:
            logger.warning("Broker connection failed (%s). Retrying in 3 seconds...", e)
            time.sleep(3)

    base_temp: float = 22.0

    try:
        while running:
            current_temp = round(base_temp + random.uniform(-0.8, 0.8), 2)
            payload: Dict[str, Any] = {
                "device_id": DEVICE_ID,
                "temperature": current_temp,
                "unit": "C",
                "timestamp": time.time()
            }
            client.publish(TOPIC, json.dumps(payload), qos=0)
            logger.info("Published to %s: %s", TOPIC, payload)
            time.sleep(PUBLISH_INTERVAL)
    finally:
        logger.info("Disconnecting client from broker...")
        client.loop_stop()
        client.disconnect()
        logger.info("Sensor simulator stopped cleanly.")


if __name__ == "__main__":
    main()
