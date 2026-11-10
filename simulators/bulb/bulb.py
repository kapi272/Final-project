import json
import logging
import os
import signal
import sys
import time
from typing import Any, Dict

import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [BulbSim] %(message)s"
)
logger = logging.getLogger(__name__)

BROKER_HOST: str = os.getenv("MQTT_BROKER_HOST", "172.20.0.10")
BROKER_PORT: int = int(os.getenv("MQTT_BROKER_PORT", "1883"))
DEVICE_ID: str = os.getenv("DEVICE_ID", "smart_bulb_01")
SET_TOPIC: str = os.getenv("MQTT_SET_TOPIC", "home/devices/bulb/set")
STATUS_TOPIC: str = os.getenv("MQTT_STATUS_TOPIC", "home/devices/bulb/status")

bulb_state: Dict[str, Any] = {
    "device_id": DEVICE_ID,
    "state": "ON",
    "brightness": 80,
    "color": "#fffaed",
    "updated_at": time.time()
}

running: bool = True


def handle_shutdown(signum: int, frame: Any) -> None:
    global running
    logger.info("Shutdown signal received (%s). Exiting...", signum)
    running = False


signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)


def on_message(client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
    try:
        raw_payload = msg.payload.decode("utf-8")
        logger.info("Command received on %s: %s", msg.topic, raw_payload)
        payload = json.loads(raw_payload)

        if "state" in payload:
            bulb_state["state"] = str(payload["state"]).upper()
        if "brightness" in payload:
            bulb_state["brightness"] = int(payload["brightness"])
        if "color" in payload:
            bulb_state["color"] = str(payload["color"])

        bulb_state["updated_at"] = time.time()
        client.publish(STATUS_TOPIC, json.dumps(bulb_state), qos=0)
        logger.info("State updated and broadcast to %s: %s", STATUS_TOPIC, bulb_state)
    except Exception as e:
        logger.error("Failed to parse command payload: %s", e)


def create_mqtt_client() -> mqtt.Client:
    if hasattr(mqtt, "CallbackAPIVersion"):
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=DEVICE_ID)
    else:
        client = mqtt.Client(client_id=DEVICE_ID)
    client.on_message = on_message
    return client


def main() -> None:
    logger.info("Starting Smart Bulb Simulator [%s]", DEVICE_ID)
    client = create_mqtt_client()

    connected = False
    while running and not connected:
        try:
            logger.info("Connecting to MQTT broker at %s:%d...", BROKER_HOST, BROKER_PORT)
            client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
            client.subscribe(SET_TOPIC)
            client.loop_start()
            connected = True
            logger.info("Connected and subscribed to %s", SET_TOPIC)
        except Exception as e:
            logger.warning("Broker connection failed (%s). Retrying in 3 seconds...", e)
            time.sleep(3)

    try:
        while running:
            bulb_state["updated_at"] = time.time()
            client.publish(STATUS_TOPIC, json.dumps(bulb_state), qos=0)
            time.sleep(5.0)
    finally:
        logger.info("Disconnecting client from broker...")
        client.loop_stop()
        client.disconnect()
        logger.info("Bulb simulator stopped cleanly.")


if __name__ == "__main__":
    main()

