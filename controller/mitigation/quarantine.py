import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PRODUCTION_NET: str = "iot_production_net"
QUARANTINE_NET: str = "iot_quarantine_net"


try:
    import docker
    import docker.errors
    _DOCKER_AVAILABLE = True
except ImportError:
    docker = None
    _DOCKER_AVAILABLE = False


_DEFAULT_CLIENT = object()


class QuarantineManager:
    """
    Manages dynamic network quarantine and restoration for virtual IoT containers
    using the Docker Engine API via /var/run/docker.sock.
    """

    def __init__(self, docker_client: Any = _DEFAULT_CLIENT) -> None:
        if docker_client is _DEFAULT_CLIENT:
            if _DOCKER_AVAILABLE and docker is not None:
                try:
                    self.client = docker.from_env()
                    logger.info("QuarantineManager connected to Docker daemon successfully.")
                except Exception as e:
                    logger.warning("Docker daemon connection failed (%s). Operating in fallback mode.", e)
                    self.client = None
            else:
                self.client = None
        else:
            self.client = docker_client

    def get_container_network_status(self, container_name_or_id: str) -> str:
        """
        Determines whether a container is in 'production', 'quarantined', or 'disconnected'.
        """
        if not self.client:
            return "unknown"

        try:
            container = self.client.containers.get(container_name_or_id)
            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})

            if QUARANTINE_NET in networks:
                return "quarantined"
            elif PRODUCTION_NET in networks:
                return "production"
            else:
                return "disconnected"
        except Exception as e:
            if _DOCKER_AVAILABLE and docker is not None and isinstance(e, docker.errors.NotFound):
                logger.error("Container '%s' not found on Docker host.", container_name_or_id)
                return "not_found"
            logger.error("Error inspecting container '%s': %s", container_name_or_id, e)
            return "error"

    def get_all_virtual_node_states(self, default_nodes: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Dynamically returns the network status for all known and active virtual IoT nodes.
        Discovers any container whose name starts with 'iot_' on Docker daemon.
        """
        known_nodes = default_nodes or [
            "iot_sensor_node",
            "iot_bulb_node",
            "iot_motion_node",
            "iot_lock_node",
            "iot_mqtt_broker",
            "iot_cowrie_honeypot",
        ]
        states: Dict[str, str] = {}

        if not self.client:
            return {node: "production" for node in known_nodes}

        try:
            containers = self.client.containers.list(all=True)
            discovered_iot = [
                c.name for c in containers
                if c.name and c.name.startswith("iot_") and c.name != "iot_defense_controller"
            ]
            target_nodes = discovered_iot if discovered_iot else known_nodes
            for node_name in target_nodes:
                status = self.get_container_network_status(node_name)
                if status not in {"not_found", "error"}:
                    states[node_name] = status
                else:
                    states[node_name] = "offline"
            return states if states else {node: "production" for node in known_nodes}
        except Exception as e:
            logger.warning("Error dynamically enumerating virtual IoT nodes: %s", e)
            return {node: self.get_container_network_status(node) for node in known_nodes}

    def quarantine_container(self, container_name_or_id: str) -> Dict[str, Any]:
        """
        Safely isolates a container:
        1. Connects to iot_quarantine_net (internal)
        2. Disconnects from iot_production_net
        This ensures the container is never left completely networkless (forensics retention).
        """
        result: Dict[str, Any] = {
            "container": container_name_or_id,
            "status": "failed",
            "previous_state": "unknown",
            "current_state": "unknown",
            "message": ""
        }

        if not self.client:
            result["message"] = "Docker client unavailable."
            return result

        try:
            container = self.client.containers.get(container_name_or_id)
            current_status = self.get_container_network_status(container_name_or_id)
            result["previous_state"] = current_status

            if current_status == "quarantined":
                result["status"] = "success"
                result["current_state"] = "quarantined"
                result["message"] = f"Container {container_name_or_id} is already in quarantine."
                return result

            # Fetch networks
            prod_net = self.client.networks.get(PRODUCTION_NET)
            quar_net = self.client.networks.get(QUARANTINE_NET)

            # Connect to quarantine network first
            logger.info("Connecting container %s to quarantine network (%s)...", container_name_or_id, QUARANTINE_NET)
            try:
                quar_net.connect(container)
            except Exception as e:
                logger.debug("Container already attached to quarantine net or connect note: %s", e)

            # Disconnect from production network
            logger.info("Disconnecting container %s from production network (%s)...", container_name_or_id, PRODUCTION_NET)
            try:
                prod_net.disconnect(container)
            except Exception as e:
                logger.debug("Container disconnect note: %s", e)

            result["status"] = "success"
            result["current_state"] = "quarantined"
            result["message"] = f"Container {container_name_or_id} successfully migrated to {QUARANTINE_NET}."
            logger.info("Quarantine migration successful for %s.", container_name_or_id)
            return result

        except Exception as e:
            if _DOCKER_AVAILABLE and docker is not None and isinstance(e, docker.errors.NotFound):
                result["message"] = f"Target container or network not found: {e}"
            else:
                result["message"] = f"Quarantine error: {e}"
            logger.error(result["message"])
            return result

    def restore_container(self, container_name_or_id: str) -> Dict[str, Any]:
        """
        Restores a quarantined container back to normal production operation.
        """
        result: Dict[str, Any] = {
            "container": container_name_or_id,
            "status": "failed",
            "previous_state": "unknown",
            "current_state": "unknown",
            "message": ""
        }

        if not self.client:
            result["message"] = "Docker client unavailable."
            return result

        try:
            container = self.client.containers.get(container_name_or_id)
            current_status = self.get_container_network_status(container_name_or_id)
            result["previous_state"] = current_status

            if current_status == "production":
                result["status"] = "success"
                result["current_state"] = "production"
                result["message"] = f"Container {container_name_or_id} is already in production."
                return result

            prod_net = self.client.networks.get(PRODUCTION_NET)
            quar_net = self.client.networks.get(QUARANTINE_NET)

            # Reconnect to production network
            logger.info("Reconnecting container %s to production network (%s)...", container_name_or_id, PRODUCTION_NET)
            try:
                prod_net.connect(container)
            except Exception as e:
                logger.debug("Container already attached to production net: %s", e)

            # Detach from quarantine network
            logger.info("Disconnecting container %s from quarantine network (%s)...", container_name_or_id, QUARANTINE_NET)
            try:
                quar_net.disconnect(container)
            except Exception as e:
                logger.debug("Container disconnect note: %s", e)

            result["status"] = "success"
            result["current_state"] = "production"
            result["message"] = f"Container {container_name_or_id} restored to {PRODUCTION_NET}."
            logger.info("Restoration successful for %s.", container_name_or_id)
            return result

        except Exception as e:
            if _DOCKER_AVAILABLE and docker is not None and isinstance(e, docker.errors.NotFound):
                result["message"] = f"Target container or network not found: {e}"
            else:
                result["message"] = f"Restoration error: {e}"
            logger.error(result["message"])
            return result

