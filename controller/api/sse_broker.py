import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


class SSEBroadcaster:
    """
    Manages subscriber queues for non-buffering Server-Sent Events (SSE).
    Distributes intrusion alerts, system health states, and heartbeats to connected clients.
    """

    def __init__(self) -> None:
        self._subscribers: Set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        """Registers a new client stream queue."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers.add(queue)
            logger.info("New SSE client subscribed. Total active listeners: %d", len(self._subscribers))
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Removes a disconnected client queue."""
        async with self._lock:
            self._subscribers.discard(queue)
            logger.info("SSE client disconnected. Remaining listeners: %d", len(self._subscribers))

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Dispatches a typed message payload to all active client queues.
        """
        payload = {
            "event": event_type,
            "timestamp": time.time(),
            "data": data,
        }
        sse_frame = f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"

        async with self._lock:
            dead_queues: List[asyncio.Queue] = []
            for queue in self._subscribers:
                try:
                    queue.put_nowait(sse_frame)
                except asyncio.QueueFull:
                    # Drop slow consumer to protect server throughput
                    logger.warning("Subscriber queue is full. Evicting slow client.")
                    dead_queues.append(queue)

            for dead in dead_queues:
                self._subscribers.discard(dead)
