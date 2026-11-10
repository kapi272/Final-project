import asyncio
import json
import logging
import os
from typing import Any, Callable, Coroutine, Optional

from controller.core.models import CowrieEvent

logger = logging.getLogger(__name__)

DEFAULT_LOG_PATH: str = os.path.join("honeypot", "logs", "cowrie.json")


class HoneypotLogTailer:
    """
    Asynchronous file-pointer tailer for cowrie.json.
    Continuously yields parsed CowrieEvent records without blocking the event loop.
    """

    def __init__(
        self,
        log_path: str = DEFAULT_LOG_PATH,
        on_event_callback: Optional[Callable[[CowrieEvent], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        self.log_path: str = log_path
        self.on_event_callback = on_event_callback
        self.running: bool = False
        self._file_handle: Optional[Any] = None

    async def start(self) -> None:
        """Starts tailing the cowrie.json file continuously."""
        self.running = True
        logger.info("Starting HoneypotLogTailer monitoring: %s", self.log_path)

        # Wait until the file exists if honeypot is still booting
        while self.running and not os.path.exists(self.log_path):
            logger.debug("Waiting for honeypot log file at %s to be created...", self.log_path)
            await asyncio.sleep(1.0)

        if not self.running:
            return

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                # Seek to end of file to tail only new events
                f.seek(0, os.SEEK_END)
                logger.info("HoneypotLogTailer attached to %s (seeking to EOF).", self.log_path)

                while self.running:
                    line = f.readline()
                    if line:
                        stripped = line.strip()
                        if not stripped:
                            continue
                        try:
                            parsed_json = json.loads(stripped)
                            event = CowrieEvent.from_cowrie_json(parsed_json)
                            if self.on_event_callback:
                                await self.on_event_callback(event)
                        except json.JSONDecodeError as err:
                            logger.warning("Malformed JSON line in honeypot log: %s", err)
                        except Exception as e:
                            logger.error("Error processing honeypot event: %s", e)
                    else:
                        # Non-blocking pause before polling next line
                        await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            logger.info("HoneypotLogTailer task cancelled.")
        except Exception as e:
            logger.error("HoneypotLogTailer encountered unexpected error: %s", e)
        finally:
            self.running = False
            logger.info("HoneypotLogTailer stopped.")

    def stop(self) -> None:
        """Signals the tailer loop to terminate cleanly."""
        self.running = False

