import logging
import os
import uvicorn
from controller.api.app import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [DefenseController] %(message)s"
)

app = create_app(enable_mqtt=os.getenv("ENABLE_MQTT", "true").lower() == "true")

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("controller.main:app", host=host, port=port, reload=False)

