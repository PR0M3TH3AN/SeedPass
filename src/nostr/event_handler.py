# nostr/event_handler.py

import datetime
import time
import traceback

from .logging_config import configure_logging
from monstr.event.event import Event
from monstr.client.client import ClientPool

logger = configure_logging()

class EventHandler:
    """
    Handles incoming Nostr events.
    """

    def __init__(self):
        pass  # Initialize if needed

    def handle_new_event(self, the_client: ClientPool, sub_id: str, evt: Event):
        """
        Processes incoming events by logging their details.

        :param the_client: The ClientPool instance.
        :param sub_id: The subscription ID.
        :param evt: The received Event object.
        """
        try:
            if isinstance(evt.created_at, datetime.datetime):
                created_at_str = evt.created_at.strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(evt.created_at, int):
                created_at_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(evt.created_at))
            else:
                created_at_str = str(evt.created_at)

            logger.info(f"\n[New Event] ID: {evt.id}\nCreated At: {created_at_str}\nContent: {evt.content}\n")
        except Exception as e:
            logger.error(f"Error handling new event: {e}")
            logger.error(traceback.format_exc())
            raise
