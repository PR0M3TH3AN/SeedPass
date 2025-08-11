# nostr/event_handler.py

import time
import logging

from nostr_sdk import Event


# Instantiate the logger
logger = logging.getLogger(__name__)


class EventHandler:
    """
    Handles incoming Nostr events.
    """

    def __init__(self):
        pass  # Initialize if needed

    def handle_new_event(self, evt: Event):
        """Process and log details from a Nostr event."""

        try:
            created_at = evt.created_at().as_secs()
            created_at_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(created_at))
            event_id = evt.id().to_hex()

            logger.info(
                f"[New Event] ID: {event_id} | Created At: {created_at_str} | Content: {evt.content()}"
            )
        except Exception as e:
            logger.error(f"Error handling new event: {e}", exc_info=True)
