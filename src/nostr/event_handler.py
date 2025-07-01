# nostr/event_handler.py

import time
import logging
import traceback

try:
    from monstr.event.event import Event
except ImportError:  # pragma: no cover - optional dependency

    class Event:  # minimal placeholder for type hints when monstr is absent
        id: str
        created_at: int
        content: str


# Instantiate the logger
logger = logging.getLogger(__name__)


class EventHandler:
    """
    Handles incoming Nostr events.
    """

    def __init__(self):
        pass  # Initialize if needed

    def handle_new_event(self, evt: Event):
        """
        Processes incoming events by logging their details.

        :param evt: The received Event object.
        """
        try:
            # Assuming evt.created_at is always an integer Unix timestamp
            if isinstance(evt.created_at, int):
                created_at_str = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(evt.created_at)
                )
            else:
                # Handle unexpected types gracefully
                created_at_str = str(evt.created_at)

            # Log the event details without extra newlines
            logger.info(
                f"[New Event] ID: {evt.id} | Created At: {created_at_str} | Content: {evt.content}"
            )
        except Exception as e:
            logger.error(f"Error handling new event: {e}", exc_info=True)
            # Optionally, handle the exception without re-raising
            # For example, continue processing other events
