from collections import defaultdict
from typing import Callable, Dict, List, Any


class PubSub:
    """Simple in-process event bus using the observer pattern."""

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callable[..., None]]] = defaultdict(list)

    def subscribe(self, event: str, callback: Callable[..., None]) -> None:
        """Register ``callback`` to be invoked when ``event`` is published."""
        self._subscribers[event].append(callback)

    def unsubscribe(self, event: str, callback: Callable[..., None]) -> None:
        """Unregister ``callback`` from ``event`` notifications."""
        if callback in self._subscribers.get(event, []):
            self._subscribers[event].remove(callback)

    def publish(self, event: str, *args: Any, **kwargs: Any) -> None:
        """Notify all subscribers of ``event`` passing ``*args`` and ``**kwargs``."""
        for callback in list(self._subscribers.get(event, [])):
            callback(*args, **kwargs)


# Global bus instance for convenience
bus = PubSub()
