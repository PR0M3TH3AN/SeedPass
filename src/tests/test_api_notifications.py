from test_api import client
from types import SimpleNamespace
import queue
import seedpass.api as api


def test_notifications_endpoint(client):
    cl, token = client
    api._pm.notifications = queue.Queue()
    api._pm.notifications.put(SimpleNamespace(message="m1", level="INFO"))
    api._pm.notifications.put(SimpleNamespace(message="m2", level="WARNING"))
    res = cl.get("/api/v1/notifications", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json() == [
        {"level": "INFO", "message": "m1"},
        {"level": "WARNING", "message": "m2"},
    ]
    assert api._pm.notifications.empty()


def test_notifications_endpoint_clears_queue(client):
    cl, token = client
    api._pm.notifications = queue.Queue()
    api._pm.notifications.put(SimpleNamespace(message="hi", level="INFO"))
    res = cl.get("/api/v1/notifications", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json() == [{"level": "INFO", "message": "hi"}]
    assert api._pm.notifications.empty()
    res = cl.get("/api/v1/notifications", headers={"Authorization": f"Bearer {token}"})
    assert res.json() == []


def test_notifications_endpoint_does_not_clear_current(client):
    cl, token = client
    api._pm.notifications = queue.Queue()
    msg = SimpleNamespace(message="keep", level="INFO")
    api._pm.notifications.put(msg)
    api._pm._current_notification = msg
    api._pm.get_current_notification = lambda: api._pm._current_notification

    res = cl.get("/api/v1/notifications", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json() == [{"level": "INFO", "message": "keep"}]
    assert api._pm.notifications.empty()
    assert api._pm.get_current_notification() is msg
