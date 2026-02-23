from types import SimpleNamespace
import queue
import pytest
import seedpass.api as api


@pytest.mark.anyio
async def test_notifications_endpoint(client):
    cl, token = client
    api.app.state.pm.notifications = queue.Queue()
    api.app.state.pm.notifications.put(SimpleNamespace(message="m1", level="INFO"))
    api.app.state.pm.notifications.put(SimpleNamespace(message="m2", level="WARNING"))
    res = await cl.get(
        "/api/v1/notifications", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    assert res.json() == [
        {"level": "INFO", "message": "m1"},
        {"level": "WARNING", "message": "m2"},
    ]
    assert api.app.state.pm.notifications.empty()


@pytest.mark.anyio
async def test_notifications_endpoint_clears_queue(client):
    cl, token = client
    api.app.state.pm.notifications = queue.Queue()
    api.app.state.pm.notifications.put(SimpleNamespace(message="hi", level="INFO"))
    res = await cl.get(
        "/api/v1/notifications", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    assert res.json() == [{"level": "INFO", "message": "hi"}]
    assert api.app.state.pm.notifications.empty()
    res = await cl.get(
        "/api/v1/notifications", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.json() == []


@pytest.mark.anyio
async def test_notifications_endpoint_does_not_clear_current(client):
    cl, token = client
    api.app.state.pm.notifications = queue.Queue()
    msg = SimpleNamespace(message="keep", level="INFO")
    api.app.state.pm.notifications.put(msg)
    api.app.state.pm._current_notification = msg
    api.app.state.pm.get_current_notification = (
        lambda: api.app.state.pm._current_notification
    )

    res = await cl.get(
        "/api/v1/notifications", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    assert res.json() == [{"level": "INFO", "message": "keep"}]
    assert api.app.state.pm.notifications.empty()
    assert api.app.state.pm.get_current_notification() is msg
