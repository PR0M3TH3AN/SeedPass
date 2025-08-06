from test_api import client
import pytest


@pytest.mark.anyio
async def test_profile_stats_endpoint(client):
    cl, token = client
    stats = {"total_entries": 1}
    import seedpass.api as api

    api.app.state.pm.get_profile_stats = lambda: stats
    res = await cl.get("/api/v1/stats", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json() == stats
