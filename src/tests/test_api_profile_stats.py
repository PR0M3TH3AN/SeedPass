from test_api import client


def test_profile_stats_endpoint(client):
    cl, token = client
    stats = {"total_entries": 1}
    # monkeypatch set _pm.get_profile_stats after client fixture started
    import seedpass.api as api

    api.app.state.pm.get_profile_stats = lambda: stats
    res = cl.get("/api/v1/stats", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json() == stats
