"""Static assets are served no-cache so a UI upgrade shows up immediately.

Without this the browser keeps the old index.html/style.css/app.js after an
update until a manual hard refresh - the "why is it still the old UI?" trap.
"""

import pytest

from netforensicai.web.app import create_app


@pytest.fixture
def client(tmp_path):
    return create_app(tmp_path / "cases").test_client()


@pytest.mark.parametrize("path", ["/", "/style.css", "/app.js", "/index.html"])
def test_static_assets_are_served_no_cache(client, path):
    resp = client.get(path)
    assert resp.status_code == 200
    assert "no-cache" in resp.headers.get("Cache-Control", "")


def test_api_responses_are_not_forced_no_cache(client):
    # The header is scoped to the static frontend, not the JSON API.
    resp = client.get("/api/cases")
    assert resp.status_code == 200
    assert "no-cache" not in resp.headers.get("Cache-Control", "")
