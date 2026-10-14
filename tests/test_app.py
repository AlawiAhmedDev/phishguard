import pytest

from phishguard.app import create_app


@pytest.fixture()
def client():
    return create_app().test_client()


def test_page(client):
    r = client.get("/")
    assert r.status_code == 200 and b"PhishGuard" in r.data


def test_api_get_and_post(client):
    r = client.get("/api/check", query_string={"url": "https://appleid.apple.com.security-check.ru/"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["verdict"] == "phishing"
    assert d["anatomy"]["registered_domain"] == "security-check.ru"
    assert d["anatomy"]["subdomain"] == "appleid.apple.com"
    r = client.post("/api/check", json={"url": "https://github.com/login"})
    assert r.get_json()["decided_by"] == "reputation"


def test_api_errors(client):
    assert client.get("/api/check").status_code == 400
    assert client.post("/api/check", json={"url": "a" * 3000}).status_code == 400
