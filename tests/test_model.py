import pytest

from phishguard.model import check


@pytest.mark.parametrize("url", [
    "https://paypal-secure-login.verify-account.top/signin/webscr?cmd=_login",
    "https://appleid.apple.com.security-check.ru/",
    "http://192.168.4.12/wp-admin/office365/login.php",
    "https://misjrg-sav.web.app/",
])
def test_obvious_phishing(url):
    v = check(url)
    assert v.verdict == "phishing"
    assert v.decided_by == "model"
    assert v.reasons, "a phishing verdict must come with reasons"
    assert abs(sum(r.impact for r in v.reasons)) <= 1.0001


@pytest.mark.parametrize("url", [
    "https://en.wikipedia.org/wiki/Phishing",
    "https://stackoverflow.com/questions/231767/what-does-the-yield-keyword-do",
    "https://www.bbc.com/news/technology",
])
def test_ordinary_pages_safe_even_without_reputation(url):
    assert check(url, use_reputation=False).verdict == "safe"


def test_popular_login_page_trusted_by_reputation():
    v = check("https://github.com/login")
    assert v.verdict == "safe" and v.decided_by == "reputation"
    # the model alone is wary of login pages on its own: that is why reputation exists
    assert check("https://github.com/login", use_reputation=False).decided_by == "model"


def test_brand_lookalike_on_free_hosting_not_trusted():
    v = check("https://paypal-login-verify.github.io/")
    assert v.decided_by == "model" and v.verdict != "safe"


def test_shortener_is_suspicious():
    v = check("bit.ly/3xYzAbC")
    assert v.verdict == "suspicious" and v.decided_by == "shortener"


def test_to_dict_is_json_ready():
    d = check("https://appleid.apple.com.security-check.ru/").to_dict()
    assert set(d) >= {"url", "score", "verdict", "decided_by", "reasons", "registered_domain"}
    assert d["registered_domain"] == "security-check.ru"
