import io
import zipfile

from phishguard.reputation import clean_list, is_trusted, parse_tranco_zip


def test_popular_domain_trusted():
    assert is_trusted("github.com", "github.com")
    assert is_trusted("paypal.com", "www.paypal.com")


def test_user_content_platforms_never_trusted():
    assert not is_trusted("github.io", "evil.github.io")
    assert not is_trusted("google.com", "sites.google.com")
    assert not is_trusted("bit.ly", "bit.ly")


def test_unknown_domain_not_trusted():
    assert not is_trusted("security-check.ru", "appleid.apple.com.security-check.ru")


def test_clean_list_dedup_and_filter():
    assert clean_list(["www.A.com", "a.com", "# c", "", "web.app", "b.org"]) == ["a.com", "b.org"]


def test_parse_tranco_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("top-1m.csv", "1,google.com\n2,firebaseapp.com\n3,example.org\n4,x.net\n")
    assert parse_tranco_zip(buf.getvalue(), top=3) == ["google.com", "example.org"]
