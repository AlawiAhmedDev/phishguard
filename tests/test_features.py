from phishguard.features import FEATURE_NAMES, extract, extract_many, normalize, parse


def test_normalize_strips_scheme_and_www():
    assert normalize("HTTPS://WWW.Example.com/A") == "example.com/a"
    assert normalize("example.com") == "example.com"


def test_scheme_does_not_change_features():
    assert extract("http://example.com/login") == extract("https://www.example.com/login")


def test_registered_domain_with_multi_part_suffix():
    p = parse("https://secure.paypal.co.uk.evil.com.br/x")
    assert p.registered_domain == "evil.com.br"
    assert p.subdomain == "secure.paypal.co.uk"


def test_brand_outside_real_domain():
    assert extract("appleid.apple.com.security-check.ru")["brand_outside_domain"] == 1
    assert extract("https://appleid.apple.com/sign-in")["brand_outside_domain"] == 0
    assert extract("evil.top/paypal/login")["brand_outside_domain"] == 1


def test_ip_host():
    assert extract("http://192.168.4.12/login.php")["has_ip"] == 1
    assert extract("http://[2001:db8::1]/x")["has_ip"] == 1
    assert extract("http://example.com")["has_ip"] == 0


def test_punycode_free_hosting_shortener_tld():
    assert extract("xn--pypal-4ve.com")["has_punycode"] == 1
    assert extract("misjrg-sav.web.app")["free_hosting"] == 1
    assert extract("web.app.example.com")["free_hosting"] == 0
    assert extract("bit.ly/abc")["is_shortener"] == 1
    assert extract("win-prize.xyz")["suspicious_tld"] == 1


def test_keywords_and_tokens():
    f = extract("a.com/signin/verify-account?session=5885d80a13c0db1f8e263663d3faee8d")
    assert f["suspicious_words"] >= 3
    assert f["hex_token"] == 1
    assert f["long_token"] == 1


def test_malformed_url_does_not_crash():
    f = extract("http://[broken-ipv6/login")
    assert len(f) == len(FEATURE_NAMES)


def test_vector_shape():
    rows = extract_many(["a.com", "b.org/x?y=1"])
    assert len(rows) == 2 and all(len(r) == len(FEATURE_NAMES) for r in rows)
