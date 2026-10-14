"""Lexical feature extraction for URLs.

PhishGuard never visits, resolves or downloads a URL: every feature is computed
from the URL string alone. That keeps analysis instant, offline and safe to run
on live phishing links.

The scheme (http/https) and a leading ``www.`` are removed before extraction on
purpose. In the public datasets used for training, legitimate URLs carry no
scheme at all while recent phishing URLs nearly always do, so a model that saw
the scheme would learn the dataset, not phishing.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

# Offline extractor: uses the public-suffix snapshot bundled with tldextract,
# never fetches the list over the network.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_WORDS = (
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification",
    "account", "update", "secure", "security", "banking", "confirm", "password",
    "passwd", "credential", "webscr", "cmd=", "ebayisapi", "wallet", "unlock",
    "suspend", "restore", "recover", "billing", "invoice", "payment", "auth",
    "validate", "session", "token", "support", "helpdesk", "alert", "free",
    "bonus", "gift", "claim", "reward",
)

BRANDS = (
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "hotmail",
    "onedrive", "sharepoint", "amazon", "netflix", "google", "gmail",
    "facebook", "instagram", "whatsapp", "linkedin", "dropbox",
    "docusign", "adobe", "dhl", "fedex", "usps", "wellsfargo",
    "bankofamerica", "citibank", "hsbc", "santander", "barclays", "binance",
    "coinbase", "metamask", "roblox", "yahoo",
    "verizon", "ebay", "walmart", "mastercard",
    "americanexpress", "naver", "allegro", "attijariwafa", "cihbank", "bmce",
)

SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click",
    "link", "work", "support", "rest", "fit", "country", "kim", "loan", "men",
    "date", "racing", "review", "stream", "download", "party", "trade", "cam",
    "icu", "monster", "cyou", "sbs", "cfd", "lol", "quest", "shop", "online",
    "site", "live", "help", "life", "info", "vip", "pw", "cc", "ws",
})

FREE_HOSTING = (
    "firebaseapp.com", "web.app", "workers.dev", "pages.dev", "github.io",
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com",
    "herokuapp.com", "netlify.app", "vercel.app", "glitch.me", "repl.co",
    "ngrok.io", "ngrok-free.app", "azurewebsites.net", "appspot.com",
    "sites.google.com", "webflow.io", "square.site", "godaddysites.com",
    "ipfs.io", "r2.dev", "framer.app", "wordpress.com", "mybluehost.me",
    "ewp.live", "translate.goog", "duckdns.org", "glitch.me", "surge.sh",
)

SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id",
    "v.gd", "bl.ink", "lnkd.in", "qrco.de",
})

_LONG_TOKEN = re.compile(r"[a-z0-9]{24,}")
_HEX_TOKEN = re.compile(r"\b[0-9a-f]{16,}\b")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


@dataclass(frozen=True)
class ParsedURL:
    normalized: str
    host: str
    path: str
    query: str
    subdomain: str
    domain: str
    suffix: str
    port: int | None

    @property
    def registered_domain(self) -> str:
        return f"{self.domain}.{self.suffix}" if self.suffix else self.domain


def normalize(url: str) -> str:
    """Lower-case, strip the scheme and a leading ``www.``."""
    url = url.strip().lower()
    url = _SCHEME.sub("", url)
    if url.startswith("www."):
        url = url[4:]
    return url


def parse(url: str) -> ParsedURL:
    norm = normalize(url)
    try:
        parts = urlsplit("http://" + norm)
        host = (parts.hostname or "").rstrip(".")
        path, query = parts.path or "", parts.query or ""
        try:
            port = parts.port
        except ValueError:
            port = None
    except ValueError:
        # Malformed URL (e.g. broken IPv6 brackets): split by hand, never crash
        m = re.match(r"([^/?#]*)([^?#]*)\??([^#]*)", norm)
        netloc, path, query = m.group(1), m.group(2), m.group(3)
        host = netloc.rsplit("@", 1)[-1].split(":")[0].strip("[]").rstrip(".")
        port = None
    ext = _EXTRACT(host)
    return ParsedURL(norm, host, path, query, ext.subdomain, ext.domain, ext.suffix, port)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host))  # hex / decimal IP


# Human-readable names, used by the explanation and the README.
FEATURE_LABELS: dict[str, str] = {
    "url_length": "URL length",
    "host_length": "host name length",
    "path_length": "path length",
    "query_length": "query string length",
    "n_subdomains": "number of subdomains",
    "n_dots_host": "dots in the host name",
    "n_hyphens_host": "hyphens in the host name",
    "n_digits_host": "digits in the host name",
    "n_hyphens_path": "hyphens in the path",
    "n_digits_path": "digits in the path",
    "digit_ratio": "share of digits in the URL",
    "path_depth": "path depth (number of /)",
    "n_params": "number of query parameters",
    "n_special": "special characters (= & % ~ _ @)",
    "host_entropy": "randomness of the host name",
    "path_entropy": "randomness of the path",
    "domain_length": "registered domain length",
    "domain_has_digit": "digit in the registered domain",
    "tld_length": "top-level domain length",
    "has_ip": "IP address instead of a domain name",
    "has_at": "'@' sign in the URL",
    "has_double_slash": "'//' inside the path",
    "has_port": "explicit port number",
    "has_punycode": "punycode (xn--) host, possible look-alike characters",
    "suspicious_words": "phishing keywords (login, verify, account...)",
    "brand_outside_domain": "brand name used outside the real domain",
    "suspicious_tld": "top-level domain often abused",
    "free_hosting": "free hosting / app platform",
    "is_shortener": "URL shortener",
    "script_extension": "path ends in .php/.html/.asp",
    "long_token": "long random token in the path",
    "hex_token": "hexadecimal token in the URL",
}
FEATURE_NAMES: list[str] = list(FEATURE_LABELS)


def extract(url: str) -> dict[str, float]:
    p = parse(url)
    u, host, path, query = p.normalized, p.host, p.path, p.query
    reg = p.registered_domain
    outside_domain = f"{p.subdomain}/{path}?{query}"

    brand_outside = any(
        b in outside_domain and b not in p.domain for b in BRANDS
    )
    return {
        "url_length": len(u),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "n_subdomains": len([s for s in p.subdomain.split(".") if s]),
        "n_dots_host": host.count("."),
        "n_hyphens_host": host.count("-"),
        "n_digits_host": sum(c.isdigit() for c in host),
        "n_hyphens_path": path.count("-"),
        "n_digits_path": sum(c.isdigit() for c in path),
        "digit_ratio": sum(c.isdigit() for c in u) / max(len(u), 1),
        "path_depth": path.count("/"),
        "n_params": len([q for q in query.split("&") if q]),
        "n_special": sum(u.count(c) for c in "=&%~_@"),
        "host_entropy": entropy(host),
        "path_entropy": entropy(path),
        "domain_length": len(p.domain),
        "domain_has_digit": int(any(c.isdigit() for c in p.domain)),
        "tld_length": len(p.suffix),
        "has_ip": int(_is_ip(host)),
        "has_at": int("@" in u),
        "has_double_slash": int("//" in path),
        "has_port": int(p.port is not None),
        "has_punycode": int("xn--" in host),
        "suspicious_words": sum(w in u for w in SUSPICIOUS_WORDS),
        "brand_outside_domain": int(brand_outside),
        "suspicious_tld": int(p.suffix.split(".")[-1] in SUSPICIOUS_TLDS),
        "free_hosting": int(any(host == f or host.endswith("." + f) for f in FREE_HOSTING)),
        "is_shortener": int(reg in SHORTENERS or host in SHORTENERS),
        "script_extension": int(bool(re.search(r"\.(php|html?|aspx?|jsp|cgi)$", path))),
        "long_token": int(bool(_LONG_TOKEN.search(path + query))),
        "hex_token": int(bool(_HEX_TOKEN.search(u))),
    }


def extract_many(urls) -> list[list[float]]:
    return [[f[name] for name in FEATURE_NAMES] for f in map(extract, urls)]
