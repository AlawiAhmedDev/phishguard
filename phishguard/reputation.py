"""Domain reputation layer.

Lexical models struggle with the login pages of big brands: a legitimate
``paypal.com/signin`` and a phishing ``paypal-signin.example.top/login`` share
the same keywords. Real filters (browsers, mail gateways) therefore combine the
model with domain reputation. PhishGuard does the same, in a deliberately
simple and transparent way:

* if the *registered domain* is in a list of popular domains, the URL is
  reported as safe, with the model score still shown;
* the trust is never given to platforms where anyone can publish
  (github.io, firebaseapp.com, blogspot.com...) or to URL shorteners.

The bundled list (``models/popular_domains.txt``) merges two public rankings.
Refresh it from the current Tranco ranking with ``phishguard update-reputation``.
"""

from __future__ import annotations

import csv
import io
import urllib.request
import zipfile
from functools import lru_cache
from pathlib import Path

from .features import FREE_HOSTING, SHORTENERS

DEFAULT_LIST = Path(__file__).resolve().parent.parent / "models" / "popular_domains.txt"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

# Hosting platforms and services whose subdomains or pages are user content.
NEVER_TRUSTED = frozenset(FREE_HOSTING) | SHORTENERS | {
    "blogger.com", "wordpress.com", "medium.com", "tumblr.com", "wix.com",
    "weebly.com", "gitlab.io", "bitbucket.io", "googleusercontent.com",
    "amazonaws.com", "cloudfront.net", "azureedge.net", "windows.net",
    "firebaseio.com", "notion.site", "typeform.com", "jotform.com", "forms.gle",
    "formstack.com", "wufoo.com", "linktr.ee", "carrd.co", "canva.site",
    "dropboxusercontent.com", "sharepoint.com", "box.com", "ipfs.io", "pinata.cloud",
}


def clean_list(domains) -> list[str]:
    out, seen = [], set()
    for d in domains:
        d = d.strip().lower().removeprefix("www.")
        if d and not d.startswith("#") and d not in NEVER_TRUSTED and d not in seen:
            seen.add(d)
            out.append(d)
    return out


@lru_cache(maxsize=4)
def load(path: str | Path = DEFAULT_LIST) -> frozenset[str]:
    path = Path(path)
    if not path.exists():
        return frozenset()
    return frozenset(clean_list(path.read_text(encoding="utf-8").splitlines()))


def is_trusted(registered_domain: str, host: str, path: str | Path = DEFAULT_LIST) -> bool:
    if registered_domain in NEVER_TRUSTED:
        return False
    if any(host == h or host.endswith("." + h) for h in NEVER_TRUSTED):
        return False
    return registered_domain in load(str(path))


def parse_tranco_zip(data: bytes, top: int) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        name = zf.namelist()[0]
        reader = csv.reader(io.TextIOWrapper(zf.open(name), encoding="utf-8"))
        domains = [row[1] for _, row in zip(range(top), reader)]
    return clean_list(domains)


def update_from_tranco(top: int = 10_000, path: Path = DEFAULT_LIST) -> int:
    """Download the latest Tranco ranking and keep the top ``top`` domains."""
    with urllib.request.urlopen(TRANCO_URL, timeout=120) as resp:  # noqa: S310
        domains = parse_tranco_zip(resp.read(), top)
    path.write_text("# Tranco top list, https://tranco-list.eu\n" + "\n".join(domains) + "\n",
                    encoding="utf-8")
    load.cache_clear()
    return len(domains)
