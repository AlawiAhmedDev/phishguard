"""The browser demo (docs/phishguard.js) must score exactly like the Python package."""

import json
import shutil
import subprocess
from pathlib import Path

import numpy as np
import pytest

from phishguard.app import EXAMPLES
from phishguard.benchmarks import LEGIT_MODERN
from phishguard.model import check

ROOT = Path(__file__).resolve().parent.parent
URLS = LEGIT_MODERN + EXAMPLES + [
    "https://paypal-secure-login.verify-account.top/signin/webscr?cmd=_login",
    "http://192.168.4.12/wp-admin/office365/login.php",
    "https://xn--pypal-4ve.com/signin",
    "HTTPS://WWW.Example.COM:8080/a?b=1&c=2",
    "http://[2001:db8::1]/x", "http://[broken/login", "user@evil.com@paypal.com",
    "foo.ck", "a.b.city.kawasaki.jp", "test.xn--p1ai/", "0x7f000001/x",
    "https://syneragrisystem.web.app/",
    "agricolalombardi.com/webmail/1206aa0b9a0b4e155e672be8f752e512/",
]

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")


def test_browser_port_matches_python(tmp_path):
    urls_file = tmp_path / "urls.json"
    urls_file.write_text(json.dumps(URLS))
    out = subprocess.run(["node", str(ROOT / "tests" / "web_parity.mjs"), str(urls_file)],
                         capture_output=True, text=True, check=True).stdout
    for url, js in zip(URLS, json.loads(out)):
        py = check(url)
        assert np.isclose(js["proba"], py.score, rtol=0, atol=1e-9), url
        assert js["verdict"] == py.verdict, url
        assert js["decided_by"] == py.decided_by, url
        assert js["reasons"] == [r.feature for r in py.reasons], url
