"""Download and prepare the training data.

Sources (public, hosted on GitHub):

* Malicious/benign URL dataset by Faizan Ahmad (~420k URLs labelled good/bad)
  https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs
* Phishing.Database by Mitchell Krog, active phishing links (updated daily)
  https://github.com/mitchellkrogza/Phishing.Database
* PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2024), 235k recent URLs,
  original at https://archive.ics.uci.edu/dataset/967 (GitHub copy used)
* Links extracted from ~40 community-curated "awesome" lists on GitHub: modern
  legitimate pages *with paths* (docs, blogs, articles), which the other
  legitimate sources lack (old URLs, or homepages only)

Preparation steps, each one there to avoid an over-optimistic model:

1. URLs are normalised (lower-case, scheme and ``www.`` removed) and deduplicated.
2. URLs that appear with both labels are dropped.
3. At most ``per_host`` URLs are kept per host, so a few huge sites (or a
   single phishing kit deployed 10 000 times) cannot dominate the data.
4. Classes are balanced.
5. The train/test split is done *by host* (see ``train.py``), so the model is
   always tested on websites it has never seen.
"""

from __future__ import annotations

import html
import re
import urllib.error
import urllib.request
from pathlib import Path

import pandas as pd

from .features import normalize, parse

SOURCES = {
    "faizann24.csv": "https://raw.githubusercontent.com/faizann24/"
                     "Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv",
    "phishing_database.txt": "https://raw.githubusercontent.com/mitchellkrogza/"
                             "Phishing.Database/master/phishing-links-ACTIVE.txt",
    "phiusiil.csv": "https://raw.githubusercontent.com/elaaatif/"
                    "DATA-MINING-PhiUSIIL-Phishing-URL/main/PhiUSIIL_Phishing_URL_Dataset.csv",
}

AWESOME_LISTS = [
    "sindresorhus/awesome", "vinta/awesome-python", "sorrycc/awesome-javascript",
    "enaqx/awesome-react", "avelino/awesome-go", "rust-unofficial/awesome-rust",
    "akullpp/awesome-java", "fffaraz/awesome-cpp", "sbilly/awesome-security",
    "Hack-with-Github/Awesome-Hacking", "josephmisiti/awesome-machine-learning",
    "ChristosChristofidis/awesome-deep-learning", "academic/awesome-datascience",
    "awesome-selfhosted/awesome-selfhosted", "veggiemonk/awesome-docker",
    "ramitsurana/awesome-kubernetes", "donnemartin/awesome-aws", "kahun/awesome-sysadmin",
    "jaywcjlove/awesome-mac", "sdras/awesome-actions", "bayandin/awesome-awesomeness",
    "public-apis/public-apis", "ripienaar/free-for-dev",
    "EbookFoundation/free-programming-books", "trimstray/the-book-of-secret-knowledge",
    "jnv/lists", "lukasz-madon/awesome-remote-job", "ziadoz/awesome-php",
    "vsouza/awesome-ios", "matteocrippa/awesome-swift", "dypsilon/frontend-dev-bookmarks",
    "bradtraversy/design-resources-for-developers", "alebcay/awesome-shell",
    "agarrharr/awesome-cli-apps", "onurakpolat/awesome-bigdata",
    "meirwah/awesome-incident-response", "hslatman/awesome-threat-intelligence",
    "paragonie/awesome-appsec", "qazbnm456/awesome-web-security",
]
_URL_IN_MD = re.compile(r"https?://[^\s)>\"'`\]]+")


def download_awesome(target: Path) -> None:
    urls: set[str] = set()
    for repo in AWESOME_LISTS:
        for branch in ("main", "master"):
            raw = f"https://raw.githubusercontent.com/{repo}/{branch}/README.md"
            try:
                with urllib.request.urlopen(raw, timeout=30) as r:  # noqa: S310
                    text = r.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError:
                continue
            urls.update(u.rstrip(".,;:") for u in _URL_IN_MD.findall(text))
            break
    target.write_text("\n".join(sorted(urls)) + "\n", encoding="utf-8")


def download(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        target = data_dir / name
        if target.exists():
            print(f"  {name}: already downloaded")
            continue
        print(f"  {name}: downloading ...")
        urllib.request.urlretrieve(url, target)  # noqa: S310 - fixed https URLs
    target = data_dir / "awesome_urls.txt"
    if target.exists():
        print("  awesome_urls.txt: already downloaded")
    else:
        print("  awesome_urls.txt: collecting links from awesome lists ...")
        download_awesome(target)


def load_raw(data_dir: Path) -> pd.DataFrame:
    a = pd.read_csv(data_dir / "faizann24.csv")
    a["label"] = (a["label"] == "bad").astype(int)
    a["source"] = "faizann24"

    lines = (data_dir / "phishing_database.txt").read_text(
        encoding="utf-8", errors="replace").splitlines()
    b = pd.DataFrame({"url": [x for x in lines if x and not x.startswith("#")]})
    b["label"] = 1
    b["source"] = "phishing_database"

    c = pd.read_csv(data_dir / "phiusiil.csv", usecols=["URL", "label"],
                    encoding="utf-8-sig").rename(columns={"URL": "url"})
    c["url"] = c["url"].astype(str).map(html.unescape)  # some URLs contain "&amp;"
    c["label"] = 1 - c["label"]  # PhiUSIIL uses 1 = legitimate
    c["source"] = "phiusiil"

    lines = (data_dir / "awesome_urls.txt").read_text(encoding="utf-8").splitlines()
    d = pd.DataFrame({"url": [x for x in lines if x]})
    d["label"] = 0
    d["source"] = "awesome_lists"
    return pd.concat([a, b, c, d], ignore_index=True)


def prepare(df: pd.DataFrame, per_class: int = 100_000, per_host: int = 5,
            seed: int = 42) -> pd.DataFrame:
    df = df.dropna(subset=["url"]).copy()
    df["url"] = df["url"].astype(str).map(normalize)
    df = df[df["url"].str.len().between(4, 2000)]

    # Drop URLs labelled both ways, then exact duplicates
    conflicting = df.groupby("url")["label"].nunique()
    df = df[~df["url"].isin(conflicting[conflicting > 1].index)]
    df = df.drop_duplicates("url")

    df["host"] = df["url"].map(lambda u: parse(u).host)
    df = df[df["host"] != ""]
    df = (df.sample(frac=1, random_state=seed)
            .groupby("host", group_keys=False).head(per_host))

    # Each class is drawn evenly from every source that has it, so the model
    # cannot learn "which dataset does this URL come from" instead of phishing.
    parts = []
    for label in (0, 1):
        sub = df[df["label"] == label]
        # Smallest sources are taken whole; the remaining quota is shared evenly.
        sizes = sub["source"].value_counts().sort_values()
        remaining, left = per_class, len(sizes)
        for src, size in sizes.items():
            take = min(size, remaining // left)
            parts.append(sub[sub["source"] == src].sample(take, random_state=seed))
            remaining -= take
            left -= 1
    return pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)
