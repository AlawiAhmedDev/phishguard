"""Export the trained model and its lookup tables to JSON for the browser demo.

    python scripts/export_web_model.py

Writes docs/model.json, which docs/phishguard.js loads. The browser then
scores URLs locally: nothing is sent to a server.
"""

import json
from pathlib import Path

import idna
import joblib
import numpy as np

from phishguard import features, reputation
from phishguard.features import FEATURE_LABELS, FEATURE_NAMES
from phishguard.model import PHISHING_AT, SUSPICIOUS_AT

ROOT = Path(__file__).resolve().parent.parent


def export_trees(model) -> list:
    trees = []
    for (pred,) in model._predictors:
        nodes = []
        for n in pred.nodes:
            if n["is_leaf"]:
                nodes.append([float(n["value"])])
            else:
                nodes.append([int(n["feature_idx"]), float(n["num_threshold"]),
                              int(n["left"]), int(n["right"])])
        trees.append(nodes)
    return trees


def export_suffix_rules() -> list[str]:
    """ICANN public-suffix rules exactly as tldextract (offline) uses them.
    Unicode labels are added in their punycode form too, so the browser does
    not need a punycode decoder."""
    ext = features._EXTRACT._get_tld_extractor()
    rules = set()
    for rule in ext.tlds_excl_private:
        rules.add(rule)
        parts = []
        for label in rule.split("."):
            prefix = "!" if label.startswith("!") else ""
            bare = label[1:] if prefix else label
            try:
                bare = bare if bare == "*" or bare.isascii() else idna.encode(bare).decode()
            except idna.IDNAError:
                pass
            parts.append(prefix + bare)
        rules.add(".".join(parts))
    return sorted(rules)


def main():
    bundle = joblib.load(ROOT / "models" / "phishguard.joblib")
    model = bundle["model"]
    out = {
        "version": bundle["version"],
        "feature_names": FEATURE_NAMES,
        "feature_labels": FEATURE_LABELS,
        "baseline_prediction": float(np.ravel(model._baseline_prediction)[0]),
        "baseline_features": [float(v) for v in bundle["baseline"]],
        "thresholds": {"suspicious": SUSPICIOUS_AT, "phishing": PHISHING_AT},
        "trees": export_trees(model),
        "lists": {
            "suspicious_words": list(features.SUSPICIOUS_WORDS),
            "brands": list(features.BRANDS),
            "suspicious_tlds": sorted(features.SUSPICIOUS_TLDS),
            "free_hosting": list(features.FREE_HOSTING),
            "shorteners": sorted(features.SHORTENERS),
            "never_trusted": sorted(reputation.NEVER_TRUSTED),
            "popular_domains": sorted(reputation.load()),
            "suffix_rules": export_suffix_rules(),
        },
    }
    target = ROOT / "docs" / "model.json"
    target.write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    print(f"Wrote {target} ({target.stat().st_size / 1e6:.1f} MB, {len(out['trees'])} trees)")


if __name__ == "__main__":
    main()
