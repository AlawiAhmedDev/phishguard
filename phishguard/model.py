"""Load the trained model, score URLs and explain each decision."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np

from . import reputation
from .features import FEATURE_LABELS, FEATURE_NAMES, extract, parse

DEFAULT_MODEL = Path(__file__).resolve().parent.parent / "models" / "phishguard.joblib"

SUSPICIOUS_AT = 0.35
PHISHING_AT = 0.70


@dataclass
class Reason:
    feature: str
    label: str
    value: float
    impact: float  # share of the evidence for phishing carried by this feature (0..1)

    def to_dict(self) -> dict:
        return {"feature": self.feature, "label": self.label,
                "value": round(float(self.value), 3), "impact": round(self.impact, 3)}


@dataclass
class Verdict:
    url: str
    host: str
    registered_domain: str
    score: float           # model probability of phishing, 0..1
    verdict: str           # "safe" | "suspicious" | "phishing"
    decided_by: str        # "model" | "reputation" | "shortener"
    reasons: list[Reason] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"url": self.url, "host": self.host,
                "registered_domain": self.registered_domain,
                "score": round(self.score, 4), "verdict": self.verdict,
                "decided_by": self.decided_by,
                "reasons": [r.to_dict() for r in self.reasons]}


@lru_cache(maxsize=4)
def load(path: str | Path = DEFAULT_MODEL) -> dict:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Model not found at {path}. Train one first: phishguard train")
    bundle = joblib.load(path)
    if bundle["feature_names"] != FEATURE_NAMES:
        raise RuntimeError("Model was trained with a different feature set; retrain it.")
    return bundle


def _label(score: float) -> str:
    if score >= PHISHING_AT:
        return "phishing"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "safe"


def _logit(p: np.ndarray | float) -> np.ndarray:
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def explain(bundle: dict, x: np.ndarray, score: float, top: int = 3) -> list[Reason]:
    """Feature ablation: replace one feature at a time by its typical value on
    legitimate URLs and measure how much the phishing evidence falls.

    Measured in log-odds rather than probability: near a score of 1.0 removing
    one red flag barely moves the probability (others still saturate it), but it
    still moves the log-odds, so the explanation stays meaningful."""
    baseline = bundle["baseline"]
    batch = np.repeat(x[None, :], len(FEATURE_NAMES), axis=0)
    idx = np.arange(len(FEATURE_NAMES))
    batch[idx, idx] = baseline
    probs = bundle["model"].predict_proba(batch)[:, 1]
    drops = np.maximum(_logit(score) - _logit(probs), 0.0)
    total = drops.sum()
    if total <= 0:
        return []
    shares = drops / total
    order = np.argsort(-shares)
    return [
        Reason(FEATURE_NAMES[i], FEATURE_LABELS[FEATURE_NAMES[i]], x[i], float(shares[i]))
        for i in order[:top] if shares[i] >= 0.05
    ]


def check(url: str, model_path: str | Path = DEFAULT_MODEL, top: int = 3,
          use_reputation: bool = True,
          reputation_path: str | Path = reputation.DEFAULT_LIST) -> Verdict:
    bundle = load(str(model_path))
    p = parse(url)
    feats = extract(url)
    x = np.array([feats[n] for n in FEATURE_NAMES], dtype=float)
    score = float(bundle["model"].predict_proba(x[None, :])[0, 1])
    base = dict(url=url, host=p.host, registered_domain=p.registered_domain, score=score)

    if feats["is_shortener"]:
        # The real destination is hidden; judging the short link itself is meaningless.
        return Verdict(**base, verdict="suspicious", decided_by="shortener", reasons=[
            Reason("is_shortener", "shortened link: the real destination is hidden", 1, 0.0)])

    if use_reputation and reputation.is_trusted(p.registered_domain, p.host, reputation_path):
        return Verdict(**base, verdict="safe", decided_by="reputation")

    verdict = _label(score)
    reasons = explain(bundle, x, score, top) if verdict != "safe" else []
    return Verdict(**base, verdict=verdict, decided_by="model", reasons=reasons)
