"""Train, compare and evaluate models, then save the best one with its report."""

from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from . import __version__
from .benchmarks import LEGIT_MODERN
from . import reputation
from .data import download, load_raw, prepare
from .features import FEATURE_LABELS, FEATURE_NAMES, extract_many, parse
from .model import PHISHING_AT, SUSPICIOUS_AT

SEED = 42


def _metrics(y, proba, threshold=0.5) -> dict:
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred),
        "recall": recall_score(y, pred),
        "f1": f1_score(y, pred),
        "roc_auc": roc_auc_score(y, proba),
        "false_positive_rate": fp / (fp + tn),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def candidate_models() -> dict:
    return {
        "Logistic Regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, C=1.0)),
        "Random Forest": RandomForestClassifier(
            n_estimators=150, min_samples_leaf=2, n_jobs=-1, random_state=SEED),
        "Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=400, learning_rate=0.08, max_leaf_nodes=63,
            l2_regularization=1.0, random_state=SEED),
    }


def run(data_dir: Path, out_dir: Path, per_class: int = 100_000) -> dict:
    t0 = time.time()
    print("[1/6] Data")
    download(data_dir)
    df = prepare(load_raw(data_dir), per_class=per_class, seed=SEED)
    print(f"      {len(df):,} URLs after cleaning "
          f"({(df.label == 0).sum():,} legitimate / {(df.label == 1).sum():,} phishing)")

    print("[2/6] Feature extraction")
    X = np.array(extract_many(df["url"]), dtype=float)
    y = df["label"].to_numpy()

    print("[3/6] Train/test split grouped by host (test sites never seen in training)")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tr, te = next(gss.split(X, y, groups=df["host"]))
    assert not set(df["host"].iloc[tr]) & set(df["host"].iloc[te])

    print("[4/6] Model comparison")
    results, fitted = {}, {}
    for name, model in candidate_models().items():
        s = time.time()
        model.fit(X[tr], y[tr])
        proba = model.predict_proba(X[te])[:, 1]
        results[name] = _metrics(y[te], proba) | {"train_seconds": round(time.time() - s, 1)}
        fitted[name] = model
        print(f"      {name:<22} F1={results[name]['f1']:.4f}  AUC={results[name]['roc_auc']:.4f}")

    # Text baseline: character n-grams, a common approach in the literature
    s = time.time()
    text = make_pipeline(
        TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=5, max_features=200_000,
                        sublinear_tf=True),
        LogisticRegression(max_iter=2000, C=4.0))
    text.fit(df["url"].iloc[tr], y[tr])
    proba = text.predict_proba(df["url"].iloc[te])[:, 1]
    results["Char n-gram TF-IDF + LR"] = _metrics(y[te], proba) | {
        "train_seconds": round(time.time() - s, 1)}
    print(f"      {'Char n-gram TF-IDF + LR':<22} F1={results['Char n-gram TF-IDF + LR']['f1']:.4f}")

    print("[5/6] Evaluation of the selected model (Gradient Boosting)")
    best = fitted["Gradient Boosting"]
    proba = best.predict_proba(X[te])[:, 1]
    test = df.iloc[te].assign(proba=proba)

    by_source = {}
    for src, g in test[test.label == 1].groupby("source"):
        by_source[src] = {"n": int(len(g)), "recall": float((g.proba >= 0.5).mean())}

    # Full system = reputation layer + model, on the same unseen test set
    trusted = test.url.map(lambda u: reputation.is_trusted(
        parse(u).registered_domain, parse(u).host))
    system_proba = np.where(trusted, 0.0, proba)
    system = _metrics(y[te], system_proba) | {
        "test_urls_on_trusted_domains": {
            "legitimate": int((trusted & (test.label == 0)).sum()),
            "phishing": int((trusted & (test.label == 1)).sum()),
        }}

    # Modern legitimate benchmark: model alone vs full system
    legit_X = np.array(extract_many(LEGIT_MODERN), dtype=float)
    legit_p = best.predict_proba(legit_X)[:, 1]
    bench = []
    for u, pr in zip(LEGIT_MODERN, legit_p):
        pu = parse(u)
        t = reputation.is_trusted(pu.registered_domain, pu.host)
        bench.append({"url": u, "model_score": round(float(pr), 3), "trusted_domain": t,
                      "model_flags": bool(pr >= SUSPICIOUS_AT),
                      "system_flags": bool(pr >= SUSPICIOUS_AT and not t)})

    sub = np.random.default_rng(SEED).choice(len(te), size=min(8000, len(te)), replace=False)
    imp = permutation_importance(best, X[te][sub], y[te][sub], scoring="f1",
                                 n_repeats=5, random_state=SEED, n_jobs=-1)
    importance = sorted(
        ({"feature": n, "label": FEATURE_LABELS[n], "importance": float(m)}
         for n, m in zip(FEATURE_NAMES, imp.importances_mean)),
        key=lambda d: -d["importance"])

    print("[6/6] Saving")
    out_dir.mkdir(parents=True, exist_ok=True)
    legit_train = X[tr][y[tr] == 0]
    bundle = {
        "model": best,
        "feature_names": FEATURE_NAMES,
        "baseline": np.median(legit_train, axis=0),
        "version": __version__,
        "thresholds": {"suspicious": SUSPICIOUS_AT, "phishing": PHISHING_AT},
    }
    joblib.dump(bundle, out_dir / "phishguard.joblib", compress=3)

    report = {
        "version": __version__,
        "dataset": {
            "total": int(len(df)),
            "train": int(len(tr)),
            "test": int(len(te)),
            "legitimate": int((df.label == 0).sum()),
            "phishing": int((df.label == 1).sum()),
            "split": "GroupShuffleSplit by host, 80/20",
        },
        "models": results,
        "selected_model": "Gradient Boosting",
        "full_system_on_test": system,
        "recall_by_phishing_source": by_source,
        "modern_legit_benchmark": {
            "n": len(LEGIT_MODERN),
            "flagged_by_model_alone": sum(b["model_flags"] for b in bench),
            "flagged_by_full_system": sum(b["system_flags"] for b in bench),
            "urls": bench,
        },
        "permutation_importance": importance,
        "total_seconds": round(time.time() - t0, 1),
    }
    (out_dir / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    pd.DataFrame({"url": test.url, "label": test.label, "proba": test.proba}) \
      .to_csv(out_dir / "test_predictions.csv.gz", index=False)
    print(f"      done in {report['total_seconds']}s -> {out_dir}")
    return report
