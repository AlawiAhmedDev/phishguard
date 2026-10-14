"""Render the README charts from models/metrics.json.

    python scripts/make_charts.py
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
INK, MUTED, GRID, BAR, BAR_SOFT = "#18202b", "#5d6878", "#e3e7ed", "#2a46c4", "#9aa9e6"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 11, "axes.edgecolor": GRID,
    "axes.labelcolor": MUTED, "xtick.color": MUTED, "ytick.color": INK,
    "axes.spines.top": False, "axes.spines.right": False,
})


def hbar(ax, labels, values, colors, fmt):
    y = range(len(labels))[::-1]
    ax.barh(list(y), values, height=0.55, color=colors)
    ax.set_yticks(list(y), labels)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for yi, v in zip(y, values):
        ax.text(v, yi, " " + fmt(v), va="center", color=INK, fontsize=10)


def main():
    m = json.loads((ROOT / "models" / "metrics.json").read_text())
    out = ROOT / "docs"
    out.mkdir(exist_ok=True)

    # 1) Model comparison, F1 on the unseen-host test set
    models = m["models"]
    names = list(models)
    f1 = [models[n]["f1"] for n in names]
    colors = [BAR if n == m["selected_model"] else BAR_SOFT for n in names]
    fig, ax = plt.subplots(figsize=(8, 3.2), dpi=150)
    hbar(ax, names, f1, colors, lambda v: f"{v:.3f}")
    ax.set_xlim(0.5, 1.0)
    ax.set_xlabel("F1 score on websites never seen in training (higher is better)")
    ax.set_title("Model comparison", loc="left", color=INK, fontsize=13, pad=12)
    fig.tight_layout()
    fig.savefig(out / "model_comparison.png", facecolor="white")

    # 2) Permutation importance, top 12 features
    imp = m["permutation_importance"][:12]
    fig, ax = plt.subplots(figsize=(9, 4.8), dpi=150)
    hbar(ax, [d["label"] for d in imp], [d["importance"] for d in imp], BAR,
         lambda v: f"{v:.3f}")
    ax.set_xlim(0, imp[0]["importance"] * 1.15)
    ax.set_xlabel("Drop in F1 when the feature is shuffled")
    ax.set_title("What the model relies on", loc="left", color=INK, fontsize=13, pad=12)
    fig.tight_layout()
    fig.savefig(out / "feature_importance.png", facecolor="white")
    print("Wrote docs/model_comparison.png and docs/feature_importance.png")


if __name__ == "__main__":
    main()
