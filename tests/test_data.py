import pandas as pd

from phishguard.data import prepare


def test_prepare_cleans_and_balances():
    rows = (
        [("http://www.same.com/x", 0, "a"), ("same.com/x", 1, "b")]           # conflict -> dropped
        + [(f"big.com/page{i}", 0, "a") for i in range(50)]                     # capped per host
        + [(f"site{i}.org/p", 0, "a") for i in range(30)]
        + [(f"evil{i}.top/login", 1, "b") for i in range(40)]
    )
    df = pd.DataFrame(rows, columns=["url", "label", "source"])
    out = prepare(df, per_class=20, per_host=5)
    assert "same.com/x" not in set(out.url)
    assert (out.host == "big.com").sum() <= 5
    assert (out.label == 0).sum() == 20 and (out.label == 1).sum() == 20
    assert not out.url.str.startswith("http").any()
