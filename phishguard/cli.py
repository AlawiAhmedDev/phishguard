"""Command-line interface.

    phishguard check URL [URL ...]      score one or more URLs
    phishguard check -f urls.txt        score every URL in a file
    phishguard serve                    start the web interface
    phishguard train                    download data, retrain, write the report
    phishguard update-reputation        refresh popular domains from Tranco
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__

ROOT = Path(__file__).resolve().parent.parent
_COLORS = {"safe": "\033[32m", "suspicious": "\033[33m", "phishing": "\033[1;31m"}
_RESET = "\033[0m"


def _cmd_check(args) -> int:
    from .model import check

    urls = list(args.urls)
    if args.file:
        urls += [line.strip() for line in Path(args.file).read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.startswith("#")]
    if not urls:
        print("error: give at least one URL or --file", file=sys.stderr)
        return 1

    results = [check(u, use_reputation=not args.no_reputation) for u in urls]
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        for r in results:
            label = r.verdict.upper().ljust(10)
            if color:
                label = f"{_COLORS[r.verdict]}{label}{_RESET}"
            note = " (popular domain)" if r.decided_by == "reputation" else ""
            print(f"{label} score={r.score:.2f}{note}  {r.url}")
            for reason in r.reasons:
                share = f"  ({reason.impact:.0%})" if reason.impact > 0 else ""
                print(f"           - {reason.label}{share}")
    worst = max(("safe", "suspicious", "phishing").index(r.verdict) for r in results)
    return 2 if args.fail_on_phishing and worst == 2 else 0


def _cmd_serve(args) -> int:
    from .app import create_app

    print(f"PhishGuard running on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    create_app().run(host=args.host, port=args.port, debug=False)
    return 0


def _cmd_train(args) -> int:
    from .train import run

    run(Path(args.data_dir), Path(args.out_dir), per_class=args.per_class)
    return 0


def _cmd_update_reputation(args) -> int:
    from .reputation import update_from_tranco

    n = update_from_tranco(top=args.top)
    print(f"Saved {n} popular domains from the current Tranco ranking.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishguard",
                                description="Machine-learning phishing URL detector. "
                                            "URLs are analysed as text and never visited.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="score URLs")
    c.add_argument("urls", nargs="*")
    c.add_argument("-f", "--file", help="text file with one URL per line")
    c.add_argument("--json", action="store_true", help="machine-readable output")
    c.add_argument("--no-reputation", action="store_true",
                   help="use the model only, ignore the popular-domain list")
    c.add_argument("--fail-on-phishing", action="store_true",
                   help="exit with code 2 if any URL is judged phishing")
    c.add_argument("--no-color", action="store_true")
    c.set_defaults(func=_cmd_check)

    s = sub.add_parser("serve", help="start the web interface")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.set_defaults(func=_cmd_serve)

    t = sub.add_parser("train", help="download data and retrain the model")
    t.add_argument("--data-dir", default=str(ROOT / "data"))
    t.add_argument("--out-dir", default=str(ROOT / "models"))
    t.add_argument("--per-class", type=int, default=100_000)
    t.set_defaults(func=_cmd_train)

    u = sub.add_parser("update-reputation", help="refresh popular domains from Tranco")
    u.add_argument("--top", type=int, default=10_000)
    u.set_defaults(func=_cmd_update_reputation)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
