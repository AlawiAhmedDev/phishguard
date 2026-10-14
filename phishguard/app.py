"""Small Flask web interface and JSON API.

    GET  /                      the page
    GET  /api/check?url=...     JSON verdict
    POST /api/check             {"url": "..."} -> JSON verdict
"""

from __future__ import annotations

from flask import Flask, jsonify, request

from .features import parse
from .model import check

MAX_URL = 2048

EXAMPLES = [
    "https://paypal-secure-login.verify-account.top/signin/webscr?cmd=_login",
    "https://appleid.apple.com.security-check.ru/",
    "https://misjrg-sav.web.app/",
    "https://github.com/login",
    "https://en.wikipedia.org/wiki/Phishing",
    "bit.ly/3xYzAbC",
]


def anatomy(url: str) -> dict:
    p = parse(url)
    reg = p.registered_domain
    return {
        "subdomain": p.subdomain,
        "registered_domain": reg,
        "port": f":{p.port}" if p.port else "",
        "path": p.path if p.path not in ("", "/") else "",
        "query": f"?{p.query}" if p.query else "",
    }


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return PAGE

    @app.route("/api/check", methods=["GET", "POST"])
    def api_check():
        if request.method == "POST":
            url = (request.get_json(silent=True) or {}).get("url", "")
        else:
            url = request.args.get("url", "")
        url = str(url).strip()
        if not url:
            return jsonify(error="Enter a link to check, for example paypal.com/signin."), 400
        if len(url) > MAX_URL:
            return jsonify(error=f"This link is longer than {MAX_URL} characters."), 400
        result = check(url).to_dict()
        result["anatomy"] = anatomy(url)
        return jsonify(result)

    @app.get("/api/examples")
    def examples():
        return jsonify(EXAMPLES)

    return app


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --paper: #eef1f5; --panel: #ffffff; --ink: #18202b; --muted: #5d6878; --rule: #cdd4de;
  --domain: #2a46c4; --safe: #1e7a4c; --suspicious: #a86400; --phishing: #b42318;
  --sans: "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, "Cascadia Mono", Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root { --paper: #10151c; --panel: #171e27; --ink: #e6ebf1; --muted: #93a0b0; --rule: #2a3441;
          --domain: #9aabff; --safe: #5cc48f; --suspicious: #f0b54a; --phishing: #ff7a6e; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink); font: 17px/1.55 var(--sans); }
main { max-width: 780px; margin: 0 auto; padding: 56px 20px 80px; }
h1 { font-size: 30px; font-weight: 600; margin: 0 0 6px; letter-spacing: -0.01em; }
.lead { color: var(--muted); margin: 0 0 28px; max-width: 60ch; }

form { display: flex; gap: 10px; }
input[type=text] { flex: 1; min-width: 0; font: 16px var(--mono); color: var(--ink); background: var(--panel);
  border: 1.5px solid var(--rule); border-radius: 6px; padding: 13px 14px; }
input[type=text]:focus { outline: none; border-color: var(--domain); box-shadow: 0 0 0 3px color-mix(in srgb, var(--domain) 22%, transparent); }
button { font: 600 16px var(--sans); color: #fff; background: var(--ink); border: 0; border-radius: 6px;
  padding: 0 20px; cursor: pointer; }
@media (prefers-color-scheme: dark) { button { color: var(--paper); } }
button:focus-visible, .example:focus-visible { outline: 3px solid var(--domain); outline-offset: 2px; }

.examples { margin: 14px 0 0; color: var(--muted); font-size: 14px; display: flex; flex-wrap: wrap; gap: 6px 8px; align-items: baseline; }
.example { font: 13px var(--mono); color: var(--muted); background: none; border: 1px dashed var(--rule);
  border-radius: 4px; padding: 3px 7px; cursor: pointer; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.example:hover { color: var(--ink); border-style: solid; }

#result { margin-top: 44px; }
.verdict { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; margin-bottom: 26px; }
.verdict h2 { margin: 0; font-size: 34px; font-weight: 600; letter-spacing: -0.015em; }
.verdict .score { color: var(--muted); font-size: 15px; }
.safe h2 { color: var(--safe); } .suspicious h2 { color: var(--suspicious); } .phishing h2 { color: var(--phishing); }

/* The URL anatomy: the one place this page is loud */
.anatomy { background: var(--panel); border: 1px solid var(--rule); border-radius: 8px; padding: 22px 20px 16px; }
.segments { display: flex; flex-wrap: wrap; align-items: flex-start; row-gap: 10px; font: 20px/1.3 var(--mono); }
.seg { display: flex; flex-direction: column; min-width: 0; }
.seg .txt { word-break: break-all; }
.seg.reg .txt { word-break: normal; white-space: nowrap; }
.seg .txt { padding-bottom: 6px; border-bottom: 2px solid var(--rule); }
.seg .lbl { font: 12.5px var(--sans); color: var(--muted); padding-top: 6px; padding-right: 10px; }
.seg.sub .txt { color: var(--muted); }
.seg.reg .txt { color: var(--domain); font-weight: 600; border-bottom: 3px solid var(--domain); }
.seg.reg .lbl { color: var(--domain); font-weight: 500; }
.seg.rest .txt { color: var(--muted); }
.anatomy p { margin: 16px 0 0; font-size: 15px; color: var(--muted); max-width: 64ch; }
.anatomy p strong { color: var(--ink); font-weight: 600; }

h3 { font-size: 17px; font-weight: 600; margin: 34px 0 12px; }
.reasons { list-style: none; margin: 0; padding: 0; }
.reasons li { display: grid; grid-template-columns: 1fr 140px 44px; gap: 14px; align-items: center;
  padding: 10px 0; border-top: 1px solid var(--rule); font-size: 15.5px; }
.reasons li:last-child { border-bottom: 1px solid var(--rule); }
.bar { height: 6px; background: var(--rule); border-radius: 3px; overflow: hidden; }
.bar span { display: block; height: 100%; background: var(--phishing); }
.suspicious .bar span { background: var(--suspicious); }
.pct { text-align: right; color: var(--muted); font-variant-numeric: tabular-nums; font-size: 14px; }
.note { margin-top: 26px; font-size: 15px; color: var(--muted); max-width: 64ch; }
.error { color: var(--phishing); margin-top: 24px; }
footer { margin-top: 64px; font-size: 13.5px; color: var(--muted); max-width: 64ch; }
footer a { color: inherit; }
@media (max-width: 560px) {
  main { padding-top: 32px; } form { flex-direction: column; } button { padding: 12px; }
  .reasons li { grid-template-columns: 1fr 70px 40px; }
  .segments { font-size: 16px; }
}
</style>
</head>
<body>
<main>
  <h1>PhishGuard</h1>
  <p class="lead">Paste a link to see where it really leads and whether it looks like phishing.
  The link is analysed as text and never opened.</p>

  <form id="f" autocomplete="off">
    <label for="u" class="visually-hidden" style="position:absolute;left:-9999px">Link to check</label>
    <input id="u" type="text" placeholder="https://..." spellcheck="false" autofocus>
    <button type="submit">Check link</button>
  </form>
  <div class="examples" id="ex"><span>Try an example:</span></div>

  <section id="result" aria-live="polite"></section>

  <footer>A gradient-boosting model reads 32 features of the link (length, subdomains, keywords,
  brand names, hosting platform...). Links on the 10,000 most visited domains are trusted.
  It is a learning project and makes mistakes: when in doubt, type the site's address yourself.
  <a href="https://github.com/AlawiAhmedDev/phishguard">Source code</a></footer>
</main>
<script>
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const TITLES = { safe: "Looks safe", suspicious: "Suspicious", phishing: "Looks like phishing" };

function seg(cls, text, label) {
  return text ? `<span class="seg ${cls}"><span class="txt">${esc(text)}</span><span class="lbl">${label}</span></span>` : "";
}

function render(r) {
  const a = r.anatomy;
  const sub = a.subdomain ? a.subdomain + "." : "";
  const rest = a.path + a.query;
  let explain;
  if (a.subdomain && r.decided_by !== "reputation") {
    explain = `This link opens <strong>${esc(a.registered_domain)}</strong>. Everything before it,
      <strong>${esc(a.subdomain)}</strong>, is chosen freely by whoever owns that domain.`;
  } else {
    explain = `This link opens <strong>${esc(a.registered_domain || r.host)}</strong>.`;
  }
  let html = `<div class="${r.verdict}">
    <div class="verdict"><h2>${TITLES[r.verdict]}</h2>
      <span class="score">Model score ${r.score.toFixed(2)} out of 1</span></div>
    <div class="anatomy"><div class="segments">
      ${seg("sub", sub, "subdomain")}${seg("reg", a.registered_domain + a.port, "real domain")}${seg("rest", rest, a.query ? "path and parameters" : "path")}
    </div><p>${explain}</p></div>`;

  if (r.decided_by === "reputation") {
    html += `<p class="note">${esc(r.registered_domain)} is one of the most visited domains, so the link is trusted.
      The model alone scored it ${r.score.toFixed(2)}.</p>`;
  } else if (r.decided_by === "shortener") {
    html += `<p class="note">This is a shortened link, so its real destination is hidden and can't be judged.
      Expand it with a link preview service before opening it.</p>`;
  } else if (r.reasons.length) {
    html += `<h3>What raised the score</h3><ul class="reasons">` + r.reasons.map(x =>
      `<li><span>${esc(x.label)}</span><span class="bar"><span style="width:${Math.round(x.impact*100)}%"></span></span>
       <span class="pct">${Math.round(x.impact*100)}%</span></li>`).join("") + `</ul>`;
  }
  $("#result").innerHTML = html + "</div>";
}

async function run(url) {
  $("#u").value = url;
  const res = await fetch("/api/check?url=" + encodeURIComponent(url));
  const data = await res.json();
  if (!res.ok) { $("#result").innerHTML = `<p class="error">${esc(data.error)}</p>`; return; }
  render(data);
  history.replaceState(null, "", "?url=" + encodeURIComponent(url));
}

$("#f").addEventListener("submit", (e) => { e.preventDefault(); run($("#u").value.trim()); });
fetch("/api/examples").then(r => r.json()).then(list => list.forEach(u => {
  const b = document.createElement("button"); b.type = "button"; b.className = "example"; b.textContent = u;
  b.onclick = () => run(u); $("#ex").appendChild(b);
}));
const initial = new URLSearchParams(location.search).get("url");
if (initial) run(initial);
</script>
</body>
</html>
"""
