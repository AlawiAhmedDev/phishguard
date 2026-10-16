// PhishGuard in the browser: a faithful JavaScript port of phishguard/features.py,
// reputation.py and model.py. It loads model.json (exported from the trained
// scikit-learn model by scripts/export_web_model.py) and scores URLs locally.
// tests/test_web_parity.py checks that it gives the same scores as Python.

const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
const LONG_TOKEN = /[a-z0-9]{24,}/;
const HEX_TOKEN = /\b[0-9a-f]{16,}\b/;
const SCRIPT_EXT = /\.(php|html?|aspx?|jsp|cgi)$/;
const DIGIT = /\p{Nd}/u;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$/;

const chars = (s) => Array.from(s);
const len = (s) => chars(s).length;
const count = (s, sub) => (sub ? s.split(sub).length - 1 : 0);
const countDigits = (s) => chars(s).filter((c) => DIGIT.test(c)).length;

function isIPv6(h) {
  if (!h.includes(":")) return false;
  try { new URL(`http://[${h}]/`); return true; } catch { return false; }
}

function isIP(host) {
  const h = host.replace(/^\[+|\]+$/g, "");
  if (IPV4.test(h) || isIPv6(h)) return true;
  return /^(0x[0-9a-f]+|\d{8,10})$/.test(host);
}

// Python 3.12+ sum() uses Neumaier compensated summation. Matching it bit for bit
// matters: a 1e-15 difference can flip a tree split that sits exactly on a value.
function pySum(terms) {
  let s = 0, c = 0;
  for (const x of terms) {
    const t = s + x;
    c += Math.abs(s) >= Math.abs(x) ? (s - t) + x : (x - t) + s;
    s = t;
  }
  return s + c;
}

function entropy(s) {
  const cs = chars(s);
  if (!cs.length) return 0;
  const counts = new Map();
  for (const c of cs) counts.set(c, (counts.get(c) || 0) + 1);
  const n = cs.length;
  return -pySum([...counts.values()].map((k) => (k / n) * Math.log2(k / n)));
}

// ---------- Public-suffix split (port of tldextract, ICANN rules only) ----------

function buildTrie(rules) {
  const root = { m: new Map(), end: false };
  for (const rule of rules) {
    let node = root;
    for (const label of rule.split(".").reverse()) {
      if (!node.m.has(label)) node.m.set(label, { m: new Map(), end: false });
      node = node.m.get(label);
    }
    node.end = true;
  }
  return root;
}

function suffixIndex(trie, labels) {
  let node = trie;
  let suffixIdx = labels.length, labelIdx = labels.length;
  for (let i = labels.length - 1; i >= 0; i--) {
    const d = labels[i].toLowerCase();
    if (node.m.has(d)) {
      labelIdx -= 1;
      node = node.m.get(d);
      if (node.end) suffixIdx = labelIdx;
      continue;
    }
    if (node.m.has("*")) return node.m.has("!" + d) ? labelIdx : labelIdx - 1;
    break;
  }
  return suffixIdx === labels.length ? null : suffixIdx;
}

function hostFromAuthority(authority) {
  const afterUser = authority.slice(authority.lastIndexOf("@") + 1);
  if (afterUser[0] === "[") {
    const close = afterUser.indexOf("]");
    if (close !== -1) return afterUser.slice(0, close) + "]";
  }
  return afterUser.split(":")[0].trim().replace(/[.。．｡]+$/, "");
}

function tldSplit(trie, host) {
  const netloc = hostFromAuthority(host.split("/")[0].split("?")[0].split("#")[0])
    .replace(/[。．｡]/g, ".");
  if (netloc.length >= 4 && netloc[0] === "[" && netloc.at(-1) === "]" && isIPv6(netloc.slice(1, -1))) {
    return { subdomain: "", domain: netloc, suffix: "" };
  }
  const labels = netloc.split(".");
  const idx = suffixIndex(trie, labels);
  if (idx === null && labels.length === 4 && /^\d/.test(netloc) && IPV4.test(netloc)) {
    return { subdomain: "", domain: netloc, suffix: "" };
  }
  if (idx === null) {
    return { subdomain: labels.slice(0, -1).join("."), domain: labels.at(-1), suffix: "" };
  }
  return {
    subdomain: idx >= 2 ? labels.slice(0, idx - 1).join(".") : "",
    domain: idx > 0 ? labels[idx - 1] : "",
    suffix: labels.slice(idx).join("."),
  };
}

// ---------- URL parsing (mirrors Python's urlsplit on "http://" + url) ----------

export function normalize(url) {
  let u = url.trim().toLowerCase().replace(SCHEME, "");
  if (u.startsWith("www.")) u = u.slice(4);
  return u;
}

function splitURL(norm) {
  const s = norm.replace(/[\t\r\n]/g, "");
  const m = s.match(/^([^/?#]*)([^?#]*)(?:\?([^#]*))?/);
  const netloc = m[1], path = m[2] || "", query = m[3] || "";
  const hostinfo = netloc.slice(netloc.lastIndexOf("@") + 1);
  if (netloc.includes("[") !== netloc.includes("]")) throw new Error("Invalid IPv6 URL");
  let hostname, portStr = "";
  if (hostinfo.includes("[")) {
    const inside = hostinfo.slice(hostinfo.indexOf("[") + 1, hostinfo.indexOf("]"));
    if (!isIPv6(inside.split("%")[0]) && !/^v[0-9a-f]+\./i.test(inside)) throw new Error("Invalid IPv6 URL");
    hostname = inside;
    const after = hostinfo.slice(hostinfo.indexOf("]") + 1);
    if (after.startsWith(":")) portStr = after.slice(1);
  } else {
    const i = hostinfo.indexOf(":");
    hostname = i === -1 ? hostinfo : hostinfo.slice(0, i);
    if (i !== -1) portStr = hostinfo.slice(i + 1);
  }
  let port = null;
  if (portStr && /^[0-9]+$/.test(portStr) && Number(portStr) <= 65535) port = Number(portStr);
  return { host: hostname.toLowerCase().replace(/\.+$/, ""), path, query, port };
}

export class PhishGuard {
  constructor(model) {
    this.m = model;
    const L = model.lists;
    this.trie = buildTrie(L.suffix_rules);
    this.suspiciousTlds = new Set(L.suspicious_tlds);
    this.shorteners = new Set(L.shorteners);
    this.neverTrusted = new Set(L.never_trusted);
    this.popular = new Set(L.popular_domains);
    this.names = model.feature_names;
  }

  parse(url) {
    const normalized = normalize(url);
    let host, path, query, port;
    try {
      ({ host, path, query, port } = splitURL(normalized));
    } catch {
      const m = normalized.match(/([^/?#]*)([^?#]*)\??([^#]*)/);
      path = m[2]; query = m[3]; port = null;
      host = m[1].slice(m[1].lastIndexOf("@") + 1).split(":")[0].replace(/^\[+|\]+$/g, "").replace(/\.+$/, "");
    }
    const t = tldSplit(this.trie, host);
    const registered = t.suffix ? `${t.domain}.${t.suffix}` : t.domain;
    return { normalized, host, path, query, port, ...t, registered };
  }

  features(url) {
    const p = this.parse(url);
    const L = this.m.lists;
    const u = p.normalized, { host, path, query } = p;
    const outside = `${p.subdomain}/${path}?${query}`;
    return {
      url_length: len(u),
      host_length: len(host),
      path_length: len(path),
      query_length: len(query),
      n_subdomains: p.subdomain.split(".").filter(Boolean).length,
      n_dots_host: count(host, "."),
      n_hyphens_host: count(host, "-"),
      n_digits_host: countDigits(host),
      n_hyphens_path: count(path, "-"),
      n_digits_path: countDigits(path),
      digit_ratio: countDigits(u) / Math.max(len(u), 1),
      path_depth: count(path, "/"),
      n_params: query.split("&").filter(Boolean).length,
      n_special: [..."=&%~_@"].reduce((a, c) => a + count(u, c), 0),
      host_entropy: entropy(host),
      path_entropy: entropy(path),
      domain_length: len(p.domain),
      domain_has_digit: chars(p.domain).some((c) => DIGIT.test(c)) ? 1 : 0,
      tld_length: len(p.suffix),
      has_ip: isIP(host) ? 1 : 0,
      has_at: u.includes("@") ? 1 : 0,
      has_double_slash: path.includes("//") ? 1 : 0,
      has_port: p.port !== null ? 1 : 0,
      has_punycode: host.includes("xn--") ? 1 : 0,
      suspicious_words: L.suspicious_words.filter((w) => u.includes(w)).length,
      brand_outside_domain: L.brands.some((b) => outside.includes(b) && !p.domain.includes(b)) ? 1 : 0,
      suspicious_tld: this.suspiciousTlds.has(p.suffix.split(".").at(-1)) ? 1 : 0,
      free_hosting: L.free_hosting.some((f) => host === f || host.endsWith("." + f)) ? 1 : 0,
      is_shortener: this.shorteners.has(p.registered) || this.shorteners.has(host) ? 1 : 0,
      script_extension: SCRIPT_EXT.test(path) ? 1 : 0,
      long_token: LONG_TOKEN.test(path + query) ? 1 : 0,
      hex_token: HEX_TOKEN.test(u) ? 1 : 0,
    };
  }

  rawScore(x) {
    let raw = this.m.baseline_prediction;
    for (const tree of this.m.trees) {
      let node = tree[0];
      while (node.length === 4) node = tree[x[node[0]] <= node[1] ? node[2] : node[3]];
      raw += node[0];
    }
    return raw;
  }

  proba(x) { return 1 / (1 + Math.exp(-this.rawScore(x))); }

  isTrusted(registered, host) {
    if (this.neverTrusted.has(registered)) return false;
    for (const h of this.neverTrusted) if (host === h || host.endsWith("." + h)) return false;
    return this.popular.has(registered);
  }

  explain(x, top = 3) {
    // Same feature ablation as model.py, in log-odds
    const base = this.rawScore(x);
    const drops = this.names.map((_, i) => {
      const y = x.slice(); y[i] = this.m.baseline_features[i];
      return Math.max(base - this.rawScore(y), 0);
    });
    const total = drops.reduce((a, b) => a + b, 0);
    if (total <= 0) return [];
    return drops.map((d, i) => ({ i, share: d / total }))
      .sort((a, b) => b.share - a.share).slice(0, top).filter((r) => r.share >= 0.05)
      .map(({ i, share }) => ({
        feature: this.names[i], label: this.m.feature_labels[this.names[i]],
        value: x[i], impact: share,
      }));
  }

  check(url) {
    const p = this.parse(url);
    const f = this.features(url);
    const x = this.names.map((n) => f[n]);
    const score = this.proba(x);
    const base = { url, host: p.host, registered_domain: p.registered, score,
      anatomy: { subdomain: p.subdomain, registered_domain: p.registered,
        port: p.port !== null ? `:${p.port}` : "", path: p.path === "/" ? "" : p.path,
        query: p.query ? `?${p.query}` : "" } };
    if (f.is_shortener) {
      return { ...base, verdict: "suspicious", decided_by: "shortener", reasons: [{
        feature: "is_shortener", label: "shortened link: the real destination is hidden",
        value: 1, impact: 0 }] };
    }
    if (this.isTrusted(p.registered, p.host)) {
      return { ...base, verdict: "safe", decided_by: "reputation", reasons: [] };
    }
    const T = this.m.thresholds;
    const verdict = score >= T.phishing ? "phishing" : score >= T.suspicious ? "suspicious" : "safe";
    return { ...base, verdict, decided_by: "model", reasons: verdict === "safe" ? [] : this.explain(x) };
  }
}
