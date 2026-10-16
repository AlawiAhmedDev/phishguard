// Usage: node tests/web_parity.mjs urls.json  -> prints JSON [{features, proba, verdict}] to stdout
import { readFileSync } from "node:fs";
import { PhishGuard } from "../docs/phishguard.js";
const model = JSON.parse(readFileSync(new URL("../docs/model.json", import.meta.url)));
const pg = new PhishGuard(model);
const urls = JSON.parse(readFileSync(process.argv[2], "utf8"));
const out = urls.map((u) => {
  const r = pg.check(u);
  return { features: pg.features(u), proba: r.score, verdict: r.verdict, decided_by: r.decided_by,
           reasons: r.reasons.map((x) => x.feature) };
});
process.stdout.write(JSON.stringify(out));
