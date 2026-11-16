#!/usr/bin/env node
// kar-alerttriage · bin/triage.mjs — triage an alert export on your own machine. Nothing is sent anywhere.
//   node bin/triage.mjs alerts.json              JSON lines (one alert per line), or one JSON array
//   node bin/triage.mjs alerts.csv               CSV with a header: time, rule, severity, host, src, dst (names flexible)
//   node bin/triage.mjs alerts.json --top 20     how many groups to print (default 10)
//   node bin/triage.mjs alerts.json --json       print the full result as JSON instead
// Options: --burst-gap S  --incident-gap S  --background-share F   (defaults: 300, 1800, 0.25)
import { createReadStream, readFileSync, statSync } from 'node:fs';
import readline from 'node:readline';
import { normalise, triage, DEFAULTS } from '../triage.mjs';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--') && !/^\d/.test(a));
const flag = (name, d) => { const i = args.indexOf('--' + name); return i < 0 ? d : Number(args[i + 1]); };
if (!file) { console.error('usage: node bin/triage.mjs <alerts.json|alerts.jsonl|alerts.csv> [--top N] [--json]'); process.exit(1); }

// a small CSV reader: a header row, commas, double-quoted fields with "" escapes
export function parseCsv(text) {
  const rows = [];
  let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"' && text[i + 1] === '"') { field += '"'; i++; } else if (c === '"') q = false; else field += c; continue; }
    if (c === '"') q = true; else if (c === ',') { row.push(field); field = ''; } else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(field); rows.push(row); row = []; field = ''; } else field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  const head = (rows.shift() || []).map((h) => h.trim().toLowerCase());
  return rows.filter((r) => r.some((x) => x.trim() !== '')).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i]])));
}

async function load(path) {
  if (/\.csv$/i.test(path)) return parseCsv(readFileSync(path, 'utf8'));
  const head = readFileSync(path, { encoding: 'utf8', flag: 'r' }).slice(0, 64).trimStart();
  if (head.startsWith('[') && statSync(path).size < 512 * 1024 * 1024) return JSON.parse(readFileSync(path, 'utf8'));
  // JSON lines: normalise while streaming, so a large export never sits in memory as raw JSON
  const out = [];
  for await (const line of readline.createInterface({ input: createReadStream(path), crlfDelay: Infinity })) {
    if (!line.trim()) continue;
    try { const a = normalise(JSON.parse(line)); if (a !== null) out.push(a); } catch { /* not JSON: skipped */ }
  }
  return out;
}

const alerts = await load(file);
const r = triage(alerts, { burstGap: flag('burst-gap', DEFAULTS.burstGap), incidentGap: flag('incident-gap', DEFAULTS.incidentGap), backgroundShare: flag('background-share', DEFAULTS.backgroundShare) });
if (!r.ok) { console.error(r.why); process.exit(1); }
if (args.includes('--json')) { console.log(JSON.stringify(r, null, 1)); process.exit(0); }
const top = flag('top', 10);
const iso = (t) => new Date(t * 1000).toISOString().replace('T', ' ').slice(0, 19);
console.log(r.stats.alerts + ' alerts → ' + r.stats.bursts + ' bursts → ' + r.stats.groups + ' groups (' + r.stats.background + ' routine rules set aside; ' + r.stats.skipped + ' rows not read as alerts)\n');
r.groups.slice(0, top).forEach((g, i) => {
  console.log('#' + (i + 1) + '  score ' + g.score.toFixed(1) + '  ' + g.kind + '  ' + g.alerts + ' alerts  ' + iso(g.first) + ' → ' + iso(g.last));
  console.log('    hosts: ' + (g.hosts.join(', ') || '—') + (g.addresses.length ? '   addresses: ' + g.addresses.slice(0, 6).join(', ') + (g.addresses.length > 6 ? ' …' : '') : ''));
  for (const x of g.rules.slice(0, 5)) console.log('    ' + x.points.toFixed(1).padStart(6) + '  ' + x.name + '  (' + x.alerts + ' alerts, level ' + x.level + ', rarity ' + x.rarity.toFixed(2) + ')');
  if (g.rules.length > 5) console.log('           … and ' + (g.rules.length - 5) + ' more rules');
});
