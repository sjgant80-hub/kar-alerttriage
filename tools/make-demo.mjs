// kar-alerttriage · tools/make-demo.mjs — the page's demo data: an UNALTERED excerpt of one AIT-ADS scenario
// (russellmitchell, the development scenario), every Wazuh + Suricata alert inside a window around the multi-step
// attack, written compactly. The labels.csv attack phase is kept as each alert's mark, so the page can show (on request)
// which groups were attack-time. AIT-ADS: Landauer, Skopik, Wurzenberger, CC BY 4.0, zenodo.org/records/8263181.
//   node tools/make-demo.mjs <ait_ads.zip> <labels.csv> [hoursBefore=2] [hoursAfter=2]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import readline from 'node:readline';
import { normalise } from '../triage.mjs';

const [zip, labelsPath, before = '2', after = '2'] = process.argv.slice(2);
const SCENARIO = 'russellmitchell';
const phases = readFileSync(labelsPath, 'utf8').trim().split(/\r?\n/).slice(1).map((l) => l.split(',')).filter((p) => p[0] === SCENARIO).map((p) => ({ name: p[1], start: +p[2], end: +p[3] }));
const multi = phases.filter((p) => !['service_stop', 'dnsteal'].includes(p.name));
const from = Math.min(...multi.map((p) => p.start)) - Number(before) * 3600, to = Math.max(...multi.map((p) => p.end)) + Number(after) * 3600;
const dict = { rules: [], names: [], hosts: [], marks: [''] }, idx = { rules: new Map(), hosts: new Map(), marks: new Map([['', 0]]) };
const put = (kind, v) => { if (!idx[kind].has(v)) { idx[kind].set(v, dict[kind].length); dict[kind].push(v); } return idx[kind].get(v); };
const rows = [];
const child = spawn('unzip', ['-p', zip, SCENARIO + '_wazuh.json']);
for await (const line of readline.createInterface({ input: child.stdout, crlfDelay: Infinity })) {
  if (!line.trim()) continue;
  let raw; try { raw = JSON.parse(line); } catch { continue; }
  const a = normalise(raw);
  if (a === null || a.t < from || a.t > to) continue;
  const p = phases.find((ph) => a.t >= ph.start && a.t <= ph.end);
  const r = put('rules', a.rule);
  if (dict.names.length <= r) dict.names[r] = a.name;
  rows.push([Math.round(a.t * 1000) / 1000, r, a.level, put('hosts', a.host), put('hosts', a.src), put('hosts', a.dst), put('marks', p ? p.name : '')]);
}
mkdirSync(new URL('../data/', import.meta.url), { recursive: true });
const out = {
  source: 'AIT Alert Data Set (AIT-ADS) v1, scenario ' + SCENARIO + ', ' + SCENARIO + '_wazuh.json (Wazuh + Suricata alerts), unaltered excerpt',
  licence: 'CC BY 4.0', citation: 'Landauer, M., Skopik, F., Wurzenberger, M. (2024): Introducing a New Alert Data Set for Multi-Step Attack Analysis. Proceedings of the 17th Cyber Security Experimentation and Test Workshop. Data: zenodo.org/records/8263181',
  window: { from, to, note: 'every alert from ' + before + ' h before the first to ' + after + ' h after the last step of the multi-step attack' },
  phases: multi.map((p) => p.name), format: 'alerts: [time, rule index, level, host index, source index, destination index, mark index]; marks are the data set\'s own time labels',
  rules: dict.rules, names: dict.names, hosts: dict.hosts, marks: dict.marks, alerts: rows,
};
writeFileSync(new URL('../data/demo.json', import.meta.url), JSON.stringify(out));
console.log(rows.length + ' alerts, ' + dict.rules.length + ' rules, ' + (JSON.stringify(out).length / 1024).toFixed(0) + ' KB');
