// kar-alerttriage · tools/measure.mjs — measure triage on the AIT Alert Data Set (AIT-ADS, CC BY 4.0, zenodo 8263181).
//   node tools/measure.mjs <path/to/ait_ads.zip> <path/to/labels.csv> <scenario> [<scenario> …]
// For each scenario: stream <scenario>_wazuh.json (Wazuh + Suricata alerts; AMiner is not used in v1), mark each alert
// with the attack phase whose labels.csv time window it falls in (the data set's own time labels), triage, and score.
//
// Metrics (fixed before any test scenario was run):
//   reduction       alerts ÷ groups
//   attack group    a group whose alerts are mostly (> 50%) attack-time
//   precision@k     attack groups among the top k
//   phase recall@k  attack phases that produced any alert, found in an attack group within the top k
//   alert recall@k  attack-time alerts that sit inside the top k groups
//   first attack    the rank of the first attack group (added on the development scenario, before any test run)
// Development scenario: russellmitchell (the smallest). Test scenarios: the other seven, run once, after this file and
// triage.mjs were committed; no parameter was changed after seeing them.
// Baseline, same metrics: one group per rule, ranked by its highest Wazuh level, then by alert count (what a
// severity-sorted alert queue shows an analyst).
// Caveat stated with every result: labels are by TIME; a routine event inside an attack window counts as attack-time.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import readline from 'node:readline';
import { normalise, triage, DEFAULTS } from '../triage.mjs';

const [zip, labelsPath, ...scenarios] = process.argv.slice(2);
if (!zip || !labelsPath || scenarios.length === 0) { console.error('usage: node tools/measure.mjs <ait_ads.zip> <labels.csv> <scenario>…'); process.exit(1); }
const labels = readFileSync(labelsPath, 'utf8').trim().split(/\r?\n/).slice(1).map((l) => l.split(','));
const KS = [5, 10, 20];

async function load(scenario) {
  const phases = labels.filter((p) => p[0] === scenario).map((p) => ({ name: p[1], start: +p[2], end: +p[3] }));
  const child = spawn('unzip', ['-p', zip, scenario + '_wazuh.json']);
  const out = [];
  let bad = 0;
  for await (const line of readline.createInterface({ input: child.stdout, crlfDelay: Infinity })) {
    if (!line.trim()) continue;
    let raw; try { raw = JSON.parse(line); } catch { bad++; continue; }
    const a = normalise(raw);
    if (a === null) { bad++; continue; }
    const p = phases.find((ph) => a.t >= ph.start && a.t <= ph.end);
    a.mark = p ? p.name : '';
    out.push(a);
  }
  return { phases, alerts: out, bad };
}

function score(groups, phasesSeen, totalMarked) {
  const isAttack = (g) => g.alerts > 0 && Object.values(g.marks).reduce((s, c) => s + c, 0) / g.alerts > 0.5;
  // added on the development scenario, before any test run: one attack should be ONE incident, so precision@k
  // under-rates a tool that groups it correctly; the rank of the first attack group is the analyst's real wait
  const firstAttack = groups.findIndex(isAttack);
  const res = { firstAttackRank: firstAttack < 0 ? null : firstAttack + 1 };
  for (const k of KS) {
    const top = groups.slice(0, k);
    const found = new Set();
    for (const g of top) if (isAttack(g)) for (const m of Object.keys(g.marks)) found.add(m);
    const marked = top.reduce((s, g) => s + Object.values(g.marks).reduce((a, c) => a + c, 0), 0);
    res['k' + k] = {
      precision: top.length ? top.filter(isAttack).length / top.length : 0,
      phaseRecall: phasesSeen.size ? [...found].filter((m) => phasesSeen.has(m)).length / phasesSeen.size : 0,
      alertRecall: totalMarked ? marked / totalMarked : 0,
      phasesFound: [...found].sort(),
    };
  }
  return res;
}

function severityBaseline(alerts) {
  const by = new Map();
  for (const a of alerts) {
    const g = by.get(a.rule) || { rule: a.rule, level: 0, alerts: 0, marks: {} };
    g.alerts = g.alerts + 1; if (a.level > g.level) g.level = a.level;
    if (a.mark !== '') g.marks[a.mark] = (g.marks[a.mark] || 0) + 1;
    by.set(a.rule, g);
  }
  return [...by.values()].sort((x, y) => y.level - x.level || y.alerts - x.alerts || (x.rule < y.rule ? -1 : 1));
}

mkdirSync(new URL('../results/', import.meta.url), { recursive: true });
const summary = [];
for (const scenario of scenarios) {
  const t0 = Date.now();
  const { phases, alerts, bad } = await load(scenario);
  const phasesSeen = new Set(alerts.map((a) => a.mark).filter((m) => m !== ''));
  const totalMarked = alerts.filter((a) => a.mark !== '').length;
  const r = triage(alerts);
  const base = severityBaseline(alerts);
  const out = {
    scenario, data: 'AIT-ADS v1 (zenodo 8263181), ' + scenario + '_wazuh.json', options: DEFAULTS,
    alerts: alerts.length, unparsable: bad, attackTimeAlerts: totalMarked, phases: phases.map((p) => p.name), phasesWithAlerts: [...phasesSeen].sort(),
    triage: { groups: r.stats.groups, bursts: r.stats.bursts, backgroundRules: r.stats.background, reduction: alerts.length / Math.max(1, r.stats.groups), ...score(r.groups, phasesSeen, totalMarked),
      top10: r.groups.slice(0, 10).map((g) => ({ kind: g.kind, score: +g.score.toFixed(3), alerts: g.alerts, attackTime: Object.values(g.marks).reduce((s, c) => s + c, 0), hosts: g.hosts.length, rules: g.rules.slice(0, 4).map((x) => x.name) })) },
    baseline: { groups: base.length, reduction: alerts.length / Math.max(1, base.length), ...score(base, phasesSeen, totalMarked) },
    seconds: Math.round((Date.now() - t0) / 1000),
  };
  writeFileSync(new URL('../results/' + scenario + '.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
  const f = (x) => (x * 100).toFixed(0) + '%';
  summary.push(scenario.padEnd(16) + String(alerts.length).padStart(8) + ' alerts → ' + String(r.stats.groups).padStart(5) + ' groups'
    + ' | triage P@10 ' + f(out.triage.k10.precision) + ' phase@10 ' + f(out.triage.k10.phaseRecall) + ' phase@20 ' + f(out.triage.k20.phaseRecall)
    + ' | baseline P@10 ' + f(out.baseline.k10.precision) + ' phase@10 ' + f(out.baseline.k10.phaseRecall) + ' phase@20 ' + f(out.baseline.k20.phaseRecall) + '  (' + out.seconds + ' s)');
  console.log(summary[summary.length - 1]);
}
