// kar-alerttriage · page-parity.test.mjs — the page runs the gated kernel, and every number it states is the measured one.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import T from './triage.mjs';

const NL = String.fromCharCode(10);
const read = (p) => readFileSync(new URL('./' + p, import.meta.url), 'utf8').replace(/\r\n/g, NL);
const page = read('index.html');
const src = read('triage.mjs');
const body = src.slice(src.indexOf('export const DEFAULTS'), src.indexOf('export default')).replace(/\bexport /g, '').trimEnd();
const text = page.replace(/<script[\s\S]*?<\/script>/g, ' ').replace(/<style[\s\S]*?<\/style>/g, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
const SCENARIOS = ['russellmitchell', 'fox', 'harrison', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson'];
const R = SCENARIOS.map((s) => JSON.parse(read('results/' + s + '.json')));
const pct = (x) => Math.round(x * 100);
const range = (xs) => Math.min(...xs) + '–' + Math.max(...xs) + '%';

test('the page runs triage.mjs byte for byte, and nothing in it can end the page script early', () => {
  assert.ok(body.length > 4000);
  assert.ok(page.includes('/*TRIAGE:BEGIN*/' + NL + body + NL + '/*TRIAGE:END*/'));
  assert.ok(!/<\/script/i.test(body) && !body.includes('<!--'));
  const ctx = {};
  vm.runInNewContext(body + NL + ';globalThis.__t = triage;', ctx);
  const demo = JSON.parse(read('data/demo.json'));
  const alerts = demo.alerts.map((a) => ({ t: a[0], rule: demo.rules[a[1]], name: demo.names[a[1]], level: a[2], host: demo.hosts[a[3]], src: demo.hosts[a[4]], dst: demo.hosts[a[5]], mark: demo.marks[a[6]] }));
  assert.equal(JSON.stringify(ctx.__t(alerts)), JSON.stringify(T.triage(alerts)), 'the inlined kernel agrees with the module on the demo');
});

test('every headline number is the measured one', () => {
  const total = R.reduce((s, r) => s + r.alerts, 0);
  assert.ok(text.includes(total.toLocaleString('en-GB') + ' real alerts it was measured on'), 'total alerts ' + total);
  const firsts = R.filter((r) => r.triage.firstAttackRank === 1).length;
  assert.ok(text.includes(firsts + ' of 8 attacks ranked first'), 'attacks ranked first: ' + firsts);
  assert.ok(text.includes(range(R.map((r) => pct(r.triage.k10.alertRecall))) + ' of attack-time alerts in the top 10'), 'triage alert recall ' + range(R.map((r) => pct(r.triage.k10.alertRecall))));
  assert.ok(text.includes(range(R.map((r) => pct(r.baseline.k10.alertRecall))) + ' the same for a severity-sorted queue'), 'baseline alert recall');
  const b = R.map((r) => r.baseline.firstAttackRank);
  assert.ok(text.includes('rank ' + Math.min(...b) + ' to ' + Math.max(...b) + ' for the severity queue'));
  assert.ok(text.includes('(' + range(R.map((r) => pct(r.triage.k10.precision))) + ', against ' + range(R.map((r) => pct(r.baseline.k10.precision))) + ')'), 'the loss is stated with its numbers');
  assert.ok(R.every((r) => r.triage.k10.phaseRecall > r.baseline.k10.phaseRecall), 'the page says it finds more phases in all eight');
  assert.ok(R.every((r) => !r.triage.k10.phasesFound.includes('dnsteal')) && text.includes('DNS exfiltration is missed in all eight scenarios'));
  assert.ok(R.every((r) => !r.triage.k10.phasesFound.includes('network_scans')) && text.includes('first network scans'));
});

test('the pre-registration is stated and the demo is the credited data', () => {
  for (const c of ['5cc52e6', 'b996c20', '03a3111']) assert.ok(page.includes('/commit/' + c), 'commit ' + c);
  assert.ok(R.every((r) => r.data.startsWith('AIT-ADS v1 (zenodo 8263181)')));
  const demo = JSON.parse(read('data/demo.json'));
  assert.equal(demo.licence, 'CC BY 4.0');
  assert.ok(text.includes('Landauer, M., Skopik, F., Wurzenberger, M. (2024)') && text.includes('CC BY 4.0'));
  assert.ok(text.includes('Run the demo (' + demo.alerts.length.toLocaleString('en-GB') + ' real alerts)'), 'the demo count on the button is the excerpt size');
});

test('the brochure, supplier, licence and no prices', () => {
  for (const h of ['Security operations lead', 'CISO', 'Finance', 'IT and engineering', 'Against what you pay now', 'The board', 'Security and data protection', 'Deployment and roll-out', 'Ownership, support and exit']) assert.ok(text.includes(h), h);
  for (const id of ['what', 'start-here', 'try', 'how', 'measured', 'blueprint', 'business', 'limits']) assert.ok(page.includes('id="' + id + '"'), '#' + id);
  assert.ok(page.includes('href="https://www.ai-nativesolutions.com/">AI Native Solutions</a>') && text.includes('MIT, © Simon Gant'));
  assert.ok(!/[£€$]\s?\d/.test(text), 'a price on the page');
  assert.ok(!new RegExp(['karma', 'didy'].join('-'), 'i').test(page) && !/[κφ◊]/.test(page));
});

test('the page builds its output with text nodes, and loads nothing from elsewhere', () => {
  const ui = page.slice(page.indexOf('/*TRIAGE:END*/'));
  assert.ok(!/\.innerHTML\s*=|insertAdjacentHTML|document\.write/.test(ui.slice(0, ui.indexOf('</script>'))));
  assert.ok(!/<script[^>]+src=/.test(page) && !/<link[^>]+stylesheet/.test(page));
  assert.ok(/connect-src 'self'/.test(page), 'the policy lets the page fetch only its own files');
});
