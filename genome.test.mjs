// AlertTriage as a cell of the estate genome: its judge (the kernel's own ranked run), its lane and its health.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { judge, inLane, health } from './genome/cell.mjs';

const seed = JSON.parse(readFileSync(new URL('./seed.json', import.meta.url), 'utf8'));
const row = (t, rule, host, level = 5) => ({ t, rule, host, level });
const ALERTS = [];
for (let h = 0; h < 8; h++) ALERTS.push(row(h * 3600, 'noise', 'mail', 3));
ALERTS.push(row(3 * 3600 + 10, 'rare', 'web', 10), row(3 * 3600 + 20, 'rare2', 'web', 10));
const OPT = { backgroundMinHours: 8 };
const INC = { kind: 'incident', rules: ['rare', 'rare2'] }, BG = { kind: 'background', rules: ['noise'] };
const ask = (ranking, options = OPT) => ({ alerts: ALERTS, options, ranking });

test('judge: the seed cases are the kernel background test — the rare incident first verifies, noise first does not', async () => {
  assert.deepEqual(seed.judge.cases.good, ask([INC, BG]));
  assert.equal(await judge(seed.judge.cases.good), 'verified');
  assert.deepEqual(seed.judge.cases.bad.alerts, ALERTS);
  assert.equal(await judge(seed.judge.cases.bad), 'unverified');
});

test('judge: the kinds, the rules and the order must all be the kernel ranking', async () => {
  assert.equal(await judge(ask([{ kind: 'incident', rules: ['rare2', 'rare'] }, BG])), 'verified');   // rule order within a group is free
  assert.equal(await judge(ask([BG, INC])), 'unverified');
  assert.equal(await judge(ask([INC, { kind: 'incident', rules: ['noise'] }])), 'unverified');
  assert.equal(await judge(ask([INC, { kind: 'background', rules: ['noise', 'rare'] }])), 'unverified');
  assert.equal(await judge(ask([INC])), 'unverified');
  assert.equal(await judge(ask([INC, BG, BG])), 'unverified');
  assert.equal(await judge(ask([])), 'unverified');
  // the options are part of the question: with the default 24-hour minimum nothing is routine on an 8-hour export, so
  // the noise is not set aside and each hourly burst of it stands alone (they are an hour apart, past the 30-minute link)
  assert.equal(await judge(ask([INC, BG], {})), 'unverified');
  const hourly = Array.from({ length: 8 }, () => ({ kind: 'incident', rules: ['noise'] }));
  assert.equal(await judge(ask([INC, ...hourly], {})), 'verified');
  assert.equal(await judge(ask([INC, ...hourly.slice(1)], {})), 'unverified');
});

test('judge: anything that is not alerts to triage with a ranking of groups is refused', async () => {
  for (const bad of [null, undefined, 'x', 5, {}, [], { alerts: ALERTS, options: OPT }, ask('x'), ask(5), ask({}), ask([null]), ask(['incident']),
    ask([{ kind: 5, rules: ['rare'] }]), ask([{ kind: 'incident' }]), ask([{ kind: 'incident', rules: 'rare' }]),
    ask([{ rules: ['rare'] }]), ask([{ kind: 'incident', rules: ['rare', 7] }]), ask([INC, { kind: 'background', rules: [null] }]),
    { alerts: [], options: OPT, ranking: [] }, { alerts: 'x', ranking: [] }]) {
    assert.equal(await judge(bad), 'refused', String(JSON.stringify(bad)));
  }
});

test('lane: alerts the kernel can place in time are in lane; a request to act is not', async () => {
  assert.equal(await inLane(seed.boundary.inLane), true);
  assert.equal(await inLane(seed.boundary.outOfLane), false);
  assert.equal(await inLane({ alerts: [row(0, 'a', 'h')] }), true);
  assert.equal(await inLane({ alerts: [row(0, 'a', 'h'), 'garbage'] }), true);
  for (const bad of [null, undefined, 'x', 5, {}, [], () => {}, { alerts: [] }, { alerts: ['garbage', 7] }, { alerts: 'x' }, { options: OPT }]) {
    assert.equal(await inLane(bad), false, String(JSON.stringify(bad)));
  }
});

test('health says what AlertTriage cannot measure from inside its repository', async () => {
  assert.deepEqual(await health(), { used: null, dependedOn: null, lastEarned: null });
});
