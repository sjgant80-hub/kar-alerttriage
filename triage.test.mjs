// kar-alerttriage · triage.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import T from './triage.mjs';

const { DEFAULTS, time, normalise, triage } = T;
const W = (t, id, level, host, extra = {}) => ({ '@timestamp': new Date(t * 1000).toISOString(), agent: { ip: host, name: 'wazuh-client' }, rule: { id, level, description: 'rule ' + id }, ...extra });
const row = (t, rule, host, level = 5, more = {}) => ({ t, rule, host, level, ...more });

test('time reads ISO, epoch seconds and milliseconds, and refuses the rest', () => {
  assert.equal(time('2022-01-21T00:02:27.000000Z'), 1642723347);
  assert.equal(time('2022-01-21T00:14:21.351932+0000'), 1642724061.351);
  assert.equal(time(1642723347), 1642723347);
  assert.equal(time(1642723347000), 1642723347);
  assert.equal(time(1e12), 1e12);
  assert.equal(time('1642723347'), 1642723347);
  assert.equal(time(' 1642723347.5 '), 1642723347.5);
  for (const bad of ['', '  ', 'nope', null, undefined, {}, NaN, Infinity]) assert.ok(Number.isNaN(time(bad)), String(bad));
});

test('normalise: Wazuh, Suricata through Wazuh, raw Suricata, ECS, flat rows, and pre-normalised alerts', () => {
  assert.deepEqual(normalise(W(100, '31101', 5, '10.0.0.1', { data: { srcip: '1.2.3.4' } })),
    { t: 100, from: 'wazuh', rule: 'wazuh:31101', name: 'rule 31101', level: 5, host: '10.0.0.1', src: '1.2.3.4', dst: '', mark: '' });
  const viaW = W(100, '86601', 3, '10.0.0.2', { data: { src_ip: '5.6.7.8', dest_ip: '9.9.9.9', alert: { signature_id: '2013504', signature: 'ET POLICY APT' } } });
  assert.deepEqual(normalise(viaW), { t: 100, from: 'suricata', rule: 'suricata:2013504', name: 'ET POLICY APT', level: 3, host: '10.0.0.2', src: '5.6.7.8', dst: '9.9.9.9', mark: '' });
  assert.equal(normalise({ timestamp: '1970-01-01T00:01:40Z', agent: { name: 'web' }, rule: { id: 7, level: 99 } }).level, 15, 'levels clamp to 15');
  assert.equal(normalise({ timestamp: 100, agent: {}, rule: { id: 7, level: -3 }, predecoder: { hostname: 'mail' } }).host, 'mail');
  assert.equal(normalise({ '@timestamp': 'bad', agent: {}, rule: { id: 1 } }), null);
  assert.deepEqual(normalise({ event_type: 'alert', timestamp: '1970-01-01T00:01:40Z', host: 'sensor', src_ip: '1.1.1.1', dest_ip: '2.2.2.2', alert: { signature_id: 9, signature: 'ET SCAN', severity: 1 } }),
    { t: 100, from: 'suricata', rule: 'suricata:9', name: 'ET SCAN', level: 12, host: 'sensor', src: '1.1.1.1', dst: '2.2.2.2', mark: '' });
  assert.equal(normalise({ event_type: 'alert', timestamp: 100, in_iface: 'eth0', alert: { signature: 'X', severity: 3 } }).level, 4);
  assert.equal(normalise({ event_type: 'alert', timestamp: 100, alert: { signature: 'X' } }).level, 0);
  assert.equal(normalise({ event_type: 'alert', timestamp: 'x', alert: {} }), null);
  assert.deepEqual(normalise({ '@timestamp': 100, event: { severity: 47 }, rule: { name: 'Brute force' }, host: { name: 'dc1' }, source: { ip: '3.3.3.3' }, destination: { ip: '4.4.4.4' } }),
    { t: 100, from: 'ecs', rule: 'ecs:Brute force', name: 'Brute force', level: 7.05, host: 'dc1', src: '3.3.3.3', dst: '4.4.4.4', mark: '' });
  assert.equal(normalise({ '@timestamp': 100, event: { severity: 12, code: '4625' }, host: { ip: '1.1.1.1' } }).level, 12);
  assert.equal(normalise({ '@timestamp': 100, event: { severity: 15, code: '4625' } }).level, 15);
  assert.equal(normalise({ '@timestamp': 100, event: { severity: 16, code: '4625' } }).level, 2.4);
  assert.equal(normalise({ '@timestamp': 100, event: {}, host: {} }), null, 'ECS with no rule is not an alert');
  assert.equal(normalise({ '@timestamp': 100, event: { action: 'logon-failed' } }).rule, 'ecs:logon-failed');
  assert.deepEqual(normalise({ time: '100', rule: 'R1', severity: '6', hostname: 'h', src_ip: 's', destination: 'd', name: 'N', mark: 'phase1' }),
    { t: 100, from: 'row', rule: 'row:R1', name: 'N', level: 6, host: 'h', src: 's', dst: 'd', mark: 'phase1' });
  assert.equal(normalise({ timestamp: 100, signature: 'S' }).rule, 'row:S');
  assert.equal(normalise({ time: 100 }), null, 'a row needs a rule');
  assert.deepEqual(normalise(row(5, 'given:1', 'h1', 20, { from: 'x', mark: 'm' })), { t: 5, from: 'x', rule: 'given:1', name: 'given:1', level: 15, host: 'h1', src: '', dst: '', mark: 'm' });
  assert.equal(normalise({ t: 5, rule: '' , time: 9, signature: 'Z' }).rule, 'row:Z', 'an empty given rule falls through');
  for (const bad of [null, 7, 'x', [], [1]]) assert.equal(normalise(bad), null);
});

test('bursts: repeats within the gap merge; a gap, another host or another address starts a new burst', () => {
  const r = triage([row(0, 'a', 'h'), row(300, 'a', 'h'), row(601, 'a', 'h'), row(601, 'a', 'h2'), row(602, 'a', 'h', 5, { src: 'x' })], { backgroundShare: 2 });
  assert.equal(r.stats.bursts, 4);
  const at300 = triage([row(0, 'a', 'h'), row(300, 'a', 'h')]); assert.equal(at300.stats.bursts, 1, 'exactly the gap still merges');
  const at301 = triage([row(0, 'a', 'h'), row(301, 'a', 'h')]); assert.equal(at301.stats.bursts, 2);
  const lv = triage([row(0, 'a', 'h', 2), row(10, 'a', 'h', 9), row(20, 'a', 'h', 4)]);
  assert.equal(lv.groups[0].rules[0].level, 9, 'a burst keeps its highest level');
  assert.equal(lv.groups[0].alerts, 3);
});

test('background: a rule in at least a quarter of the hours is set aside, one group per rule', () => {
  const alerts = [];
  for (let h = 0; h < 8; h++) alerts.push(row(h * 3600, 'noise', 'mail', 3));
  alerts.push(row(3 * 3600 + 10, 'rare', 'web', 10), row(3 * 3600 + 20, 'rare2', 'web', 10));
  assert.equal(triage(alerts).stats.background, 0, 'eight hours is shorter than the 24 an export needs before anything is routine');
  const r = triage(alerts, { backgroundMinHours: 8 });
  assert.equal(r.stats.hours, 8);
  assert.equal(r.stats.background, 1, 'exactly the minimum span is long enough');
  assert.equal(triage(alerts, { backgroundMinHours: 9 }).stats.background, 0);
  const bg = r.groups.find((g) => g.kind === 'background');
  assert.equal(bg.alerts, 8); assert.equal(bg.bursts, 8); assert.deepEqual(bg.rules.map((x) => x.rule), ['noise']);
  const inc = r.groups.find((g) => g.kind === 'incident');
  assert.deepEqual(inc.rules.map((x) => x.rule).sort(), ['rare', 'rare2']);
  assert.equal(r.groups[0].kind, 'incident', 'the rare incident outranks the noise');
  const quarter = []; for (let h = 0; h < 4; h++) quarter.push(row(h * 3600, h === 0 ? 'once' : 'x' + h, 'h' + h));
  assert.equal(triage(quarter, { backgroundMinHours: 1 }).stats.background, 4, 'exactly a quarter of the hours counts as background');
  assert.equal(triage(quarter, { backgroundMinHours: 1, backgroundShare: 0.26 }).stats.background, 0);
  assert.equal(triage([row(0, 'a', 'h'), row(10, 'b', 'h')], { backgroundMinHours: 2 }).stats.background, 0, 'one hour is under a two-hour minimum');
  const day = []; for (let h = 0; h < 24; h++) day.push(row(h * 3600, 'hourly', 'mail'));
  assert.equal(triage(day).stats.background, 1, 'a full day with the default minimum sets routine noise aside');
});

test('incidents link by host or by address within the gap, and not beyond it', () => {
  const r = triage([row(0, 'a', 'web'), row(1000, 'b', 'web'), row(1000 + 1800, 'c', 'web'), row(1000 + 1800 + 1801, 'd', 'web')], { backgroundShare: 2 });
  const inc = r.groups.filter((g) => g.kind === 'incident');
  assert.equal(inc.length, 2);
  assert.deepEqual(inc.map((g) => g.rules.length).sort(), [1, 3]);
  const viaAddr = triage([row(0, 'a', 'web', 5, { src: '6.6.6.6' }), row(60, 'b', 'mail', 5, { dst: '6.6.6.6' }), row(120, 'c', 'db')], { backgroundShare: 2 });
  const big = viaAddr.groups.find((g) => g.rules.length === 2);
  assert.deepEqual(big.hosts, ['mail', 'web']);
  assert.deepEqual(big.addresses, ['6.6.6.6']);
  assert.equal(viaAddr.stats.groups, 2, 'an unrelated host stays apart');
  const noEntity = triage([row(0, 'a', ''), row(1, 'b', '')], { backgroundShare: 2 });
  assert.equal(noEntity.stats.groups, 2, 'alerts with no host or address never link');
  const longBurst = triage([row(0, 'a', 'h'), row(250, 'a', 'h'), row(500, 'a', 'h'), row(400, 'b', 'h')], { backgroundShare: 2, incidentGap: 0 });
  assert.equal(longBurst.stats.groups, 1, 'a burst that is still open links what starts inside it');
  const later = triage([row(0, 'a', 'h'), row(5000, 'b', 'h'), row(5100, 'c', 'h')], { backgroundShare: 2 });
  assert.equal(later.stats.groups, 2, 'the link is to the latest burst on the entity');
  const order = triage([row(0, 'a', 'h'), row(250, 'a', 'h'), row(200, 'b', 'h'), row(1900, 'c', 'h')], { backgroundShare: 2 });
  assert.equal(order.stats.groups, 1, 'a later-ending burst stays the entity\'s latest');
});

test('score: rarity × (1 + level/15), summed over distinct rules, explained, and ranked', () => {
  const r = triage([row(0, 'common', 'a', 0), row(1000, 'common', 'b', 0), row(2000, 'common', 'c', 0), row(9000, 'rare', 'z', 15)], { backgroundShare: 2 });
  const bursts = 4;
  const top = r.groups[0];
  assert.deepEqual(top.rules.map((x) => x.rule), ['rare']);
  assert.ok(Math.abs(top.score - Math.log(bursts / 1) * 2) < 1e-12);
  assert.ok(Math.abs(top.rules[0].rarity - Math.log(4)) < 1e-12);
  const c = r.groups.find((g) => g.hosts[0] === 'a');
  assert.ok(Math.abs(c.score - Math.log(4 / 3)) < 1e-12);
  const tie = triage([row(0, 'x', 'p'), row(100000, 'y', 'q')], { backgroundShare: 2 });
  assert.deepEqual(tie.groups.map((g) => g.first), [0, 100000], 'equal scores keep time order');
  const two = triage([row(0, 'm', 'h', 0), row(10, 'n', 'h', 15), row(5000, 'm', 'k', 0)], { backgroundShare: 2 });
  const g = two.groups[0];
  assert.deepEqual(g.rules.map((x) => x.rule), ['n', 'm'], 'rules sorted by points');
  assert.equal(g.first, 0); assert.equal(g.last, 10);
  const same = triage([row(0, 'b2', 'h', 5), row(1, 'a2', 'h', 5)], { backgroundShare: 2 });
  assert.deepEqual(same.groups[0].rules.map((x) => x.rule), ['a2', 'b2'], 'equal points break ties by rule name');
});

test('marks are carried and counted per group, and never change the ranking', () => {
  const plain = triage([row(0, 'a', 'h'), row(10, 'a', 'h'), row(20, 'b', 'h'), row(9000, 'c', 'k')], { backgroundShare: 2 });
  const marked = triage([row(0, 'a', 'h', 5, { mark: 'p1' }), row(10, 'a', 'h', 5, { mark: 'p1' }), row(20, 'b', 'h', 5, { mark: 'p2' }), row(9000, 'c', 'k')], { backgroundShare: 2 });
  assert.deepEqual(marked.groups.map((g) => g.score), plain.groups.map((g) => g.score));
  const g = marked.groups.find((x) => x.hosts[0] === 'h');
  assert.deepEqual(g.marks, { p1: 2, p2: 1 });
  assert.deepEqual(marked.groups.find((x) => x.hosts[0] === 'k').marks, {});
  const late = triage([row(0, 'a', 'h'), row(10, 'a', 'h', 5, { mark: 'p9' })], { backgroundShare: 2 });
  assert.deepEqual(late.groups[0].marks, { p9: 1 }, 'a mark on a later alert in a burst is counted');
});

test('refusals, options and garbage', () => {
  for (const bad of [null, undefined, 'x', 7, {}]) assert.deepEqual(triage(bad), { ok: false, why: 'give a list of alerts' });
  assert.deepEqual(triage([]), { ok: true, groups: [], stats: { alerts: 0, skipped: 0, bursts: 0, groups: 0, background: 0, hours: 0 } });
  assert.deepEqual(triage([null, 7, {}]).stats, { alerts: 0, skipped: 3, bursts: 0, groups: 0, background: 0, hours: 0 });
  const opts = triage([row(0, 'a', 'h'), row(400, 'a', 'h')], { burstGap: 500, incidentGap: -1, backgroundShare: 'x', junk: 1 });
  assert.equal(opts.stats.bursts, 1, 'a valid option is used');
  assert.equal(triage([row(0, 'a', 'h'), row(400, 'a', 'h')], { burstGap: NaN }).stats.bursts, 2, 'an invalid option keeps the default');
  assert.equal(triage([row(0, 'a', 'h'), row(400, 'a', 'h')], null).stats.bursts, 2);
  assert.equal(triage([row(0, 'a', 'h'), row(400, 'a', 'h')], { burstGap: 0 }).stats.bursts, 2, 'zero is a valid option');
  assert.equal(triage([row(5, 'b', 'h'), row(5, 'a', 'h'), { junk: 1 }]).stats.skipped, 1);
  assert.deepEqual(DEFAULTS, { burstGap: 300, incidentGap: 1800, backgroundShare: 0.25, backgroundMinHours: 24 });
  assert.ok(Object.isFrozen(DEFAULTS));
  const big = []; for (let i = 0; i < 200000; i++) big.push(row(i, 'flood', 'h', 1)); for (let h = 0; h < 60; h++) big.push(row(h * 3600, 'noise' + (h % 2), 'h2'));
  assert.equal(triage(big).ok, true, 'a large group does not overflow the stack');
});

test('options: zero is used, NaN and negatives keep the default', () => {
  const two = [row(0, 'a', 'h'), row(100, 'a', 'h')];
  assert.equal(triage(two).stats.bursts, 1, 'default gap 300 merges 100 s apart');
  assert.equal(triage(two, { burstGap: 0 }).stats.bursts, 2, 'a zero gap is honoured');
  assert.equal(triage(two, { burstGap: NaN }).stats.bursts, 1, 'NaN keeps the default');
  assert.equal(triage(two, { burstGap: '0' }).stats.bursts, 1, 'a string keeps the default');
  const apart = [row(0, 'a', 'h'), row(1000, 'b', 'h')];
  assert.equal(triage(apart, { backgroundShare: 2 }).stats.groups, 1, 'default incident gap links 1000 s apart');
  assert.equal(triage(apart, { backgroundShare: 2, incidentGap: -1 }).stats.groups, 1, 'a negative gap keeps the default');
  assert.equal(triage(apart, { backgroundShare: 2, incidentGap: 999 }).stats.groups, 2);
  assert.equal(triage(apart, { backgroundShare: 2, incidentGap: Infinity }).stats.groups, 1, 'Infinity keeps the default');
});

test('normalise: the edges of each format', () => {
  assert.equal(normalise({ '@timestamp': 100, agent: {}, rule: { description: 'Only a description' } }).rule, 'wazuh:Only a description');
  assert.equal(normalise({ '@timestamp': 100, agent: {}, rule: { level: 3 } }), null, 'a rule block with no id or description is not an alert');
  assert.equal(normalise({ '@timestamp': 100, agent: {}, rule: null }), null);
  assert.equal(normalise({ '@timestamp': 100, event: { severity: 3 }, rule: { id: 'X' } }).from, 'ecs', 'a rule block without an agent is not Wazuh');
  assert.equal(normalise({ event_type: 'alert', timestamp: 100, alert: 'x' }).rule, 'row:x', 'an alert field that is not an object is not Suricata');
  assert.equal(normalise({ event_type: 'dns', timestamp: 100, alert: { signature: 'S' } }), null, 'another event type is not a Suricata alert');
  assert.equal(normalise({ '@timestamp': 100, host: { name: 'h' }, rule: { name: 'R' } }).from, 'ecs', 'host alone marks ECS');
  assert.equal(normalise({ '@timestamp': 100, source: { ip: '1.1.1.1' }, rule: { id: 'R' } }).from, 'ecs', 'source alone marks ECS');
  assert.equal(normalise({ t: 1, rule: 'r', host: NaN }).host, '');
  assert.equal(normalise({ t: 1, rule: 'r', host: Infinity, src: 42 }).host, '');
  assert.equal(normalise({ t: 1, rule: 'r', src: 42 }).src, '42', 'a finite number reads as text');
  assert.equal(normalise({ '@timestamp': 100, agent: { ip: '1.1.1.1' }, rule: { id: 86601, description: 'Suricata: Alert' }, data: { alert: { signature: 'no id' } } }).from, 'wazuh', 'Suricata needs a signature id');
});
