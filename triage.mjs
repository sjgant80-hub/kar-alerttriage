// kar-alerttriage · triage.mjs — a flood of SIEM / EDR / IDS alerts in, a short ranked list of incidents out.
// Deterministic and explainable: no AI model judges anything. The same alerts and options always give the same list,
// and every incident carries the rules that formed it and the arithmetic of its score. Pure; garbage never throws.
//
//   1. normalise   Wazuh (incl. Suricata via Wazuh), raw Suricata eve.json, Elastic/ECS, or flat CSV rows → one shape
//   2. bursts      repeats of the same rule on the same host and addresses, within burstGap seconds, become one burst
//   3. background  a rule that fires in at least backgroundShare of the export's hours is routine noise: it is set aside
//                  in one group per rule, never linked into an incident
//   4. incidents   the remaining bursts link when they share a host or an address within incidentGap seconds
//   5. score       each group: the sum, over its distinct rules, of rarity × (1 + severity), where
//                  rarity = ln(all bursts / bursts of that rule) and severity = level / 15 (Wazuh's 0–15 scale)

// backgroundMinHours: "fires in a quarter of the hours" only means routine over a long enough export; on a short one
// (a few hours of an attack) every rule would qualify, so below this span nothing is set aside and rarity alone ranks.
export const DEFAULTS = Object.freeze({ burstGap: 300, incidentGap: 1800, backgroundShare: 0.25, backgroundMinHours: 24 });
const MAX_LEVEL = 15;

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const str = (x) => (typeof x === 'string' ? x.trim() : typeof x === 'number' && Number.isFinite(x) ? String(x) : '');
const num = (x) => { const n = typeof x === 'number' ? x : typeof x === 'string' && x.trim() !== '' ? Number(x) : NaN; return Number.isFinite(n) ? n : NaN; };
const clampLevel = (l) => (Number.isFinite(l) ? Math.min(MAX_LEVEL, Math.max(0, l)) : 0);
const pick = (o, path) => { let v = o; for (const k of path) { if (!isObj(v)) return undefined; v = v[k]; } return v; };
const first = (...xs) => { for (const x of xs) { const s = str(x); if (s !== '') return s; } return ''; };

// time(x) → seconds since the epoch, from an ISO string or epoch seconds / milliseconds; NaN if it is neither
export function time(x) {
  if (typeof x === 'number' && Number.isFinite(x)) return x > 1e12 ? x / 1000 : x;
  if (typeof x !== 'string' || x.trim() === '') return NaN;
  if (/^\d+(\.\d+)?$/.test(x.trim())) return time(Number(x));
  const t = Date.parse(x.replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
  return Number.isFinite(t) ? t / 1000 : NaN;
}

// normalise(raw) → { t, rule, name, level, host, src, dst, from } or null when it is not an alert we can place in time
export function normalise(raw) {
  const n = shape(raw);
  if (n !== null) n.mark = isObj(raw) ? str(raw.mark) : '';
  return n;
}

// an optional caller-supplied mark on an alert (an analyst's label, a known incident id) is carried through and counted
// per group; the ranking never reads it
function shape(raw) {
  if (!isObj(raw)) return null;
  // already in this shape (for example normalised while streaming a large export): checked, not trusted
  if (typeof raw.t === 'number' && Number.isFinite(raw.t) && typeof raw.rule === 'string' && raw.rule !== '') {
    return { t: raw.t, from: first(raw.from, 'given'), rule: raw.rule, name: first(raw.name, raw.rule), level: clampLevel(num(raw.level)), host: str(raw.host), src: str(raw.src), dst: str(raw.dst) };
  }
  const sig = pick(raw, ['data', 'alert']) || pick(raw, ['alert']);
  // Wazuh (its rule block), including Suricata alerts that Wazuh forwards (rule 86601 + data.alert)
  const wr = isObj(raw.rule) ? raw.rule : null;
  if (wr !== null && raw.agent !== undefined && (wr.id !== undefined || wr.description !== undefined)) {
    const viaSuricata = isObj(sig) && sig.signature_id !== undefined;
    const t = time(raw['@timestamp'] !== undefined ? raw['@timestamp'] : raw.timestamp);
    if (!Number.isFinite(t)) return null;
    return {
      t, from: viaSuricata ? 'suricata' : 'wazuh',
      rule: viaSuricata ? 'suricata:' + str(sig.signature_id) : 'wazuh:' + first(raw.rule.id, raw.rule.description),
      name: first(viaSuricata ? sig.signature : '', raw.rule.description, raw.rule.id),
      level: clampLevel(num(raw.rule.level)),
      host: first(pick(raw, ['agent', 'ip']), pick(raw, ['agent', 'name']), pick(raw, ['predecoder', 'hostname'])),
      src: first(pick(raw, ['data', 'srcip']), pick(raw, ['data', 'src_ip'])),
      dst: first(pick(raw, ['data', 'dstip']), pick(raw, ['data', 'dest_ip'])),
    };
  }
  // raw Suricata eve.json alert (severity 1 is the most severe, 3 the least)
  if (raw.event_type === 'alert' && isObj(raw.alert)) {
    const t = time(raw.timestamp);
    if (!Number.isFinite(t)) return null;
    const sev = num(raw.alert.severity);
    return {
      t, from: 'suricata', rule: 'suricata:' + first(raw.alert.signature_id, raw.alert.signature), name: first(raw.alert.signature, raw.alert.signature_id),
      level: Number.isFinite(sev) ? clampLevel((4 - sev) * 4) : 0, host: first(raw.host, raw.in_iface), src: str(raw.src_ip), dst: str(raw.dest_ip),
    };
  }
  // Elastic Common Schema (event.severity, rule.*, host.*, source.ip, destination.ip)
  if (isObj(raw.event) || isObj(raw.host) || isObj(raw.source)) {
    const t = time(raw['@timestamp']);
    const rule = first(pick(raw, ['rule', 'id']), pick(raw, ['rule', 'name']), pick(raw, ['event', 'code']), pick(raw, ['event', 'action']));
    if (!Number.isFinite(t) || rule === '') return null;
    const sev = num(pick(raw, ['event', 'severity']));
    return {
      t, from: 'ecs', rule: 'ecs:' + rule, name: first(pick(raw, ['rule', 'name']), pick(raw, ['message']), rule),
      level: Number.isFinite(sev) ? clampLevel(sev <= MAX_LEVEL ? sev : sev / 100 * MAX_LEVEL) : 0,
      host: first(pick(raw, ['host', 'name']), pick(raw, ['host', 'ip'])), src: str(pick(raw, ['source', 'ip'])), dst: str(pick(raw, ['destination', 'ip'])),
    };
  }
  // a flat row (CSV or a simple export): time, rule, severity, host, src, dst
  const t = time(raw.time !== undefined ? raw.time : raw.timestamp);
  const rule = first(raw.rule, raw.rule_id, raw.signature, raw.alert);
  if (!Number.isFinite(t) || rule === '') return null;
  return {
    t, from: 'row', rule: 'row:' + rule, name: first(raw.name, raw.description, raw.signature, rule),
    level: clampLevel(num(raw.level !== undefined ? raw.level : raw.severity)), host: first(raw.host, raw.hostname), src: first(raw.src, raw.src_ip, raw.source), dst: first(raw.dst, raw.dest_ip, raw.destination),
  };
}

// bursts(alerts, gap) → repeats of one rule on one host and address pair, each within gap seconds of the last, as one
function bursts(alerts, gap) {
  const open = new Map(), out = [];
  for (const a of alerts) {
    const key = a.rule + '|' + a.host + '|' + a.src + '|' + a.dst;
    const b = open.get(key);
    if (b !== undefined && a.t - b.last <= gap) {
      b.last = a.t; b.count = b.count + 1;
      b.level = Math.max(b.level, a.level);
      if (a.mark !== '') b.marks.set(a.mark, (b.marks.get(a.mark) || 0) + 1);
      continue;
    }
    const nb = { key, rule: a.rule, name: a.name, level: a.level, host: a.host, src: a.src, dst: a.dst, first: a.t, last: a.t, count: 1, marks: new Map() };
    if (a.mark !== '') nb.marks.set(a.mark, 1);
    open.set(key, nb);
    out.push(nb);
  }
  return out;
}

// union-find over burst indexes
function sets(n) {
  const p = Array.from({ length: n }, (_, i) => i);
  const find = (i) => { while (p[i] !== i) { p[i] = p[p[i]]; i = p[i]; } return i; };
  const join = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) p[Math.max(ra, rb)] = Math.min(ra, rb); };
  return { find, join };
}

// triage(rawAlerts, options) → { ok, groups, stats } or { ok: false, why }
export function triage(rawAlerts, options) {
  if (!Array.isArray(rawAlerts)) return { ok: false, why: 'give a list of alerts' };
  const o = { ...DEFAULTS };
  if (isObj(options)) for (const k of Object.keys(DEFAULTS)) { const v = options[k]; if (typeof v === 'number' && Number.isFinite(v) && v >= 0) o[k] = v; }
  // a stable sort by time: alerts at the same second keep the order they were given in, so the same input gives the same result
  const alerts = rawAlerts.map(normalise).filter((a) => a !== null).sort((a, b) => a.t - b.t);
  const skipped = rawAlerts.length - alerts.length;
  if (alerts.length === 0) return { ok: true, groups: [], stats: { alerts: 0, skipped, bursts: 0, groups: 0, background: 0, hours: 0 } };
  const bs = bursts(alerts, o.burstGap);

  // background: the share of the export's hours in which each rule fires
  const start = Math.floor(alerts[0].t / 3600), hours = Math.floor(alerts[alerts.length - 1].t / 3600) - start + 1;
  const ruleHours = new Map(), ruleBursts = new Map();
  for (const a of alerts) { const h = Math.floor(a.t / 3600); const s = ruleHours.get(a.rule) || new Set(); s.add(h); ruleHours.set(a.rule, s); }
  for (const b of bs) ruleBursts.set(b.rule, (ruleBursts.get(b.rule) || 0) + 1);
  const background = new Set();
  for (const [rule, hs] of ruleHours) if (hours >= o.backgroundMinHours && hs.size / hours >= o.backgroundShare) background.add(rule);
  const rarity = (rule) => Math.log(bs.length / ruleBursts.get(rule));

  // incidents: link non-background bursts that share a host or an address within incidentGap
  // per entity: the newest burst on it and the latest moment it was active (a long burst can outlast a newer one)
  const u = sets(bs.length), seen = new Map();
  bs.forEach((b, i) => {
    if (background.has(b.rule)) return;
    for (const e of [b.host === '' ? '' : 'h:' + b.host, b.src === '' ? '' : 'a:' + b.src, b.dst === '' ? '' : 'a:' + b.dst]) {
      if (e === '') continue;
      const prev = seen.get(e);
      const linked = prev !== undefined && b.first - prev.last <= o.incidentGap;
      if (linked) u.join(i, prev.idx);
      seen.set(e, { idx: i, last: linked ? Math.max(prev.last, b.last) : b.last });
    }
  });
  const byKey = new Map();
  bs.forEach((b, i) => {
    const k = background.has(b.rule) ? 'bg:' + b.rule : 'in:' + u.find(i);
    const g = byKey.get(k) || { kind: background.has(b.rule) ? 'background' : 'incident', bursts: [] };
    g.bursts.push(b);
    byKey.set(k, g);
  });

  const groups = [...byKey.values()].map((g) => {
    const rules = new Map();
    for (const b of g.bursts) {
      const r = rules.get(b.rule) || { rule: b.rule, name: b.name, level: 0, alerts: 0 };
      r.alerts = r.alerts + b.count;
      r.level = Math.max(r.level, b.level);
      rules.set(b.rule, r);
    }
    const why = [...rules.values()].map((r) => ({ ...r, rarity: rarity(r.rule), points: rarity(r.rule) * (1 + r.level / MAX_LEVEL) }))
      .sort((a, b) => b.points - a.points || a.rule.localeCompare(b.rule, 'en'));
    const set = (f) => [...new Set(g.bursts.map(f).filter((x) => x !== ''))].sort();
    const marks = {};
    for (const b of g.bursts) for (const [m, c] of b.marks) marks[m] = (marks[m] || 0) + c;
    // reduce, not Math.min(...list): a background group can hold hundreds of thousands of bursts
    return {
      kind: g.kind, score: why.reduce((s, r) => s + r.points, 0),
      first: g.bursts.reduce((m, b) => Math.min(m, b.first), Infinity), last: g.bursts.reduce((m, b) => Math.max(m, b.last), -Infinity),
      alerts: g.bursts.reduce((s, b) => s + b.count, 0), bursts: g.bursts.length, hosts: set((b) => b.host),
      addresses: [...new Set(set((b) => b.src).concat(set((b) => b.dst)))].sort(), rules: why, marks,
    };
  }).sort((a, b) => b.score - a.score || a.first - b.first);
  return { ok: true, groups, stats: { alerts: alerts.length, skipped, bursts: bs.length, groups: groups.length, background: background.size, hours } };
}

export default { DEFAULTS, time, normalise, triage };
