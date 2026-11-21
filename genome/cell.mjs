// cell.mjs — AlertTriage's three answers for the birth check (seed.json, genome/).
//
// judge  AlertTriage's own run (triage.mjs). A claimed ranking for a list of alerts (each group's kind and the rules
//        that formed it, in rank order) is verified when the kernel, run on the same alerts and options, gives the
//        same groups in the same order; unverified when it does not. The birth check's cases are the kernel's own
//        background test: eight hours of a "noise" rule on the mail server and two rare rules on the web server.
//        The kernel ranks the rare incident first and sets the noise aside; a ranking that puts the noise first
//        (what counting alerts would do: 8 against 2) is unverified. Refused when the input is not alerts to triage,
//        or the claim is not a list of groups, each a kind and a list of rule ids.
// lane   alerts the kernel can triage: a list with at least one alert it can place in time. A request to block an
//        address or act on an incident is out of lane and goes to Kar: AlertTriage ranks, people respond.
import { triage } from '../triage.mjs';

const isObj = (v) => v !== null && typeof v === 'object';
const isGroup = (g) => isObj(g) && typeof g.kind === 'string' && Array.isArray(g.rules) && g.rules.every((r) => typeof r === 'string');
const shape = (groups) => JSON.stringify(groups.map((g) => [g.kind, g.rules.map((r) => (typeof r === 'string' ? r : r.rule)).sort()]));

export async function judge(input) {
  if (!(await inLane(input)) || !Array.isArray(input.ranking) || !input.ranking.every(isGroup)) return 'refused';
  return shape(triage(input.alerts, input.options).groups) === shape(input.ranking) ? 'verified' : 'unverified';
}

export async function inLane(input) {
  if (!isObj(input)) return false;
  const r = triage(input.alerts, input.options);
  return r.ok === true && r.stats.alerts > 0;
}

// health: AlertTriage cannot see its page's visitors or its callers from inside the repository, so it says so
export async function health() {
  return { used: null, dependedOn: null, lastEarned: null };
}
