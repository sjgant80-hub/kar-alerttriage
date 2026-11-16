# Kar AlertTriage

**Live: https://sjgant80-hub.github.io/kar-alerttriage/**

A flood of SIEM, EDR or IDS alerts in; a short ranked list of incidents out. It runs on your own machine, and no AI model judges anything. The same alerts always give the same list, and every incident carries the rules that formed it and the arithmetic of its score. Part of [Sovereign AI-Security](https://sjgant80-hub.github.io/sovereign-ai-security/). Built by Kar for [AI Native Solutions](https://www.ai-nativesolutions.com/).

```bash
node bin/triage.mjs alerts.json            # JSON lines or a JSON array (Wazuh, Suricata eve.json, Elastic/ECS)
node bin/triage.mjs alerts.csv --top 20    # CSV with time, rule, severity, host, src, dst
node bin/triage.mjs alerts.json --json     # the full result as JSON
```

## How it works

1. **Normalise** Wazuh (including Suricata alerts forwarded by Wazuh), raw Suricata, Elastic/ECS or CSV rows into one shape.
2. **Bursts**: repeats of one rule on one host and address pair, within 5 minutes, become one burst.
3. **Routine noise**: over an export of a day or more, a rule that fires in at least a quarter of the hours is set aside, one group per rule.
4. **Incidents**: the remaining bursts link when they share a host or an address within 30 minutes.
5. **Score**: the sum, over a group's distinct rules, of `ln(all bursts ÷ bursts of that rule) × (1 + level ÷ 15)`.

## Measured, with the failures

On the public [AIT Alert Data Set](https://zenodo.org/records/8263181) (CC BY 4.0), 2,600,263 Wazuh and Suricata alerts from eight runs of a multi-step attack:

- The method was developed on one scenario (russellmitchell), then committed before the other seven were run once: commits `5cc52e6` (pre-registration) and `b996c20` (test results).
- **The first group is an attack in all 8 scenarios**, against rank 2–4 for a severity-sorted queue.
- **The top 10 groups hold 81–100% of attack-time alerts**, against 7–10%.
- **It loses on "top 10 that are attack"** (10–20%, against 20–50%), because one attack becomes one incident.
- **It misses DNS exfiltration in every scenario** (whose traces in this data are mainly AMiner alerts, which v1 does not read), and the first network scans.

Labels are by time (an alert inside an attack window counts as attack-time). Every number is in `results/`, and CI re-derives all of them from the Zenodo download on every change.

```bash
node --test triage.test.mjs page-parity.test.mjs
node tools/inline.mjs --check
node tools/measure.mjs ait_ads.zip labels.csv russellmitchell fox harrison santos shaw wardbeck wheeler wilson
```

## Licence and credits

MIT, © Simon Gant. Measured on, and the demo excerpted unaltered from, the AIT Alert Data Set: Landauer, M., Skopik, F., Wurzenberger, M. (2024), "Introducing a New Alert Data Set for Multi-Step Attack Analysis," Proceedings of the 17th Cyber Security Experimentation and Test Workshop (CC BY 4.0).
