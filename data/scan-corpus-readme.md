# Inkog scan corpus — methodology

`scan-corpus.json` holds the rolling dataset behind [Inkog Labs](https://inkog.io/labs) and the [State of AI Agent Security 2026](https://inkog.io/report) live data. It is refreshed weekly by an automated routine.

## What's in the corpus

Each entry is a single Inkog scan against a public GitHub repository, producing:

- **timestamp** — ISO 8601 of when the scan ran
- **repo** — `org/name`
- **report_id** — public Inkog report URL ID for click-through (`https://app.inkog.io/report/{id}`)
- **findings_count** — total findings (filtered by `balanced` policy)
- **critical_count / high_count / medium_count / low_count** — by severity
- **governance_score** — 0-100 (Inkog's compliance readiness score)
- **risk_score** — 0-100
- **eu_ai_act_readiness** — `READY` / `PARTIAL` / `NOT_READY`
- **top_finding_categories** — up to 5 most common categories, ordered

The `aggregates` object at the top of the file is recomputed on every refresh.

## What's eligible to be in the corpus

Strict inclusion criteria — only repos that meet **all** of:

1. **Publicly available** on GitHub
2. **Deliberately scannable** — either:
   a. Designed as a vulnerability test target (e.g. `harishsg993010/DamnVulnerableLLMProject`, `ReversecLabs/damn-vulnerable-llm-agent`), OR
   b. A popular agent framework example/template repo where the maintainer publishes a security policy
3. **Agent-shaped code** — scanning the repo produces meaningful Inkog findings (not a Hello World)
4. **Not on the do-not-target list** — see internal `routines/research-do-not-target.yml`

We will never include:

- Private code
- Small personal / hobbyist projects (< 100 stars)
- Repos where the maintainer has asked us not to scan
- Anything that would feel like an ambush

## Refresh cadence

The corpus is refreshed by an automated routine that runs weekly. Each entry is a snapshot — historical entries are not deleted (the corpus is append-only) so the dataset preserves a time series.

If a target's situation changes (e.g. they ask us to stop), past entries for that repo are removed and the target is added to the do-not-target list.

## How to use this data

- Cite specific entries with `(corpus #{index}, scanned {date})`
- Don't aggregate across entries with different scan policies — all corpus entries use the `balanced` policy by default
- For the live "X% had vulnerabilities" stat: use the `aggregates` block, which is recomputed each refresh

## Reproducing a scan

Every entry includes a `report_id`. Visit `https://app.inkog.io/report/{report_id}` to see the same findings the corpus entry summarizes.

## Issues / corrections

Spot a problem with a corpus entry? Open an issue: <https://github.com/inkog-io/inkog/issues/new?labels=corpus>.
