# SAPP as a Mistral internal app — plan and non-redundancy check

(2026-11-20. Security review results and the issues/PRs are in PROVENANCE.md; this file is
the deployment/integration plan.)

## Verdict: not redundant with Chonkcave or Linear

Checked against the live Chonkcave MCP and Linear connectors (2026-11-20):

| system | role today | overlap with SAPP |
|---|---|---|
| **Chonkcave** (`chonkcave-web.cheetah-koi.ts.net`) | internal vulnerability **triage inbox / arsenal**: program → components → gadgets (findings) → reports (severity, CVSS, CWE, status, comments, links). One program exists: `mistral / harmattan` (`a3ddb0ed-…`), fed by project 01's Pysa zdr-guard; reports record the Pysa finding hash as text — no traces, no runs, no raw reports. Review prompts are manual playbooks (closest: `untrusted-input-dataflow`). No SAPP/SARIF/Mariana/code-scanning ingest anywhere | stores finding IDs + triage — SAPP does not replace it, and must not become a second triage inbox |
| **Linear** | **action/ownership tracker**: RUN-2766…2816 (Pysa ZDR findings, team Runtime, Chonkcave report URLs attached), MOB-2435/2521/2524 (mobile security, label `Security and Compliance`), `Sisyphe` label for dependency CVEs, GIT-1225 for Wiz SAST triage. No SAPP/MT/SARIF project or issue | tickets are the system of action — SAPP files none |
| **SAPP** (this repo) | **analysis-side exploration layer**: per-run SQLite DB, issues deduplicated across runs by handle, `is_new_issue` diffing, frame-by-frame trace UI/CLI, structured filters, SARIF export | unique: trace-level exploration + run-over-run diffing + the SARIF bridge to GitHub code scanning (nothing at Mistral turns Mariana/Pysa output into code-scanning alerts today; Sisyphe covers dependencies only) |

## Target architecture (extends the project 01 pattern to project 30)

```
Mariana Trench / Pysa run (Buildkite, per release APK or per PR)
  → raw report dir (model@*.json + metadata.json)
  → SAPP: `scripts/sapp/inspect.sh <report> --db _work/sapp/<target>.db`   (one run per invocation)
  → exploration: `serve.sh` (web UI, localhost) / `explore` CLI / `filter` (headless, new_issues, first_party)
  → SARIF: `sapp filter issues <run> scripts/sapp/filters/new_issues.json --output-format sarif`
       → upload to GitHub code scanning on `dashboard`   (the missing ingestion point)
  → triage of record: Chonkcave program per target (e.g. "mistral / le-chat-android",
       mirroring "mistral / harmattan"), gadget/report per surviving finding, with the
       SAPP issue handle + run id in the details (same as the Pysa hash today)
  → action: Linear issue (MOB-…, label Security and Compliance) with the Chonkcave
       report URL attached — the RUN-2766…2816 pattern. Never file per-run SAPP instances.
```

Rules that keep it non-redundant: SAPP stores raw runs + traces only; Chonkcave stores
triaged findings of record; Linear stores actionable work. Baselines/accepted findings stay
SAPP-side as filters (`scripts/sapp/filters/`), not as Chonkcave entries.

## Deployment shape

- Default and recommended: **per-target local DBs** (`_work/sapp/*.db`, shareable as files),
  server on `localhost:13337`. No shared server needed for triage sessions.
- If a shared instance is ever wanted: `SAPP_SERVER_HOST=0.0.0.0` **plus**
  `SAPP_AUTH_TOKEN=<random>` (bearer auth on every route, added 2026-11-20, PR #12) behind
  a reverse proxy that terminates TLS; never run `--debug` off-loopback (now refused,
  PR #12); source reads are confined to `--source-directory` (PR #11).
- CI ingestion: one Buildkite step per target running `inspect.sh` into a persistent DB
  volume; SARIF upload step from the same DB. Upstream's `sapp-action` GitHub Action can
  be used for the pysa variant on GitHub-hosted repos.

## Follow-up integration script (small, not yet written)

`scripts/sapp/export_new_findings.sh <db> <run>`: runs the `new_issues`+`first_party`
filters, emits SARIF for code scanning, and for each new first-party issue creates a
Chonkcave report (`mcp_chonkcave.submit_report`, recording the SAPP handle/run) and a
Linear issue (`connector_linear.save_issue`, team Vibe Native - Mobile, label
Security and Compliance, Chonkcave URL attached). This is the only new glue needed —
the three systems already have the connectors.

## Ownership

- Mobile team: rule pack + MOB tickets. Security Engineering: the Chonkcave program and
  the SARIF/code-scanning wiring. SAPP itself: per-target DBs under `_work/sapp/`, run by
  whoever triages.
