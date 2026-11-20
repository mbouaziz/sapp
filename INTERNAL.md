# SAPP, internal runbook

Internal instance of meta/sapp for inspecting the static-analysis reports we create
(currently Mariana Trench output of the Le Chat Android app from project 30,
`../scripts/mariana/run.sh`; Pysa `taint-output.json` works the same way).

Layout:

```
lang/
├── sapp/                  this repo: upstream meta/sapp @ 4e22c5c + PROVENANCE.md + this file
│                              + vendored prebuilt web UI (sapp/ui/frontend/build)
├── scripts/sapp/          bootstrap.sh, inspect.sh, serve.sh, query.sh, filters/
└── _work/sapp-venv/       the Python 3.10 venv (editable install of sapp/)
    _work/sapp/*.db        SAPP databases, one per target (each `analyze` adds a run)
```

## 1. Bootstrap once

```bash
sh ../scripts/sapp/bootstrap.sh        # from this directory, or from anywhere
```

Creates `_work/sapp-venv` with `uv` (Python 3.10 — the pinned deps, `ipython<8.4` and
`graphene<3`, predate 3.11+; the system Python 3.15 will not do), installs
`requirements.txt` plus an editable install of this clone, and vendors the compiled
React UI from the `fb-sapp` PyPI wheel if `sapp/ui/frontend/build/index.html` is missing.
No upstream file is patched; everything runs as cloned.

## 2. Ingest a report, inspect it

```bash
# report = Mariana Trench output dir (model@*.json + metadata.json) or a pysa json file
sh scripts/sapp/inspect.sh _work/mariana/out_2.19.1c --db _work/sapp/lechat.db --source-dir <apk sources>
sh scripts/sapp/inspect.sh _work/mariana/out_2.19.1c --db _work/sapp/lechat.db --serve   # + web UI
```

`inspect.sh` runs, in order:

1. `sapp --database-name $DB --tool mariana-trench analyze <report> [--branch … --commit … --job-id …]`
   — adds one **run** to the DB (rerun on the same DB to diff runs: the UI's
   "new issues" filter shows instances whose issue handle was not present before).
2. `sapp … update warning-codes <report>/metadata.json` — imports the rule names/descriptions
   (needed for readable messages and SARIF).
3. prints run/issue counts.

Then inspect with any of:

| surface | command | notes |
|---|---|---|
| web UI | `sh scripts/sapp/serve.sh _work/sapp/lechat.db --source-dir <sources>` then http://localhost:13337 | lists runs → issues → traces, with source snippets; GraphiQL at `/graphql` |
| GraphQL API | `sh scripts/sapp/query.sh '{ runs { edges { node { run_id num_issues } } } }'` | POSTs to `/graphql` on port 13337 (or `--port`) |
| interactive CLI | `sapp --database-name $DB explore` | `issues`, `issue 1`, `trace`, `n`, `list` (source listing needs `--source-directory`) |
| headless list / SARIF | `sapp --database-name $DB filter issues <run_id> scripts/sapp/filters/all.json [--output-format sarif]` | filters importable: `sapp … filter import <file-or-dir>`; see `filters/new_issues.json` |
| lint | `sapp --database-name $DB lint <filenames…>` | DB models in lint-friendly format |

Useful one-liners:

```bash
V=_work/sapp-venv/bin/sapp; DB=_work/sapp/lechat.db
$V --database-name $DB filter issues 2 scripts/sapp/filters/new_issues.json          # issues new in run 2
$V --database-name $DB filter issues 2 scripts/sapp/filters/all.json --output-format sarif > run2.sarif
printf 'issues\nissue 3\ntrace\n' | $V --database-name $DB explore                    # non-interactive explore
```

## 3. Mapping to our existing triage

`../scripts/mariana/triage.py` remains the precision layer for PR comments (baseline
accepts, first-party scoping, Meta's filters). SAPP complements it as the persistent,
queryable record: every run is a row in `runs`, issues are deduplicated across runs by
handle, and traces are explorable frame by frame. `scripts/sapp/filters/` holds SAPP-side
filters (JSON, importable with `sapp filter import`); `all.json` matches every rule code
we use (1–6, 3001–3006), `new_issues.json` only issues new in the selected run.

## 4. Operations notes

- DB is SQLite: copy/share `_work/sapp/*.db` freely; `sapp --database-engine memory` exists for throwaway parses.
- Server: `SAPP_SERVER_PORT` (default 13337), host `localhost`; `--debug` adds CORS for a
  separately running React dev server on port 3000 (not needed here — we serve the vendored build).
- Big reports: the full APK run (53 shards, 105 instances) parses in ~7.5 s and the DB stays small.
- Tests: `cd sapp && ../_work/sapp-venv/bin/python -m unittest discover -s . -t . -p "*_test.py"`
  (47 tests; the single error is `os.mknod` being blocked in this sandbox, not a code failure).
