# Provenance

This directory is a clone of `meta/sapp` ("SAPP — Static Analysis Post Processor",
github.com/meta/sapp, MIT license) at commit `4e22c5c` (2026-11-20, "Remove Pyre mode
headers"; 748 commits of upstream history, 2021-12 to 2026-11). `git remote -v` points at
the upstream URL; `git log` is the untouched upstream history.

SAPP is the post-processor for Meta's static taint analyzers: it ingests the raw JSON
reports of Pysa (`taint-output.json`), Mariana Trench (`model@*.json` shards + `metadata.json`)
and Prophecy into a SQLite database and serves them for triage through a web UI
(Flask + GraphQL + React, port 13337), an interactive CLI (`sapp explore`) and
filter/SARIF commands. That is exactly the "SAPP database for triage" that
`../report/projects/30_android_taint.md` refers to for the Mariana Trench runs produced by
`../scripts/mariana/run.sh`.

Everything after the upstream clone is a Mistral-side addition, all of it additive
(no upstream file is modified):

| addition | what it is |
|---|---|
| `PROVENANCE.md` | this file |
| `INTERNAL.md` | runbook: how we build, run and feed it internally |
| `sapp/ui/frontend/build/` | the compiled React web UI, vendored from the PyPI wheel `fb-sapp==0.5.9` (same version as `setup.py` here). The git repo does not ship the build; the wheel does (12 MB). Without it `sapp server` serves only the GraphQL API. Re-fetch with `../scripts/sapp/bootstrap.sh` |

Upstream also publishes `fb-sapp` on PyPI (`pip install fb-sapp`); we deliberately run the
source clone (editable install) so internal patches stay local and reviewable, the same
pattern as `../sledge`.

## Verification at this commit (2026-11-20, macOS arm64)

- `python -m unittest discover -s . -t . -p "*_test.py"` in the venv: **47 tests, 1 error**,
  and that error is environmental only (`os.mknod` is not permitted in this sandbox,
  `sapp/tests/cli_test.py::test_previous_input`); no code failure. Same result after the
  security PRs, with click 8.5.1.
- Ingested our own Mariana Trench reports from `../_work/mariana/`: `out_native`
  (8 shards → run 1, 6 issues) and `out_2.19.1c` (53 shards → run 2, 104 issues) in ~7.5 s
  into one database `_work/sapp/native.db`; `update warning-codes` with `metadata.json`,
  `filter issues --output-format sarif`, `explore` (issues/trace), and the web server
  (`/` 200 + `/graphql` runs/issues/trace frames) all verified against it.

## Security review (2026-11-20) and fixes

Sunfire Review depth scan of this repository (run folder `.sunfire/runs/20261120-170638-f3076b`,
report copied to `../audit/sapp_sunfire_20261120.md`): **2 high, 8 medium, 13 low**, plus a
dependency/CI/secrets pass (no secrets found in tree or 748-commit history). Filed as
issues #1–#10 on `github.com/mbouaziz/sapp` and fixed in merged PRs #11–#17:

- #6 (high, CWE-22) arbitrary file read via the GraphQL `file` query — absolute paths
  bypassed the `".."` check → `resolve()` + `relative_to()` containment (PR #11, verified:
  `/etc/passwd` and `../..` rejected, in-source files still served).
- #7 (high, CWE-306) no auth on the server incl. destructive mutations → optional
  `SAPP_AUTH_TOKEN` bearer auth, Host-header allowlist on loopback binds (anti DNS-rebinding),
  `SAPP_SERVER_HOST`, `nosniff` (PR #12, verified live: 401/200/403).
- #3 (low, CWE-489) `--debug` Werkzeug debugger → refused off-loopback, GraphiQL only in
  debug (PR #12).
- #8 (medium, CWE-1333) ReDoS via `matches` regexes → 512-char cap + 1 s SIGALRM budget
  (PR #13, verified: catastrophic pattern aborts at 1.0 s).
- #9 (medium, CWE-22) bundle `filename_glob` traversal → confined to the bundle dir
  (PR #14).
- #10 (medium, CWE-22) `explore` `list` traversal via report-controlled filename → refused
  outside the repository dir (PR #15).
- #1 (low, CWE-79) `/export_filter` served as text/html → `application/json` + nosniff;
  #2 (low, CWE-400) nine unbounded typeahead queries → capped at 10k rows; #4 (low, CWE-73)
  `sapp json` lookup-table paths → validated against the analysis output (PR #16).
- #5 (CI) actions SHA-pinned (was `facebook/pyrefly@main`, `checkout@v2`), `permissions:
  contents: read`, `npm ci`, dependabot.yml, `click>=8.3.3` (CVE-2026-7246), qs 6.17.1 /
  follow-redirects 1.16.3 re-lock, publish-pypi.sh guarded (PR #17). Issue #5 remains open
  only for the `.github/workflows/*.yml` patch, which needs a `workflow`-scoped token to
  push (`../scripts/sapp/ci-workflows.patch` in the workspace).
