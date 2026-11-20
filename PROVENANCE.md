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
  `sapp/tests/cli_test.py::test_previous_input`); no code failure.
- Ingested our own Mariana Trench reports from `../_work/mariana/`: `out_native`
  (8 shards → run 1, 6 issues) and `out_2.19.1c` (53 shards → run 2, 104 issues) in ~7.5 s
  into one database `_work/sapp/native.db`; `update warning-codes` with `metadata.json`,
  `filter issues --output-format sarif`, `explore` (issues/trace), and the web server
  (`/` 200 + `/graphql` runs/issues/trace frames) all verified against it.
