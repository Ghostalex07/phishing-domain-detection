# AGENTS.md

## Stack

- Python 3.10+, `src/` layout, setuptools, editable install
- `rapidfuzz` + `numpy` for similarity; stdlib `json`/`csv` for I/O
- pytest, ruff, mypy (strict over `src`), Makefile, GitHub Actions

## Commands

- `make install-dev` — editable install with dev extras
- `make test` — pytest
- `make lint` / `make format` — `ruff check` / `ruff check --fix`. There is no
  `ruff format` step and the repo is not format-enforced: do not reformat files
  wholesale, it buries the real change in noise.
- `make typecheck` — mypy over `src` only; `tests` are intentionally untyped
- `make pipeline` — full run against `data/`

`python` may not exist on the machine; the Makefile resolves `python3` through
`PYTHON ?=`. Call `python3` by hand.

## Conventions

- **One owner per file.** Each stage module owns both the reading and the
  writing of its format: `clustering.py` owns `clusters.txt`, `base_domain.py`
  owns `base_domains.csv`, `similarity.py` owns `similar_pairs.csv`. Never
  re-parse another stage's output with a private reader.
- **Errors are values, not tracebacks.** Modules raise `cli.PipelineError`;
  `cli.run_step` catches it, logs one line to stderr and returns exit code 1.
  Express new failure modes as `PipelineError`, never as a bare `except`.
  `run_step` also catches `OSError` and `csv.Error`; it deliberately does **not**
  catch `ValueError`, because a `ValueError` reaching it is a bug in this code
  that must stay visible. Malformed bytes are handled at the reader with
  `errors="replace"`, not by a blanket handler.
- **CSV is validated before use.** `cli.require_fields` checks headers; missing
  columns and unparsable numbers are `PipelineError`.
- **Untrusted input is validated on read, and escaped on write.** This is the
  security invariant, and it is enforced from both ends:
  - Every *reader* validates the strings it accepts — full hostnames through
    `hostname.normalize`, single labels through `hostname.normalize_label` — and
    raises `PipelineError` on a bad cell. A stage output is an ordinary input to
    the next stage, so a hand-edited or synced CSV is untrusted too. The only
    exception is `preprocess.count_labels`, which is the first stage to touch bulk
    scraped text: it skips and warns instead, because one bad line should not
    cost the analyst a whole run.
  - Every *writer* runs `hostname.safe_cell` on each string cell, so no future
    writer can forget and ship a live formula.

  Together these mean no output cell can start with `=`, `+`, `-` or `@`, and no
  input cell can inject an extra record into `clusters.txt` via a newline.
  `tests/conftest.py` sweeps all six outputs for this on every relevant test; if
  you add a seventh writer or a new input, extend the sweep or it will not hold.
- **Log untrusted text with `!r`.** Rejected input was rejected *because* it is not
  a valid domain, so it can contain newlines, ANSI escapes or megabytes of text.
  `preprocess.py` and `similarity.py` are the in-repo precedent; `detect_new`
  truncates to 80 characters as well.
- **The pipeline is untrusted-input-shaped and bounded.** Step 3 is O(n²); a
  few thousand mutually similar names produce millions of pairs, and an attacker
  registering typo variants against one brand controls that. `similarity.MAX_PAIRS`
  makes it fail loudly; never truncate silently, because an analyst acting on a
  truncated report is worse off than one whose run stopped.
- **Stages stay pure and deterministic.** The same input files must produce
  byte-identical outputs; `tests/test_pipeline.py` asserts this.
- Tests use `tmp_path` and small synthetic inputs — no network, no dependence on
  `data/`. Tests going through `main()` assert on `capsys`, because
  `config_logging(force=True)` replaces the handlers `caplog` needs; tests
  calling a helper directly assert on `caplog`.
- Keep the committed `data/` outputs current: rerun `make pipeline` after
  touching any stage.
- Dependency bounds are next-major (`numpy>=1.24,<3`), never the newest patch
  that supports 3.10, because the project supports 3.10+. The `pytest>=9.0.3`
  floor is a CVE fix, not a preference: GHSA-6w46-j5rx-g56g.
- Actions in CI are pinned to a commit SHA; `.github/dependabot.yml` is what
  keeps them patched. Do not "simplify" them back to `@v4`.