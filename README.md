<div align="center">

# 🛡️ Similarity-Based Phishing Domain Detection

**A modular Python pipeline that flags typosquatting domains from Certificate Transparency logs.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/github/actions/workflow/status/Ghostalex07/phishing-domain-detection/ci.yml?style=flat-square)](https://github.com/Ghostalex07/phishing-domain-detection/actions)

</div>

---

## 📌 Overview

Phishing campaigns frequently rely on **typosquatting** — registering lookalike domains such as `googIe.com` instead of `google.com`. This project shows how a small set of lightweight signals can surface these threats from **public Certificate Transparency (CT) logs**:

1. **Extract** registrable domains from raw `crt.sh` JSON dumps.
2. **Preprocess** the domains into normalized, countable "names".
3. **Score** every pair of names with a **normalized edit-distance** ratio.
4. **Cluster** similar names with graph **connected components**.
5. **Select** the most likely legitimate "base domain" per cluster.
6. **Monitor** lists of new registrations and flag high-similarity matches.

It is designed to be *explainable*: every suspicion is backed by a concrete base domain and a similarity score, not an opaque black box.

---

## 🚀 Quickstart

```bash
# 1. Clone the repository
git clone https://github.com/Ghostalex07/phishing-domain-detection
cd phishing-domain-detection

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate

# 3. Install the package with dev dependencies
make install-dev          # or: pip install -e ".[dev]"

# 4. Run the complete pipeline (extraction -> suspects report)
make pipeline             # or: phishing-pipeline
```

The pipeline reads from and writes to `data/`, producing everything from
`domains_raw.txt` up to the final `suspect_domains.csv` report.

---

## 🧭 Usage

Every step ships as its own CLI tool (and as a console script once installed).
Run any of them with `--help` for the full list of options.

| Command | What it does | Default input | Default output |
| :--- | :--- | :--- | :--- |
| `phishing-extract` | Parse a crt.sh JSON dump into unique domains | `crtsh_raw.json` | `domains_raw.txt` |
| `phishing-preprocess` | Normalize domains and count primary labels | `domains_raw.txt` | `domains_clean.csv` |
| `phishing-similarity` | Find pairs above a name-similarity threshold | `domains_clean.csv` | `similar_pairs.csv` |
| `phishing-cluster` | Group pairs into clusters (connected components) | `similar_pairs.csv` | `clusters.txt` |
| `phishing-base` | Pick a representative base domain per cluster | `clusters.txt` + `domains_clean.csv` | `base_domains.csv` |
| `phishing-detect` | Flag new registrations that resemble a base | `base_domains.csv` + `new_domains.txt` | `suspect_domains.csv` |
| `phishing-pipeline` | Execute all the steps above in one shot | — | — |

Example — a single step with a custom threshold and output path:

```bash
phishing-similarity --threshold 0.85 --output /tmp/pairs.csv
```

All tools accept `--data-dir <path>` to point at a different dataset directory and
`-v` for debug logging.

### Tuning the thresholds

- `--pair-threshold` (default `0.8`) controls how strictly names are paired during clustering.
- `--detect-threshold` (default `0.75`) controls how strictly a new domain must resemble a base to be flagged.

Lower thresholds capture more candidates (with more false positives); higher thresholds are stricter.

---

## 📊 Example Results

The system cleanly surfaces common typosquatting patterns from a small list of
new registrations:

| New Domain | Matched Base | Similarity |
| :--- | :--- | :--- |
| `absbok.com` | `absbook` | **0.92** |
| `addax-tactical.net` | `addaxtactical` | **0.96** |
| `ramarketing-secure.org` | `ramarketing` | **0.76** |
| `ad-digital-login.com` | `ad-digital` | **0.77** |

---

## 📂 Repository Structure

```text
phishing-domain-detection/
├── .github/workflows/       # CI: lint, typecheck, unit tests, full pipeline
├── data/                    # Input CT logs and every intermediate/result file
├── docs/                    # Project documentation (PDF thesis, etc.)
├── src/phishing_domain_detection/
│   ├── cli.py               # Shared CLI helpers (logging, data dir, paths)
│   ├── hostname.py          # Host normalization and registrable-domain logic
│   ├── extract_domains.py   # Step 1: crt.sh JSON -> domains
│   ├── preprocess.py        # Step 2: domains -> normalized names
│   ├── similarity.py        # Step 3: batched pairwise name scoring
│   ├── clustering.py        # Step 4: connected-component clustering
│   ├── base_domain.py       # Step 5: representative domain per cluster
│   ├── detect_new.py        # Step 6: flag lookalike new domains
│   ├── pipeline.py          # Orchestrator running steps 1-6
│   └── __main__.py          # `python -m phishing_domain_detection`
├── tests/                   # Unit tests (pytest)
├── Makefile                 # Convenience targets (install, test, pipeline)
├── pyproject.toml           # Packaging, dependencies & console scripts
└── requirements.txt         # Runtime dependencies (mirrors pyproject)
```

---

## 🧪 Testing

```bash
make test          # or: python -m pytest
```

The suite (664 tests) covers every stage — extraction, counting, similarity,
clustering, base selection, detection and the end-to-end pipeline — with small
synthetic inputs, so no network access or large dataset is required. The
similarity tests check the batched scorer against a brute-force reference
implementation, which is what keeps the blocking optimisation honest.

---

## 🛠️ Tech Stack

* **Python 3.10+**
* **rapidfuzz** — `Indel` similarity plus `process.cdist` for vectorised scoring
* **numpy** — score matrices, processed in fixed-size bands
* **Graph theory (BFS / connected components)** — cluster formation
* **Plain JSON/CSV** — no database or server required

---

## ⚡ Performance

Step 3 is the only quadratic stage, so it gets the attention. The 4.5M pairs in
the bundled dataset are scored in batches of 256 rows with `process.cdist`,
which avoids materialising the full matrix:

| Implementation | Time on 4.5M pairs |
| :--- | :--- |
| One pair at a time | ~3.6 s |
| Batched `process.cdist` | ~0.14 s |

The whole pipeline runs end to end in **~0.15 s** on the bundled dataset.

---

## 🔐 Input Handling

Every input this tool touches is untrusted: the CT dump is scraped from a third
party, and the intermediate CSVs are ordinary inputs to the next stage, so a
hand-edited or synced file is untrusted too. Two rules hold throughout:

- **Readers validate.** Full hostnames go through `hostname.normalize`, single
  labels through `hostname.normalize_label`, and a bad cell is a hard error
  rather than a skipped row. That is what stops a formula-shaped domain in
  `base_domains.csv` from being carried into the report.
- **Writers escape.** All six outputs additionally run `hostname.safe_cell`, so
  no cell can start with `=`, `+`, `-` or `@` — the prefixes a spreadsheet would
  evaluate as a formula — and no cell can inject a new record into
  `clusters.txt` with an embedded newline.

Step 3 also refuses to hold more than `MAX_PAIRS` (1M) pairs and fails loudly if
it would. The work is quadratic by nature, and an attacker registering typo
variants against one brand controls exactly that.

---

## ⚠️ Limitations & Next Steps

* Step 3 is still **O(n²)** in the number of names. Batching made it ~28x
  faster, but the asymptotics are unchanged; corpora in the millions would need
  real blocking (LSH, prefix indexing) rather than wider score matrices.
* Registrable domains use a small built-in list of multi-label public suffixes
  (`com.au`, `co.uk`, `com.cn`, …). Exotic suffixes are not covered and fall
  back to last-two-labels; `tldextract` with the full Public Suffix List would
  be more complete at the cost of a runtime dependency.
* Base selection takes the **shortest** cluster member, which assumes the
  legitimate domain is the shortest one. A cluster of all-squatted domains would
  pick an arbitrary representative.
* Substring matches bypass the similarity threshold by design, so
  `suspect_domains.csv` can contain rows whose score is below `--detect-threshold`.
  Filter on the score, not just on the presence of a row.
* Thresholds are best tuned against a labeled dataset of real phishing and
  benign domains.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.