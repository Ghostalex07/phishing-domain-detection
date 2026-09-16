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
3. **Score** every pair of names with the **Levenshtein ratio**.
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
| `phishing-similarity` | Find pairs above a Levenshtein similarity threshold | `domains_clean.csv` | `similar_pairs.csv` |
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
├── .github/workflows/       # CI: unit tests + full pipeline on every push
├── data/                    # Input CT logs and every intermediate/result file
├── docs/                    # Project documentation (PDF thesis, etc.)
├── src/phishing_domain_detection/
│   ├── cli.py               # Shared CLI helpers (logging, data dir, paths)
│   ├── extract_domains.py   # Step 1: crt.sh JSON -> domains
│   ├── preprocess.py        # Step 2: domains -> normalized names
│   ├── similarity.py        # Step 3: Levenshtein pair scoring
│   ├── clustering.py        # Step 4: connected-component clustering
│   ├── base_domain.py       # Step 5: representative domain per cluster
│   ├── detect_new.py        # Step 6: flag lookalike new domains
│   └── pipeline.py          # Orchestrator running steps 1-6
├── tests/                   # Unit tests (pytest)
├── Makefile                 # Convenience targets (install, test, pipeline)
├── pyproject.toml           # Packaging & console scripts
└── requirements.txt         # Minimal runtime dependencies
```

---

## 🧪 Testing

```bash
make test          # or: python -m pytest
```

The test suite covers the pure logic of every stage (extraction, counting,
similarity, clustering, base selection and detection) with small synthetic
inputs — no network or large dataset required.

---

## 🛠️ Tech Stack

* **Python 3.10+**
* **python-Levenshtein** — fast C-implemented string similarity
* **Graph theory (BFS / connected components)** — cluster formation
* **Plain JSON/CSV** — no database or server required

---

## ⚠️ Limitations & Next Steps

* Pairwise similarity is **O(n²)** — fine for thousands of names, but larger
  corpora should use blocking (e.g. prefix grouping) or `rapidfuzz` /
  `networkx` graph utilities.
* The registrable-domain reduction is a naive *last-two-labels* heuristic; a
  proper public-suffix list (e.g. `tldextract`) would improve accuracy for
  country-code TLDs like `co.uk`.
* Detection thresholds are best tuned against a labeled dataset of real
  phishing and benign domains.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.