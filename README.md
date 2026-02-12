# 🛡️ Similarity-Based Phishing Domain Detection

A modular Python-based pipeline designed to identify potential phishing domains by analyzing **lexical similarity** and structural patterns in **Certificate Transparency (CT) logs**.

---

## 📌 Project Overview
Phishing attacks often rely on **typosquatting** (e.g., `googIe.com` instead of `google.com`). This project explores how simple yet effective similarity metrics can provide strong signals for detecting these threats by:
1. Extracting data from public CT logs (`crt.sh`).
2. Clustering domains using graph-based connected components.
3. Identifying "Base Domains" (legitimate targets).
4. Monitoring new registrations to flag high-similarity matches.

---

## 🎯 Objectives
* Extract and clean domain data from raw JSON Certificate Transparency records.
* Group lexically similar domains using the **Levenshtein Distance** algorithm.
* Implement a **Graph-based Clustering** approach to link related domain variants.
* Develop an explainable detection system for newly registered suspicious domains.

---

## 🧠 Technologies & Tools
* **Python 3.x**
* **Levenshtein**: For high-performance string similarity calculations.
* **Graph Theory**: Used for domain clustering (Connected Components).
* **JSON/CSV**: Standard formats for data extraction and reporting.

---

## 📊 Project Workflow
Run the scripts in the following order from the `src/` directory:

1.  **`extract_domains.py`**: Parses raw `crt.sh` JSON logs into a clean domain list.
2.  **`preprocess.py`**: Normalizes domains (lowercasing, stripping TLDs).
3.  **`similarity.py`**: Calculates similarity ratios between domain pairs.
4.  **`clustering.py`**: Groups similar domains into clusters using graph logic.
5.  **`base_domain.py`**: Identifies the representative "original" domain per group.
6.  **`detect_new.py`**: Compares new domain lists against identified bases to flag suspects.

---

## 📈 Example Results
The system effectively identifies common typosquatting patterns:

| New Domain | Matched Base | Similarity Score |
| :--- | :--- | :--- |
| `absbok.com` | `absbook` | **0.92** |
| `addax-tactical.net` | `addaxtactical` | **0.96** |
| `ramarketing-secure.org` | `ramarketing` | **0.76** |

---

## 📂 Repository Structure
```text
phishing-domain-detection/
├── data/               # Input JSON logs and output CSV results
├── src/                # Modular Python source code
├── requirements.txt    # Project dependencies
└── README.md           # Project documentation
