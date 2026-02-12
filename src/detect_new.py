
import csv
import Levenshtein

BASE_DOMAINS_FILE = "../data/base_domains.csv"
NEW_DOMAINS_FILE = "../data/new_domains.txt"
OUTPUT_FILE = "../data/suspect_domains.csv"
LEV_THRESHOLD = 0.75  

base_domains = []
with open(BASE_DOMAINS_FILE, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        base_domains.append(row["base_domain"].strip().lower())

print(f"{len(base_domains)} base domains loaded")

new_domains = []
with open(NEW_DOMAINS_FILE, "r", encoding="utf-8") as f:
    for line in f:
        d = line.strip().lower()
        if not d:
            continue

        parts = d.split(".")
        if len(parts) < 2:
            continue

        name = ".".join(parts[:-1]) 
        new_domains.append((d, name))

print(f"{len(new_domains)} new domains loaded")

suspects = []

for full_domain, name in new_domains:
    for base in base_domains:
        lev_score = Levenshtein.ratio(name, base)

        if lev_score >= LEV_THRESHOLD or base in name:
            suspects.append(
                (full_domain, base, round(lev_score, 2))
            )

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["new_domain", "matched_base", "similarity"])
    for row in suspects:
        writer.writerow(row)

print(f"{len(suspects)} suspect domains written to {OUTPUT_FILE}")
