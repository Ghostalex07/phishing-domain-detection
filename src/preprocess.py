
import csv

input_file = "../data/domains_raw.txt"
output_file = "../data/domains_clean.csv"

domain_counts = {}

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        domain = line.strip().lower()
        if not domain:
            continue
        parts = domain.split(".")
        if len(parts) < 2:
            continue

        name = parts[0]

        if name not in domain_counts:
            domain_counts[name] = {
                "domain": domain,
                "count": 0
            }

        domain_counts[name]["count"] += 1

with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["name", "domain", "count"])

    for name, data in sorted(domain_counts.items()):
        writer.writerow([name, data["domain"], data["count"]])

print(f"{len(domain_counts)} unique domain names written")

