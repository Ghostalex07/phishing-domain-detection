
import csv

clusters_file = "../data/clusters.txt"
domains_clean_file = "../data/domains_clean.csv"
output_file = "../data/base_domains.csv"

domain_freq = {}
with open(domains_clean_file, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        name = row["name"]
        domain = row["domain"]
        count = int(row["count"])
        domain_freq[name] = count

clusters = []
with open(clusters_file, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            parts = line.strip().split(": ", 1)
            if len(parts) == 2:
                members = [m.strip() for m in parts[1].split(",")]
                clusters.append(members)

output_data = []
for idx, members in enumerate(clusters, 1):
    members_sorted = sorted(members, key=lambda x: (len(x), -domain_freq.get(x, 0)))
    base_domain = members_sorted[0]
    output_data.append((idx, base_domain, "|".join(members)))

with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["cluster_id", "base_domain", "members"])
    for row in output_data:
        writer.writerow(row)

print(f"{len(output_data)} base domains written to {output_file}")
