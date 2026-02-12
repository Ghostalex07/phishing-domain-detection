
import json
import re

input_file = "../data/crtsh_raw.json"
output_file = "../data/domains_raw.txt"

domains = set()

with open(input_file, "r", encoding="utf-8") as f:
    data = json.load(f)

for entry in data:
    if "name_value" not in entry:
        continue

    values = entry["name_value"].split("\n")

    for v in values:
        v = v.strip().lower()
        if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", v):
            parts = v.split(".")
            if len(parts) >= 2:
                domain = parts[-2] + "." + parts[-1]
                domains.add(domain)

with open(output_file, "w") as f:
    for d in sorted(domains):
        f.write(d + "\n")

print(f"{len(domains)} domains extracted")

