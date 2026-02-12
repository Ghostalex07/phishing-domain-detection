
import csv
from itertools import combinations
import Levenshtein

input_file = "../data/domains_clean.csv"
output_file = "../data/similar_pairs.csv"
SIMILARITY_THRESHOLD = 0.8 

names = []
with open(input_file, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        names.append(row["name"])

print(f"{len(names)} names loaded")

similar_pairs = []

for name1, name2 in combinations(names, 2):
    score = Levenshtein.ratio(name1, name2) 
    if score >= SIMILARITY_THRESHOLD:
        similar_pairs.append((name1, name2, round(score, 2)))

print(f"{len(similar_pairs)} similar pairs found")


with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["name1", "name2", "similarity"])
    for pair in similar_pairs:
        writer.writerow(pair)

print(f"Similar pairs written to {output_file}")

