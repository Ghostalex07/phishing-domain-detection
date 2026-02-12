
import csv
from collections import defaultdict, deque

input_file = "../data/similar_pairs.csv"
output_file = "../data/clusters.txt"

graph = defaultdict(set)

with open(input_file, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        name1 = row["name1"]
        name2 = row["name2"]
        graph[name1].add(name2)
        graph[name2].add(name1)

print(f"{len(graph)} nodes in graph")

visited = set()
clusters = []

def bfs(start):
    cluster = set()
    queue = deque([start])
    visited.add(start)
    while queue:
        node = queue.popleft()
        cluster.add(node)
        for neighbor in graph[node]:
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return cluster

for node in graph:
    if node not in visited:
        cluster = bfs(node)
        clusters.append(cluster)

print(f"{len(clusters)} clusters found")

with open(output_file, "w", encoding="utf-8") as f:
    for i, cluster in enumerate(clusters, 1):
        f.write(f"Cluster {i}: {', '.join(sorted(cluster))}\n")

print(f"Clusters written to {output_file}")

