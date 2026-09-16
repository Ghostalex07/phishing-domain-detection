from phishing_domain_detection.base_domain import (
    parse_clusters,
    select_base_domain,
    select_base_domains,
)


def test_select_base_domain_prefers_shortest():
    assert select_base_domain(["foooooo", "foo"], {}) == "foo"


def test_select_base_domain_breaks_ties_by_frequency():
    frequency = {"foo": 1, "bar": 5}
    assert select_base_domain(["foo", "bar"], frequency) == "bar"


def test_select_base_domains_sorts_members():
    rows = select_base_domains([["b", "a"]], {})
    assert rows == [("b", ["a", "b"])]


def test_parse_clusters(tmp_path):
    path = tmp_path / "clusters.txt"
    path.write_text("Cluster 1: a, b\nCluster 2: c\n", encoding="utf-8")
    assert parse_clusters(path) == [["a", "b"], ["c"]]