from phishing_domain_detection.clustering import build_graph, connected_components

EDGES = [("a", "b", 0.9), ("b", "c", 0.9), ("x", "y", 0.9)]


def test_build_graph_is_undirected():
    graph = build_graph(EDGES)
    assert "b" in graph["a"]
    assert "a" in graph["b"]


def test_connected_components():
    components = connected_components(build_graph(EDGES))
    sizes = sorted(len(component) for component in components)
    assert sizes == [2, 3]


def test_loops_do_not_break_clustering():
    graph = build_graph([("a", "a", 1.0)])
    assert connected_components(graph) == [{"a"}]