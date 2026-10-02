from phishing_domain_detection import clustering, similarity

EDGES = [("a", "b", 0.9), ("b", "c", 0.9), ("x", "y", 0.9)]


def test_build_graph_is_undirected():
    graph = clustering.build_graph(EDGES)
    assert "b" in graph["a"]
    assert "a" in graph["b"]


def test_connected_components():
    components = clustering.connected_components(clustering.build_graph(EDGES))
    sizes = sorted(len(component) for component in components)
    assert sizes == [2, 3]


def test_loops_do_not_break_clustering():
    graph = clustering.build_graph([("a", "a", 1.0)])
    assert clustering.connected_components(graph) == [{"a"}]


def test_no_edges_gives_no_clusters():
    assert clustering.connected_components(clustering.build_graph([])) == []


def test_clusters_join_chains_not_just_direct_edges():
    """a-b and b-c must land in one cluster even though a-c was never compared."""
    clusters = clustering.connected_components(clustering.build_graph(EDGES))
    assert {"a", "b", "c"} in clusters


def test_write_clusters_numbers_lines_from_one_and_sorts_members(tmp_path):
    path = tmp_path / "clusters.txt"
    clustering.write_clusters(path, [{"c", "a", "b"}])
    assert path.read_text(encoding="utf-8") == "Cluster 1: a, b, c\n"


def test_write_and_parse_clusters_round_trip(tmp_path):
    path = tmp_path / "clusters.txt"
    clusters = [{"c", "a"}, {"x"}, {"p", "q", "r"}]
    clustering.write_clusters(path, clusters)
    assert clustering.parse_clusters(path) == [["a", "c"], ["x"], ["p", "q", "r"]]


def test_parse_clusters_skips_lines_it_does_not_understand(tmp_path):
    path = tmp_path / "clusters.txt"
    path.write_text("garbage\n\nCluster 1: a, b\nnot a cluster\n", encoding="utf-8")
    assert clustering.parse_clusters(path) == [["a", "b"]]


def test_parse_clusters_handles_single_member_clusters(tmp_path):
    path = tmp_path / "clusters.txt"
    path.write_text("Cluster 1: solo\n", encoding="utf-8")
    assert clustering.parse_clusters(path) == [["solo"]]


def test_main_succeeds(tmp_path):
    similarity.save_pairs(tmp_path / "similar_pairs.csv", EDGES)
    assert clustering.main(["--data-dir", str(tmp_path)]) == 0
    assert clustering.parse_clusters(tmp_path / "clusters.txt") == [
        ["a", "b", "c"],
        ["x", "y"],
    ]


def test_main_reports_a_missing_input(tmp_path):
    assert clustering.main(["--data-dir", str(tmp_path)]) == 1


def test_main_reports_a_truncated_pairs_file(tmp_path, capsys):
    (tmp_path / "similar_pairs.csv").write_text("name1,name2\na,b\n", encoding="utf-8")
    assert clustering.main(["--data-dir", str(tmp_path)]) == 1
    assert "missing CSV column" in capsys.readouterr().err


def test_main_reports_a_non_numeric_score(tmp_path, capsys):
    (tmp_path / "similar_pairs.csv").write_text(
        "name1,name2,similarity\na,b,very\n", encoding="utf-8"
    )
    assert clustering.main(["--data-dir", str(tmp_path)]) == 1
    assert "bad similarity" in capsys.readouterr().err
