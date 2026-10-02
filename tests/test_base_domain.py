import pytest

from phishing_domain_detection import base_domain, clustering, preprocess
from phishing_domain_detection.cli import PipelineError


def test_select_base_domain_prefers_shortest():
    assert base_domain.select_base_domain(["foooooo", "foo"], {}) == "foo"


def test_select_base_domain_breaks_ties_by_frequency():
    frequency = {"foo": 1, "bar": 5}
    assert base_domain.select_base_domain(["foo", "bar"], frequency) == "bar"


def test_select_base_domains_sorts_members():
    rows = base_domain.select_base_domains([["bb", "a"]], {})
    assert rows == [("a", ["a", "bb"])]


def test_select_base_domain_ignores_input_order():
    """A tie must resolve the same way whatever order the members arrive in."""
    assert base_domain.select_base_domain(["b", "a"], {}) == base_domain.select_base_domain(
        ["a", "b"], {}
    )


def test_select_base_domain_handles_names_missing_from_the_counts():
    """An unseen member must not raise; it just has no frequency to compare."""
    assert base_domain.select_base_domain(["aaa", "bb"], {"bb": 1}) == "bb"


def test_parse_clusters_lives_with_the_writer(tmp_path):
    """clusters.txt has a single owner: the module that writes it."""
    path = tmp_path / "clusters.txt"
    clustering.write_clusters(path, [{"b", "a"}])
    assert clustering.parse_clusters(path) == [["a", "b"]]


def test_save_base_domains_round_trips(tmp_path):
    path = tmp_path / "base_domains.csv"
    rows = [("a", ["a", "bb"]), ("solo", ["solo"])]
    base_domain.save_base_domains(path, rows)
    assert path.read_text(encoding="utf-8") == (
        "cluster_id,base_domain,members\n1,a,a|bb\n2,solo,solo\n"
    )
    assert base_domain.load_base_domains(path) == ["a", "solo"]


def test_load_base_domains_lowercases_and_trims(tmp_path):
    path = tmp_path / "base_domains.csv"
    path.write_text("cluster_id,base_domain,members\n1, AbsBook ,absbook\n", encoding="utf-8")
    assert base_domain.load_base_domains(path) == ["absbook"]


def test_load_base_domains_rejects_a_missing_column(tmp_path):
    path = tmp_path / "base_domains.csv"
    path.write_text("cluster_id,members\n1,a|b\n", encoding="utf-8")
    with pytest.raises(PipelineError, match="base_domain"):
        base_domain.load_base_domains(path)


def test_main_succeeds(tmp_path):
    clustering.write_clusters(tmp_path / "clusters.txt", [{"foooooo", "foo"}])
    preprocess.save_counts(
        tmp_path / "domains_clean.csv", preprocess.count_labels(["foo.com", "foooooo.com"])
    )
    assert base_domain.main(["--data-dir", str(tmp_path)]) == 0
    assert base_domain.load_base_domains(tmp_path / "base_domains.csv") == ["foo"]


def test_main_reports_a_missing_input(tmp_path):
    assert base_domain.main(["--data-dir", str(tmp_path)]) == 1


def test_main_reports_a_missing_cluster_file(tmp_path):
    preprocess.save_counts(tmp_path / "domains_clean.csv", preprocess.count_labels(["a.com"]))
    assert base_domain.main(["--data-dir", str(tmp_path)]) == 1
