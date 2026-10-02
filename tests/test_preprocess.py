import pytest

from phishing_domain_detection import preprocess
from phishing_domain_detection.cli import PipelineError


def test_counts_primary_labels():
    counts = preprocess.count_labels(["google.com", "google.com", "example.org", ""])
    assert counts["google"].count == 2
    assert counts["example"].count == 1


def test_keeps_first_seen_domain():
    counts = preprocess.count_labels(["google.com", "google.net"])
    assert counts["google"].domain == "google.com"


def test_skips_invalid_lines():
    """Every line is validated now, which also changes the verdict on "a.b.c".

    "a.b.c" ends in a one-character TLD, and :func:`hostname.normalize` requires
    two or more letters there - "c" is not a real TLD. Step 1 cannot produce such
    a line, because :mod:`extract_domains` runs the same ``normalize`` over the
    CT dump and drops it there. Step 2 used to keep it anyway, which meant the
    two stages disagreed about what a valid domain is and step 2 admitted
    something step 1 had already filtered out. Validating every line makes step 2
    accept exactly the set step 1 emits.
    """
    counts = preprocess.count_labels(["nodots", "a.b.c", "   ", ""])
    assert counts == {}


def test_keeps_the_valid_domains_around_a_skipped_line():
    """One bad line must not cost the analyst the rest of the run."""
    counts = preprocess.count_labels(["google.com", "a.b.c", "google.net"])
    assert counts["google"].count == 2
    assert counts["google"].domain == "google.com"


def test_skips_formula_shaped_lines():
    """A skipped line is skipped validated, so it cannot reach the CSV as a formula."""
    counts = preprocess.count_labels(
        ["=1+1.com", "+SUM(1+1).com", "@sum(1+1).x", "-2+3.com", "google.com"]
    )
    assert set(counts) == {"google"}


def test_the_skip_is_reported_as_one_count(caplog):
    preprocess.count_labels(["a.b.c", "google.com", "nope"])
    assert "Skipped 2 line(s)" in caplog.text


def test_a_clean_input_reports_no_skips(caplog):
    preprocess.count_labels(["google.com", "google.net"])
    assert "Skipped" not in caplog.text


def test_skips_lines_with_an_empty_first_label():
    assert preprocess.count_labels([".com", "ok.com"]) == preprocess.count_labels(["ok.com"])


def test_bump_does_not_mutate():
    entry = preprocess.DomainCount(domain="a.com", count=1)
    bumped = entry.bump()
    assert bumped.count == 2
    assert bumped.domain == "a.com"
    assert entry.count == 1


def test_domain_count_is_immutable():
    entry = preprocess.DomainCount(domain="a.com", count=1)
    with pytest.raises(AttributeError):
        entry.count = 2  # type: ignore[misc]


def test_counts_lowercase_input():
    counts = preprocess.count_labels(["GOOGLE.COM", "google.net"])
    assert counts["google"].domain == "google.com"
    assert counts["google"].count == 2


def test_save_counts_is_sorted_and_round_trips(tmp_path):
    counts = preprocess.count_labels(["b.com", "a.com", "a.net"])
    path = tmp_path / "domains_clean.csv"
    preprocess.save_counts(path, counts)

    assert path.read_text(encoding="utf-8").splitlines()[0] == "name,domain,count"
    assert [line.split(",")[0] for line in path.read_text(encoding="utf-8").splitlines()[1:]] == [
        "a",
        "b",
    ]
    assert preprocess.load_counts(path) == counts


def test_load_counts_yields_real_integers(tmp_path):
    """count is a str on disk; load_counts is the only place that casts it."""
    path = tmp_path / "domains_clean.csv"
    path.write_text("name,domain,count\ngoogle,google.com,7\n", encoding="utf-8")
    entry = preprocess.load_counts(path)["google"]
    assert entry.count == 7
    assert isinstance(entry.count, int)


def test_load_counts_rejects_a_missing_column(tmp_path):
    path = tmp_path / "domains_clean.csv"
    path.write_text("name,domain\ngoogle,google.com\n", encoding="utf-8")
    with pytest.raises(PipelineError, match="missing CSV column"):
        preprocess.load_counts(path)


def test_load_counts_rejects_a_non_numeric_count(tmp_path):
    path = tmp_path / "domains_clean.csv"
    path.write_text("name,domain,count\ngoogle,google.com,many\n", encoding="utf-8")
    with pytest.raises(PipelineError, match="bad count"):
        preprocess.load_counts(path)


def test_load_names_preserves_file_order(tmp_path):
    path = tmp_path / "domains_clean.csv"
    path.write_text("name,domain,count\nz,z.com,1\na,a.com,1\n", encoding="utf-8")
    assert preprocess.load_names(path) == ["z", "a"]


def test_main_succeeds(tmp_path):
    (tmp_path / "domains_raw.txt").write_text("google.com\ngoogle.net\nexample.org\n")
    assert preprocess.main(["--data-dir", str(tmp_path)]) == 0
    assert preprocess.load_counts(tmp_path / "domains_clean.csv")["google"].count == 2


def test_main_reports_a_missing_input(tmp_path):
    assert preprocess.main(["--data-dir", str(tmp_path)]) == 1
