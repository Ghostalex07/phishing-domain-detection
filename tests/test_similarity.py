from itertools import combinations

import pytest
from rapidfuzz.distance import Indel

from phishing_domain_detection import similarity
from phishing_domain_detection.cli import PipelineError


def brute_force(names, threshold):
    """The obvious all-pairs implementation the blocked version replaces."""
    return [
        (a, b, round(Indel.normalized_similarity(a, b), 2))
        for a, b in combinations(names, 2)
        if Indel.normalized_similarity(a, b) >= threshold
    ]


def test_finds_close_names():
    pairs = similarity.find_similar_pairs(["gogle", "google", "example"], threshold=0.6)
    names = {name for pair in pairs for name in pair[:2]}
    assert "gogle" in names
    assert "google" in names
    assert "example" not in names


def test_respects_threshold():
    assert similarity.find_similar_pairs(["abc", "def"], threshold=1.0) == []
    assert len(similarity.find_similar_pairs(["abc", "abc"], threshold=1.0)) == 1


def test_scores_are_rounded():
    pairs = similarity.find_similar_pairs(["abcdef", "abcdeg"], threshold=0.8)
    assert pairs == [("abcdef", "abcdeg", 0.83)]


@pytest.mark.parametrize("threshold", [0.6, 0.8, 0.9, 1.0])
def test_matches_a_brute_force_reference(threshold):
    names = ["google", "gogle", "googol", "example", "exemple", "faraway", "goggle", "gogg le"]
    assert similarity.find_similar_pairs(names, threshold) == brute_force(names, threshold)


def test_matches_brute_force_across_a_band_boundary():
    """The matching pair straddles a multiple of BLOCK_SIZE.

    Using band-local row indices instead of global ones re-emits cross-band
    pairs, so this is the case that catches that bug.
    """
    block = similarity.BLOCK_SIZE
    names = [f"filler{i:05d}qq" for i in range(block - 1)]
    names.append("target")
    names.append("targets")
    pairs = similarity.find_similar_pairs(names, 0.8)
    assert ("target", "targets", 0.92) in pairs
    assert pairs == brute_force(names, 0.8)


def test_scores_every_pair_exactly_once():
    names = ["aaaa", "aaab", "aaac", "zzzz"]
    pairs = similarity.find_similar_pairs(names, 0.0)
    assert len(pairs) == len(list(combinations(names, 2)))
    assert len(set(map(frozenset, ((a, b) for a, b, _ in pairs)))) == len(pairs)


def test_keeps_pairs_exactly_at_the_threshold():
    """rapidfuzz's score_cutoff drops these; the explicit >= must not."""
    names = ["abcde", "abcdx"]
    assert Indel.normalized_similarity("abcde", "abcdx") == 0.8
    assert similarity.find_similar_pairs(names, 0.8) == [("abcde", "abcdx", 0.8)]


@pytest.mark.parametrize("names", [[], ["solo"]])
def test_returns_nothing_when_there_is_nothing_to_compare(names):
    assert similarity.find_similar_pairs(names) == []


def test_handles_duplicate_names():
    assert similarity.find_similar_pairs(["abc", "abc"], 1.0) == [("abc", "abc", 1.0)]


def test_order_follows_the_input():
    names = ["zzz", "abcdx", "abcde"]
    assert similarity.find_similar_pairs(names, 0.8) == [("abcdx", "abcde", 0.8)]


def test_save_and_load_pairs_round_trip(tmp_path):
    path = tmp_path / "similar_pairs.csv"
    pairs = [("a", "b", 0.9), ("c", "d", 0.8)]
    similarity.save_pairs(path, pairs)
    assert path.read_text(encoding="utf-8").splitlines()[0] == "name1,name2,similarity"
    assert similarity.load_pairs(path) == pairs


def test_load_pairs_rejects_a_missing_column(tmp_path):
    path = tmp_path / "similar_pairs.csv"
    path.write_text("name1,name2\na,b\n", encoding="utf-8")
    with pytest.raises(PipelineError, match="similarity"):
        similarity.load_pairs(path)


def test_load_pairs_rejects_a_non_numeric_score(tmp_path):
    path = tmp_path / "similar_pairs.csv"
    path.write_text("name1,name2,similarity\na,b,high\n", encoding="utf-8")
    with pytest.raises(PipelineError, match="bad similarity"):
        similarity.load_pairs(path)


def test_main_succeeds(tmp_path):
    (tmp_path / "domains_clean.csv").write_text(
        "name,domain,count\ngogle,gogle.com,1\ngoogle,google.com,1\n",
        encoding="utf-8",
    )
    assert similarity.main(["--data-dir", str(tmp_path)]) == 0
    assert similarity.load_pairs(tmp_path / "similar_pairs.csv") == [("gogle", "google", 0.91)]


def test_main_reports_a_missing_input(tmp_path):
    assert similarity.main(["--data-dir", str(tmp_path)]) == 1


def test_main_rejects_an_out_of_range_threshold(tmp_path, capsys):
    (tmp_path / "domains_clean.csv").write_text("name,domain,count\n", encoding="utf-8")
    assert similarity.main(["--data-dir", str(tmp_path), "--threshold", "1.5"]) == 1
    assert "--threshold must be" in capsys.readouterr().err
