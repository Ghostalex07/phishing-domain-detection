from phishing_domain_detection.similarity import find_similar_pairs


def test_finds_close_names():
    pairs = find_similar_pairs(["gogle", "google", "example"], threshold=0.6)
    names = {name for pair in pairs for name in pair[:2]}
    assert "gogle" in names
    assert "google" in names
    assert "example" not in names


def test_respects_threshold():
    assert find_similar_pairs(["abc", "def"], threshold=1.0) == []
    assert len(find_similar_pairs(["abc", "abc"], threshold=1.0)) == 1


def test_scores_are_rounded():
    pairs = find_similar_pairs(["abcdef", "abcdeg"], threshold=0.8)
    assert pairs == [("abcdef", "abcdeg", 0.83)]