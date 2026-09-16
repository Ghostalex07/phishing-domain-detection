from phishing_domain_detection.preprocess import count_labels


def test_counts_primary_labels():
    counts = count_labels(["google.com", "google.com", "example.org", ""])
    assert counts["google"]["count"] == 2
    assert counts["example"]["count"] == 1


def test_keeps_first_seen_domain():
    counts = count_labels(["google.com", "google.net"])
    assert counts["google"]["domain"] == "google.com"


def test_skips_invalid_lines():
    counts = count_labels(["nodots", "a.b.c", "   ", ""])
    assert "nodots" not in counts
    assert set(counts) == {"a"}