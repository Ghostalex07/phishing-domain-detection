from phishing_domain_detection.detect_new import find_suspects


def test_flags_lookalike_domains():
    suspects = find_suspects([("absbok.com", "absbok")], ["absbook"], threshold=0.75)
    assert suspects == [("absbok.com", "absbook", 0.92)]


def test_flags_substring_match():
    suspects = find_suspects([("login.example-secure.org", "example-secure")], ["example"], threshold=1.0)
    assert any(base == "example" for _, base, _ in suspects)


def test_low_threshold_keeps_clear_matches_only():
    suspects = find_suspects([("totallyunrelated.com", "totallyunrelated")], ["anchor"], threshold=0.9)
    assert suspects == []