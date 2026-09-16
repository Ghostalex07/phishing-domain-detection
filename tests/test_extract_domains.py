from phishing_domain_detection.extract_domains import extract_domains


RECORDS = [
    {"name_value": "www.tiffany.com"},
    {"name_value": "a.wazizu.com\nSee www.rapidssl.com/resources/cps (c)12"},
    {"name_value": "Go to https://www.thawte.com/repository/index.html\nWWW.PATH2USA.COM"},
    {},
]


def test_reduces_names_to_registrable_domain():
    domains = extract_domains(RECORDS)
    assert "tiffany.com" in domains
    assert "wazizu.com" in domains


def test_skips_noise_lines():
    domains = extract_domains(RECORDS)
    assert "rapidssl.com" not in domains
    assert "thawte.com" not in domains


def test_lowercases_input():
    domains = extract_domains(RECORDS)
    assert "path2usa.com" in domains
    assert "WWW.PATH2USA.COM" not in domains


def test_handles_empty_input():
    assert extract_domains([]) == set()
    assert "wazizu.com" in extract_domains(RECORDS)