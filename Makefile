PYTHON ?= $(shell command -v python3 || command -v python)

.PHONY: install install-dev test pipeline run clean

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

pipeline:
	phishing-pipeline

run: pipeline

clean:
	rm -rf .pytest_cache build dist src/*.egg-info