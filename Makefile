PYTHON ?= $(shell command -v python3 || command -v python)

.PHONY: install install-dev test lint format typecheck pipeline run clean

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	ruff check src tests

format:
	ruff check --fix src tests

typecheck:
	$(PYTHON) -m mypy

pipeline:
	phishing-pipeline

run: pipeline

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist src/*.egg-info
