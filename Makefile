# Developer convenience targets. `make test` bootstraps a local venv with the
# package installed editable (incl. dev extras) on first run, then runs pytest.
# Idempotent: the venv is rebuilt only when pyproject.toml changes.

VENV := .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest

.PHONY: venv test test-all clean

venv: $(VENV)/.installed

$(VENV)/.installed: pyproject.toml
	python -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e '.[dev]'
	touch $(VENV)/.installed

# Default suite (integration tests excluded via pyproject addopts).
test: venv
	$(PYTEST)

# Include the integration tests that hit the real network.
test-all: venv
	$(PYTEST) -m 'integration or not integration'

clean:
	rm -rf $(VENV)
