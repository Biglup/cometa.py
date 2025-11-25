.PHONY: install lint test check clean

# Install dependencies and the package in editable mode
install:
	python -m pip install --upgrade pip
	pip install pylint pytest cffi
	pip install -e .

# Run Pylint (matches CI step)
lint:
	pylint src

# Run Unit Tests (matches CI step)
test:
	pytest -v

# Run both Lint and Test (Standard CI check)
check: lint test

# Cleanup build artifacts
clean:
	rm -rf build dist *.egg-info
	rm -rf src/*.egg-info
	find . -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -exec rm -f {} +