.DEFAULT_GOAL := all

.PHONY: install-linting
install-linting:
	pip install -r tests/requirements-linting.txt

.PHONY: install-blacknet
install-blacknet:
	pip install -U pip build wheel
	pip install -e .

.PHONY: install-devel
install-devel:
	pip install -r tests/requirements-devel.txt

.PHONY: install-testing
install-testing: install-blacknet
	pip install -r tests/requirements-testing.txt

.PHONY: install
install: install-devel install-linting
	@echo 'Installed development requirements'

.PHONY: build
build:
	python -m build --wheel --sdist

.PHONY: format
format:
	ruff check --select=I --fix-only
	ruff format

.PHONY: lint
lint:
	ruff check
	ruff format --check --diff

.PHONY: mypy
mypy:
	mypy

.PHONY: all
all: lint mypy

.PHONY: clean
clean:
	$(RM) .coverage
	$(RM) .coverage.*
	$(RM) -r *.egg-info
	$(RM) -r .mypy_cache
	$(RM) -r build
	$(RM) -r dist
	$(RM) -r htmlcov
	find blacknet -name '*.py[cod]' -delete
	ruff clean
