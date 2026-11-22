.PHONY: install validate test hooks

install:          ## create a venv and install HoloNet with dev tools
	python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

validate:         ## lint and tests: the gate run before every push
	.venv/bin/ruff check holonet map tests
	.venv/bin/pytest -q

test:             ## tests only
	.venv/bin/pytest -q

hooks:            ## run validation before every git push from this clone
	git config core.hooksPath .githooks
