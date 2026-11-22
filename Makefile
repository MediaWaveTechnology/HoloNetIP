.PHONY: install validate test secret-scan hooks

install:          ## create a venv and install HoloNet with dev tools
	python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

validate:         ## lint, tests, and secret scan: the gate run before every push
	.venv/bin/ruff check holonet map tests scripts
	.venv/bin/pytest -q
	$(MAKE) secret-scan

test:             ## tests only
	.venv/bin/pytest -q

secret-scan:      ## scan working tree and git history; reports in reports/secret-scan/
	.venv/bin/python scripts/secret_scan.py --mode all

hooks:            ## run validation before every git push from this clone
	git config core.hooksPath .githooks
