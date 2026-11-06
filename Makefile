PY ?= python3

.PHONY: check build

check:
	$(PY) tools/check.py --base origin/main

build:
	$(PY) tools/build.py --version $(VERSION) --out dist
