# Sovereign Security Archive - convenience targets.
# Requires: python3 (3.9+) or py -3 on Windows.

PYTHON ?= python3
ROOT   ?= .

.PHONY: help init verify validate index stats upstream-diff clean

help:
	@echo "SSA targets:"
	@echo "  make init            scaffold/refresh the archive tree"
	@echo "  make verify          structure + reference integrity"
	@echo "  make validate        JSON Schema validation"
	@echo "  make index           build 03-wordlists/index/wordlist.db"
	@echo "  make stats           archive statistics"
	@echo "  make upstream-diff   compare pinned upstream refs (network)"
	@echo "  make clean           remove generated artifacts"

init:
	$(PYTHON) tools/ssactl.py init --root $(ROOT)

verify:
	$(PYTHON) tools/ssactl.py verify --root $(ROOT) --strict

validate:
	$(PYTHON) tools/ssactl.py validate --root $(ROOT)

index:
	$(PYTHON) tools/ssactl.py index --root $(ROOT)

stats:
	$(PYTHON) tools/ssactl.py stats --root $(ROOT)

upstream-diff:
	$(PYTHON) tools/ssactl.py diff --upstream --root $(ROOT)

clean:
	$(PYTHON) tools/ssactl.py clean --root $(ROOT)
