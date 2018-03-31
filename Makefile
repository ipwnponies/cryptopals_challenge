.DEFAULT_GOAL := help

sets:= set1 set2
challenges_set1:= $(patsubst %, set1-%, 1 2 3 4 5 6 7 8)
challenges_set2:= $(patsubst %, set2-%, 9 10 11)

.PHONY: help
help:  # Print help
	@grep -E -v -e '^\s' -e '^\.' $(MAKEFILE_LIST) | grep -E '^\S+( \S+)*:.*#' | sort | awk 'BEGIN {FS = ":.*# "}; {printf "\033[1;32m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: venv
venv:  # Create venv
	./bin/venv_update.py venv= -ppython3 venv install= -r requirements-dev.txt -r requirements.txt --quiet
	./venv/bin/pre-commit install

.PHONY: test
all_sets :=$(foreach i, $(sets), test-$(i))
test: $(all_sets)  # Run all tests
	./venv/bin/pre-commit run

.PHONY: test-set1
test-set1: $(challenges_set1);  # Run tests for set 1

.PHONY: set1-%
set1-%: venv  # Run test for single challenge in set 1
	./venv/bin/python -m set1.challenge$*

.PHONY: test-set2
test-set2: $(challenges_set2);  # Run tests for set 2

.PHONY: set2-%
set2-%: venv  # Run test for single challenge in set 2
	./venv/bin/python -m set2.challenge$*
