challenges:= 1 2 3 4 5 6 7
.DEFAULT_GOAL:= test

.PHONY: venv
venv:
	./bin/venv_update.py venv= -ppython3 venv install= -r requirements-dev.txt -r requirements.txt --quiet

.PHONY: test
test: $(challenges)

$(challenges): venv
	./venv/bin/python -m set1.challenge$@
