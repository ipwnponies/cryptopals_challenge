.PHONY: venv
venv:
	./bin/venv_update.py venv= -ppython3 venv install= -r requirements-dev.txt --quiet

.PHONY: test
test: venv
	./venv/bin/python set1/challenge*.py
