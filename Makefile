.PHONY: venv
venv:
	./bin/venv_update.py venv= -ppython3 venv install= -r requirements-dev.txt
