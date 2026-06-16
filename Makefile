# ─────────────────────────────────────────────────
# Windows note:
#   `make` is not built into PowerShell or CMD.
#   Install it via Chocolatey: choco install make
#   Or run the commands inside each target manually.
# ─────────────────────────────────────────────────

VENV    := .venv
PYTHON  := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
SERVER  := http://127.0.0.1:8000

# On Windows the Scripts directory is used instead of bin.
# Override: make PYTHON=.venv/Scripts/python.exe
ifeq ($(OS),Windows_NT)
	PYTHON := $(VENV)/Scripts/python.exe
	PIP    := $(VENV)/Scripts/pip.exe
endif

.PHONY: install server get post json health headers docker-build docker-run clean

## install — create .venv and install all dependencies from requirements.txt
install:
	python -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

## server — start the FastAPI server on 127.0.0.1:8000
server:
	$(PYTHON) server.py

## get — fetch all vulnerabilities and display as a colored Rich table sorted newest first
get:
	$(PYTHON) cli.py get

## post — POST the two bundled demo entries (XZ Utils Backdoor + HTTP Request Smuggling)
##        then automatically re-fetch and display the updated collection
post:
	$(PYTHON) cli.py post

## json — fetch all vulnerabilities and print raw JSON (useful for piping to jq)
json:
	$(PYTHON) cli.py get --format json

## health — call the /health liveness probe and print the JSON response
health:
	curl -s $(SERVER)/health | python -m json.tool

## headers — send a HEAD request and print all response headers
##           use this to verify security headers are present on every response
headers:
	curl -I $(SERVER)/api/v1/vulnerabilities

## docker-build — build the container image tagged vuln-tracker
docker-build:
	docker build -t vuln-tracker .

## docker-run — run the container and bind host port 8000 to container port 8000
docker-run:
	docker run -p 8000:8000 vuln-tracker

## docker-up — build and run in one step (equivalent to docker-build + docker-run)
docker-up:
	docker build -t vuln-tracker . && docker run -p 8000:8000 vuln-tracker

## clean — remove the virtual environment and all Python bytecode cache directories
clean:
	rm -rf $(VENV) __pycache__ .pytest_cache
