.PHONY: help install test lint format security docker-build run-backend run-frontend clean

help:
	@echo "Cerberus SOC - Make commands:"
	@echo "  make install       Install all production and dev dependencies"
	@echo "  make test          Run pytest suite with coverage enforcement"
	@echo "  make lint          Run Ruff linting, formatting checks, and MyPy type checks"
	@echo "  make format        Auto-format and fix lint issues using Ruff"
	@echo "  make security      Run Bandit AST security analysis and pip-audit"
	@echo "  make docker-build  Build backend and frontend Docker containers"
	@echo "  make run-backend   Start local backend FastAPI API with hot-reload"
	@echo "  make run-frontend  Serve static frontend on localhost:5173"
	@echo "  make clean         Clean build artifacts, caches, and coverage reports"

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pip install -e .

test:
	pytest tests/ -v --cov=src --cov=api --cov-report=term-missing --cov-fail-under=45

lint:
	ruff check .
	ruff format --check .
	mypy src/ api.py --ignore-missing-imports --explicit-package-bases

format:
	ruff format .
	ruff check --fix .

security:
	bandit -r src/ -ll -x tests/
	pip-audit -r requirements.txt --desc

docker-build:
	docker build -t cerberus-backend:latest .
	docker build -t cerberus-frontend:latest ./frontend

run-backend:
	python -m uvicorn api:app --reload --host 0.0.0.0 --port 8000

run-frontend:
	python serve_frontend.py

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov/ build/ dist/ *.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} +
