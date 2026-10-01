# Contributing to Cerberus

Thank you for your interest in contributing to Cerberus! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and inclusive in all interactions.

## How to Contribute

### Reporting Issues

1. Check if the issue already exists in the [issue tracker](https://github.com/Aikagra-rgb/Cerberus/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce (if bug)
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Screenshots/logs if applicable

### Pull Request Process

1. **Fork** the repository
2. **Create a feature branch** from `develop` (not `main`):
   ```bash
   git checkout -b feature/your-feature-name develop
   ```
3. **Make your changes** following the coding standards below
4. **Run tests and linters** locally:
   ```bash
   # Install dev dependencies
   pip install -r requirements-dev.txt
   pre-commit install
   
   # Run checks
   ruff check .
   ruff format --check .
   mypy src/ api.py
   pytest tests/ -v --cov=src --cov=api --cov-fail-under=70
   bandit -r src/
   pip-audit -r requirements.txt
   ```
5. **Commit** with clear, conventional commit messages:
   ```
   feat: add new detection rule for CVE-2024-XXXX
   fix: resolve race condition in session handling
   docs: update API documentation for /metrics endpoint
   ```
6. **Push** to your fork and create a Pull Request against `develop`

### Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Formatting, missing semicolons, etc.
- `refactor:` - Code restructuring without behavior changes
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks (deps, build config, etc.)
- `perf:` - Performance improvements
- `security:` - Security-related changes

### Coding Standards

#### Python
- **Type hints** required for all public functions
- **Docstrings** for all public classes/functions (Google style)
- **Line length**: 100 characters max
- **Imports**: `isort` style (stdlib, third-party, local)
- **Async/await** preferred for I/O operations

#### JavaScript
- **ES6+** syntax
- **No frameworks** (vanilla JS only for now)
- **Event delegation** over inline handlers
- **IIFE** for module encapsulation

#### Security
- **Never commit secrets** (API keys, passwords, tokens)
- **Validate all inputs** on both client and server
- **Use parameterized queries** for database operations
- **Sanitize output** to prevent XSS

### Testing Requirements

- **Unit tests** for all new functions/classes
- **Integration tests** for new API endpoints
- **Coverage**: Maintain ≥70% overall coverage
- **Test naming**: `test_<function>_<scenario>_<expected>`

### Documentation

- Update relevant docs for any API changes
- Add docstrings for new public APIs
- Update `CHANGELOG.md` for notable changes
- Include type hints in all new code

## Development Setup

```bash
# Clone and setup
git clone https://github.com/Aikagra-rgb/Cerberus.git
cd Cerberus

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Train models (if needed)
python trainer.py --type all

# Start development servers
# Terminal 1: Backend
python -m uvicorn api:app --reload --port 8000

# Terminal 2: Frontend
cd frontend && node server.mjs
```

## Release Process

1. **Version bump** in `api.py` and `frontend/package.json`
2. **Update CHANGELOG.md** with release notes
3. **Create release branch**: `release/vX.Y.Z`
4. **Run full CI suite** - must pass
5. **Merge to main** and tag release
6. **Deploy** via CI/CD pipeline

## Getting Help

- Check existing [documentation](https://github.com/Aikagra-rgb/Cerberus/wiki)
- Search [closed issues](https://github.com/Aikagra-rgb/Cerberus/issues?q=is%3Aissue+is%3Aclosed)
- Ask in [Discussions](https://github.com/Aikagra-rgb/Cerberus/discussions)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.