# Contributing to django-smart-layer

Thank you for considering contributing! Every bit helps — bug reports, fixes,
docs, and new features are all welcome.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Running Tests](#running-tests)
- [How to Contribute](#how-to-contribute)
- [Code Style](#code-style)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Getting Started

1. Fork the repository and clone your fork:
```bash
   git clone https://github.com/your-username/SmartLayer.git
   cd SmartLayer
```

2. Create a virtual environment and install dependencies:
```bash
   python -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   pip install django httpx
   pip install apscheduler          # optional, for scheduled log analysis
   pip install pytest pytest-django
```

3. Create a branch for your change:
```bash
   git checkout -b fix/your-fix-name
```

---

## Running Tests

```bash
pytest
```

All tests must pass before submitting a pull request. If you are adding a
feature, please add tests for it too.

---

## How to Contribute

1. **Open an issue first** for any non-trivial change so we can discuss it
   before you invest time writing code.
2. Make your changes on your branch.
3. Write or update tests as needed.
4. Push your branch and open a pull request against `main`.
5. Fill in the pull request description — what the change does and why.

---

## Code Style

- Follow the existing code style in the file you are editing.
- Keep functions small and focused.
- Add a comment when the reason for doing something is not obvious.
- No unused imports.

---

## Reporting Bugs

Open a [GitHub issue](https://github.com/ayushi2577/SmartLayer/issues) and include:

- Your Django version and Python version.
- The relevant section of your `SMART_MIDDLEWARE` settings (redact API keys).
- The full traceback if there is one.

---

## Feature Requests

Open a [GitHub issue](https://github.com/ayushi2577/SmartLayer/issues) with
the label `enhancement` and describe the use case you are trying to solve.