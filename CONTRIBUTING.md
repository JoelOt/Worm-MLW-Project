## Contributing Guide

Thank you for your interest in improving this project. This guide explains how to propose changes safely and responsibly.

## Ethics and Legal Use

- This project is intended for defensive education and research. Only run code on systems and networks you own and control, with explicit authorization.
- Operate strictly within the law and your institution's policies. You are solely responsible for lawful, ethical use.
- Always use an isolated test environment (e.g., private network, disposable VMs/containers). Do not connect tests to production or public networks.

## Development Setup

- Python 3.8+ is required.
- Create and activate a virtual environment, then install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install paramiko scp
```

- Optional: formatters/linters (recommended)
  - `ruff` or `flake8` for linting
  - `black` for formatting

## Branching and Pull Requests

1. Fork the repository and create a feature branch from `main`:
   - Feature: `feat/<short-kebab-description>`
   - Fix: `fix/<short-kebab-description>`
   - Docs: `docs/<short-kebab-description>`
2. Keep changes focused and atomic; avoid unrelated edits.
3. Update documentation (`README.md`) when behavior, flags, or defaults change.
4. Open a Pull Request with:
   - Clear problem statement and rationale
   - Summary of changes
   - Testing notes (what you ran, expected vs. actual)

## Commit Message Convention

Use Conventional Commits:

- `feat: add polymorphic mutation step to upload`  
- `fix: handle empty grep output in AbraWorm`  
- `docs: clarify debug mode credentials`  
- `refactor: extract ssh connection helper`  
- `chore: pin paramiko version`

Include scope when helpful, e.g., `feat(fooworm): ...`.

## Python Style and Quality

- Prefer readable, explicit code with descriptive names.
- Avoid unnecessary try/except; handle errors meaningfully.
- Keep functions cohesive; favor early returns over deep nesting.
- If you add dependencies, document them and explain why.
- If you introduce configuration (e.g., timeouts, IP ranges), make it parameterized with sane defaults.

## Testing and Verification

- Use an isolated test environment only.
- For `debug = 1` modes:
  - Default credentials: `seed` / `dees`
  - Default IPs: `10.0.2.10`, `10.0.2.11` (targets), `10.0.2.9` (exfil)
  - Verify that a single iteration exits as expected.
- For networked components (`FooWorm.py`, `AbraWorm.py`):
  - Confirm SSH is enabled and reachable on target hosts.
  - Verify identification of target files (e.g., `.foo` or files containing `abracadabra`).
  - Validate exfiltration paths and credentials before enabling exfil steps.
- Do not run with randomized scanning outside controlled environments.

## Documentation

- Update `README.md` to reflect new scripts, flags, environment variables, or behavior changes.
- Include usage examples and any operational caveats (timeouts, permissions, dependencies).

## Adding New Modules or Features

- Keep responsibilities clear (discovery, infection, propagation, exfiltration). Avoid mixing multiple unrelated concerns in one module.
- Provide reinfection guards (idempotence markers) where applicable.
- Prefer configuration constants at the top of files (e.g., timeouts, usernames, ports) and document them.
- If adding polymorphism or mutation steps, ensure generated variants remain syntactically valid and executable.

## Security and Responsible Disclosure

- If you discover a vulnerability in this project (or a dependency), do not open a public issue with exploit details. Instead, propose a minimal private report or redact sensitive details in a PR while describing the fix.
- Avoid committing secrets or real infrastructure details. Use placeholders.

## Code of Conduct

Treat all contributors with respect. Be constructive in feedback, and assume good intent. Harassment, discrimination, or abusive behavior will not be tolerated.

---

By submitting a contribution, you confirm that you have the right to do so, the contribution is your own work (or you have rights to submit it), and you agree to license it under the repository's license.


