This is a single self-contained fix; keep it small and focused. Fix the startup failure on Render for the Flask app 'System Ministranci' so that `gunicorn main:app` starts successfully with PostgreSQL.

Working directory: d:\FullStackRoad\Ministranci
Integrity mode: development

## Requirements

### R1. Fix Render Startup and PostgreSQL Database Initialization
Resolve the startup crash (`ModuleNotFoundError: No module named 'psycopg'`) so that the application module imports and the SQLAlchemy engine is created successfully when `DATABASE_URL` points to PostgreSQL in an environment matching Render (Python 3.14, latest SQLAlchemy 2.1.x, dependencies installed only from `requirements.txt`).

### R2. Maintain Test Compatibility and Deployment Instructions
Ensure all 7 tests in the existing regression test suite continue to pass. Detail exactly what files to commit and push (or any Render settings to update) so the next deploy succeeds, without pushing to the remote repository.

## Verification Resources
- Existing regression test suite: `C:\Users\Asus\.gemini\antigravity\brain\54733681-ad15-4efb-8ab1-d151d4f34104\scratch\test_suite.py` (run with `python test_suite.py` from the project directory).

## Acceptance Criteria

### Startup & Database Engine Initialization
- [ ] The Flask application imports cleanly and initializes SQLAlchemy without raising `ModuleNotFoundError: No module named 'psycopg'` under Python 3.14 with dependencies installed only from `requirements.txt` and a PostgreSQL `DATABASE_URL`.
- [ ] `gunicorn main:app` starts successfully without startup crashes in the target environment.

### Test Verification & Safe Deployment
- [ ] All 7 tests in `C:\Users\Asus\.gemini\antigravity\brain\54733681-ad15-4efb-8ab1-d151d4f34104\scratch\test_suite.py` pass without errors.
- [ ] The user is provided with exact instructions on what to commit/push or what Render configuration settings to modify for the next deploy.
- [ ] No git commit is pushed to the remote repository.
