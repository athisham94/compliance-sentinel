# Compliance Sentinel
Continuous compliance drift detection MVP.

## What this prototype does
- Accepts synthetic HR termination and account-status events.
- Evaluates access-revocation controls against a configurable deadline.
- Stores events and findings in SQLite.
- Exposes a FastAPI backend and a Streamlit dashboard.
- Includes a simulator for a demo scenario.

This is a prototype using synthetic data. It is not a certified ISO 27001 compliance tool and does not connect to real SAP, AWS, or GitHub systems.

## Setup
Use Python 3.11+.
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the API
Terminal 1:
```bash
uvicorn backend.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

## Run the dashboard
Terminal 2:
```bash
streamlit run dashboard/app.py
```

## Load demo events
Terminal 3:
```bash
python simulator/demo_scenario.py
```
Refresh the dashboard to see the detected drift.

## IBM Z / LinuxONE plan
The MVP runs locally first. It is designed to be containerizable and can be deployed to LinuxONE if an environment is available. Actual LinuxONE deployment and live mainframe integrations are planned, not implemented in this prototype.
