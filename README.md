# Compliance Sentinel

Continuous compliance drift detection and monitoring MVP.

## Features

- AC-01: Access revocation after employee termination.
- AC-02: Privileged account ownership checks.
- CM-01: Critical cloud change review checks.
- Finding management and supporting evidence.
- Scheduled compliance evaluation.
- Persistent monitoring run history.
- Audit trail and Streamlit dashboard.
- Synthetic demo scenario.

## Setup

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the API

```bash
uvicorn backend.main:app --reload
```

API documentation: http://127.0.0.1:8000/docs

## Run the dashboard

```bash
streamlit run dashboard/app.py
```

## Run the demo

With the API running:

```bash
python simulator/demo_scenario.py
```

## Monitoring

The background scheduler periodically evaluates compliance controls. Configure the interval with `COMPLIANCE_MONITOR_INTERVAL_SECONDS`.

Monitoring endpoints: `/monitoring/status` and `/monitoring/runs?limit=10`.

## Tests

```bash
PYTHONPATH=. python -m pytest tests/ -v
```

## Limitations

This prototype uses synthetic data. Live enterprise integrations and IBM LinuxONE deployment have not been implemented or demonstrated.
