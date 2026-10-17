# Compliance Sentinel v2 — MVP Architecture

```text
Synthetic HR / AWS-style / SAP-style / GitHub events
                         |
                         v
                FastAPI Event Ingestion
                         |
                         v
             Validation + SQLite Evidence Store
                         |
                         v
                 Event Correlation
                         |
                         v
                Compliance Control Engine
             /              |               \
            v               v                v
    Access Revocation  Privileged Owner  Cloud Change Review
             \              |               /
                         v
                  Drift Detection
                         |
                         v
             Risk severity + evidence
                         |
                         v
             Streamlit dashboard
                         |
                         v
              Manual remediation status
```

## Implemented in this prototype
- Access revocation deadline detection (AC-01).
- Privileged account ownership detection (AC-02).
- Critical cloud change review deadline detection (CM-01).
- SQLite event and finding persistence.
- Streamlit dashboard with evidence and finding resolution.
- Synthetic demo events.

## Limitations
- Cloud change review is evaluated when a critical change event is ingested; this MVP does not run a background scheduler. A later review event is not yet designed to automatically resolve an existing finding.
- Integrations with live AWS, SAP, GitHub, HR, and IBM Z/LinuxONE are not implemented.
- AI-assisted policy interpretation is planned, not implemented.
- This is a prototype, not a certified compliance assessment.

## IBM Z/LinuxONE path
The Python API and dashboard can be containerized for a future LinuxONE deployment if the team has access. Actual deployment and mainframe integration must be completed and tested before being claimed.
