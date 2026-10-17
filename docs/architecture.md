# Compliance Sentinel — Architecture

## 1. Overview

Compliance Sentinel is a Python-based compliance monitoring prototype. It accepts synthetic enterprise events, evaluates configured security controls, stores findings and evidence, and presents compliance information through a FastAPI backend and Streamlit dashboard.

## 2. Architecture Diagram

```text
       Synthetic Enterprise Events
                    |
                    v
             FastAPI Backend
                    |
                    v
              SQLite Database
                    |
                    v
          Compliance Evaluation
                    ^
                    |
          Background Scheduler
                    |
                    v
          Monitoring Run History
                    |
                    v
          Findings and Evidence
                    |
                    v
           Streamlit Dashboard
                    |
                    v
       Investigation and Remediation
```

## 3. Implemented Components

### 3.1 Event Ingestion

The FastAPI backend provides endpoints for accepting and accessing enterprise event data used by compliance evaluations.

The current prototype uses synthetic data rather than live enterprise integrations.

### 3.2 Data Persistence

SQLite stores application data, including events, compliance findings, audit records, and monitoring run history.

### 3.3 Compliance Control Engine

The application evaluates three implemented controls.

**AC-01 — Access Revocation**

Detects access that remains active after an employee's termination beyond the configured deadline.

**AC-02 — Privileged Account Ownership**

Detects privileged accounts that lack expected ownership information.

**CM-01 — Critical Change Review**

Detects critical cloud changes that remain unreviewed beyond the configured deadline.

### 3.4 Continuous Monitoring

A background scheduler periodically triggers compliance evaluation.

The monitoring system records execution status, timestamps, evaluation counts, and errors. This information supports troubleshooting and visibility into monitoring activity.

### 3.5 Finding Management

Compliance findings include relevant evidence and status information. Findings can be reviewed through the API and dashboard.

### 3.6 Audit Trail

The application exposes recorded audit events to support investigation and traceability.

### 3.7 Dashboard

The Streamlit dashboard provides views for:

- Overview and monitoring health
- Findings and alerts
- Compliance controls
- Security events
- Audit trail
- Live monitoring and run history

## 4. API Endpoints

The application provides endpoints including:

- `GET /health`
- `GET /controls`
- `GET /events`
- `GET /findings`
- `GET /audit-log`
- `GET /monitoring/status`
- `GET /monitoring/runs?limit=10`

Consult the running FastAPI documentation at `/docs` for the available operations and request formats.

## 5. Monitoring Workflow

1. The application receives or stores enterprise event data.
2. The compliance monitor evaluates applicable controls.
3. Violations are recorded as findings with supporting evidence.
4. Monitoring execution details are persisted in the run history.
5. Users inspect findings, events, and monitoring status through the dashboard.
6. Investigators review findings and perform remediation as appropriate.

## 6. Current Limitations

Compliance Sentinel is a prototype that uses synthetic data.

Live integrations with enterprise HR platforms, cloud providers, SAP, GitHub, and mainframe systems have not been implemented.

Deployment on IBM LinuxONE has not been demonstrated. Production authentication, authorization, and deployment hardening require further work.

The prototype is not a certified compliance product, and its output alone does not establish compliance with a regulatory standard.

## 7. Future Enhancements

Potential future improvements include:

- Live enterprise event integrations
- IBM LinuxONE deployment and validation
- Mainframe-specific event ingestion
- Additional compliance controls and framework mappings
- Expanded evidence collection
- More automated remediation workflows
- Enhanced authentication and authorization
- Production deployment automation