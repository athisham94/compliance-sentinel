# Compliance Sentinel — Architecture and Roadmap

## 1. Current System

```text
       Synthetic Enterprise Events
                    |
                    v
              FastAPI Backend
                    |
                    v
               SQLite Store
                    |
                    v
           Compliance Evaluation
                    ^
                    |
          Periodic Background Scheduler
                    |
                    v
          Monitoring Run History
                    |
                    v
          Findings and Evidence
                    |
                    v
           Streamlit Dashboard
```

## 2. Current Capabilities

### Event Processing
The application accepts and stores synthetic enterprise event data for compliance evaluation.

### Compliance Evaluation
Three controls are currently implemented:

- **AC-01:** Access revocation following employee termination
- **AC-02:** Privileged account ownership checks
- **CM-01:** Critical cloud change review

### Finding Management
The system records compliance findings and supporting evidence for investigation.

### Continuous Monitoring
A background scheduler periodically triggers compliance evaluations and records monitoring execution history.

### Auditability
Audit records and monitoring history provide visibility into application activity and evaluation outcomes.

### Dashboard
The Streamlit interface allows users to inspect findings, controls, events, audit records, and monitoring health.

## 3. Monitoring and Evidence Flow

1. Enterprise events enter the application.
2. The events are stored in SQLite.
3. The compliance evaluation process checks applicable controls.
4. Violations generate or update findings.
5. Monitoring execution details are saved in the run history.
6. The dashboard presents findings and monitoring information for investigation.

## 4. Planned Extensions

The following capabilities are future roadmap items and are not represented as implemented features.

### Enterprise Integrations
- HR and employee lifecycle systems
- Cloud provider audit events
- Identity and access management platforms
- Configuration management systems
- SAP and GitHub integrations

### IBM Z and LinuxONE
- IBM LinuxONE deployment and validation
- Mainframe-specific event ingestion
- Integration with appropriate enterprise monitoring sources
- Environment-specific security and operational testing

### Compliance Intelligence
- Additional compliance controls
- Mapping controls to selected security frameworks
- More detailed evidence collection
- Enhanced risk prioritization
- Policy interpretation and analysis

### Operational Improvements
- Authentication and role-based authorization
- More automated remediation workflows
- Deployment automation
- Expanded testing and error handling
- Production monitoring and operational documentation

## 5. Design Principles

- **Evidence first:** Compliance findings should be supported by recorded evidence.
- **Traceability:** Monitoring executions and audit records should help explain system activity.
- **Separation of responsibilities:** Event ingestion, compliance evaluation, persistence, and presentation should remain distinct components.
- **Incremental integration:** Future data sources should feed validated events into the existing evaluation pipeline.
- **Honest capability claims:** Planned integrations and deployment targets must not be presented as already implemented.

## 6. Prototype Disclaimer

Compliance Sentinel currently uses synthetic data. Live enterprise integrations and IBM LinuxONE deployment have not been demonstrated.

The application is a compliance monitoring prototype, not a certified compliance product. Its results do not independently establish regulatory compliance.