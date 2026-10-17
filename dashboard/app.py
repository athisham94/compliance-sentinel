import json
import os
from datetime import datetime

import pandas as pd
import requests
import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================

API_BASE = os.getenv(
    "COMPLIANCE_API_URL",
    "http://127.0.0.1:8000"
).rstrip("/")

REQUEST_TIMEOUT = 5

st.set_page_config(
    page_title="Compliance Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# API HELPERS
# ============================================================

def api_get(endpoint):
    """Fetch data from the Compliance Sentinel API."""
    try:
        response = requests.get(
            f"{API_BASE}{endpoint}",
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json(), None

    except requests.RequestException as exc:
        return None, str(exc)


def api_post(endpoint, payload=None):
    """Send a POST request to the API."""
    try:
        response = requests.post(
            f"{API_BASE}{endpoint}",
            json=payload or {},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        if response.content:
            return response.json(), None

        return {}, None

    except requests.RequestException as exc:
        message = str(exc)

        if getattr(exc, "response", None) is not None:
            try:
                message = (
                    f"HTTP {exc.response.status_code}: "
                    f"{exc.response.text}"
                )
            except Exception:
                pass

        return None, message


def api_patch(endpoint, payload):
    """Send a PATCH request to the API."""
    try:
        response = requests.patch(
            f"{API_BASE}{endpoint}",
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        if response.content:
            return response.json(), None

        return {}, None

    except requests.RequestException as exc:
        return None, str(exc)


def as_list(data):
    """Normalize common API response formats into a list."""
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("items", "findings", "controls", "events", "entries", "logs"):
            if isinstance(data.get(key), list):
                return data[key]

    return []


def display_value(value):
    """Convert structured values into readable text."""
    if value is None:
        return "Not provided"

    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)

    text = str(value).strip()

    return text if text else "Not provided"


def first_value(record, *keys, default="Not provided"):
    """Return the first available field from a dictionary."""
    for key in keys:
        value = record.get(key)

        if value is not None and value != "":
            return value

    return default


def normalize_status(value):
    return str(value or "OPEN").strip().upper()


def normalize_severity(value):
    return str(value or "UNKNOWN").strip().upper()


def format_timestamp(value):
    if not value or value == "Not provided":
        return "Not provided"

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
        return parsed.strftime("%d %b %Y, %I:%M:%S %p")
    except (ValueError, TypeError):
        return str(value)


def severity_color(severity):
    severity = normalize_severity(severity)

    colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#16a34a",
        "INFO": "#2563eb",
    }

    return colors.get(severity, "#64748b")


def status_color(status):
    status = normalize_status(status)

    colors = {
        "OPEN": "#dc2626",
        "RESOLVED": "#16a34a",
        "CLOSED": "#16a34a",
        "IN_PROGRESS": "#2563eb",
        "ACKNOWLEDGED": "#ca8a04",
    }

    return colors.get(status, "#64748b")


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.title("🛡️ Compliance Sentinel")

    st.caption("Continuous Compliance Drift Detection")

    st.divider()

    st.markdown("### System")

    st.code(API_BASE, language=None)

    health, health_error = api_get("/health")

    if health_error:
        st.error("API disconnected")
        st.caption(health_error)
    else:
        st.success("API connected")

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Findings",
            "Controls",
            "Events",
            "Audit Trail",
        ],
        index=0,
    )

    st.divider()

    if st.button("Refresh dashboard", use_container_width=True):
        st.rerun()

    st.caption("Compliance Sentinel · Version 1.0.0")


# ============================================================
# LOAD DATA
# ============================================================

findings_data, findings_error = api_get("/findings")
controls_data, controls_error = api_get("/controls")
events_data, events_error = api_get("/events")
audit_data, audit_error = api_get("/audit-log")

findings = as_list(findings_data) if findings_data is not None else []
controls = as_list(controls_data) if controls_data is not None else []
events = as_list(events_data) if events_data is not None else []
audit_entries = as_list(audit_data) if audit_data is not None else []


# ============================================================
# PAGE HEADER
# ============================================================

st.title("🛡️ Compliance Sentinel")

st.markdown(
    """
    Monitor compliance violations, investigate evidence, track remediation,
    and maintain an auditable record of security events.
    """
)

st.divider()


# ============================================================
# OVERVIEW PAGE
# ============================================================

if page == "Overview":

    if findings_error or controls_error or events_error:
        st.warning(
            "Some dashboard data could not be loaded. "
            "Check that the FastAPI backend is running."
        )

    total_findings = len(findings)

    open_findings = [
        finding
        for finding in findings
        if normalize_status(finding.get("status")) == "OPEN"
    ]

    resolved_findings = [
        finding
        for finding in findings
        if normalize_status(finding.get("status")) in ("RESOLVED", "CLOSED")
    ]

    critical_findings = [
        finding
        for finding in open_findings
        if normalize_severity(finding.get("severity")) == "CRITICAL"
    ]

    high_findings = [
        finding
        for finding in open_findings
        if normalize_severity(finding.get("severity")) == "HIGH"
    ]

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total Findings", total_findings)
    col2.metric("Open Findings", len(open_findings))
    col3.metric("Critical", len(critical_findings))
    col4.metric("High", len(high_findings))
    col5.metric("Resolved", len(resolved_findings))

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Finding Severity")

        severity_counts = {}

        for finding in open_findings:
            severity = normalize_severity(finding.get("severity"))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts:
            severity_df = pd.DataFrame(
                [
                    {"Severity": key, "Count": value}
                    for key, value in severity_counts.items()
                ]
            )

            st.bar_chart(
                severity_df.set_index("Severity"),
                y="Count",
            )
        else:
            st.success("No open findings.")

    with right:
        st.subheader("Compliance Controls")

        if controls:
            controls_rows = []

            for control in controls:
                controls_rows.append(
                    {
                        "Control ID": first_value(
                            control, "control_id", "id"
                        ),
                        "Name": first_value(
                            control, "name", "title"
                        ),
                        "Enabled": first_value(
                            control, "enabled", "is_enabled"
                        ),
                        "Threshold": first_value(
                            control,
                            "threshold_hours",
                            "expected_hours",
                            "deadline_hours",
                        ),
                    }
                )

            st.dataframe(
                pd.DataFrame(controls_rows),
                use_container_width=True,
                hide_index=True,
            )
        elif controls_error:
            st.error(f"Could not load controls: {controls_error}")
        else:
            st.info("No controls returned by the API.")

    st.divider()

    st.subheader("Latest Open Findings")

    if open_findings:
        latest_findings = sorted(
            open_findings,
            key=lambda item: str(
                first_value(item, "detected_at", "created_at", default="")
            ),
            reverse=True,
        )

        rows = []

        for finding in latest_findings[:10]:
            rows.append(
                {
                    "ID": first_value(finding, "id", "finding_id"),
                    "Control": first_value(
                        finding, "control_id", "control"
                    ),
                    "Severity": normalize_severity(
                        finding.get("severity")
                    ),
                    "Status": normalize_status(
                        finding.get("status")
                    ),
                    "Title": first_value(
                        finding, "title", "description", "message"
                    ),
                    "Detected": format_timestamp(
                        first_value(
                            finding,
                            "detected_at",
                            "created_at",
                        )
                    ),
                }
            )

        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.success("There are no open findings.")

    st.divider()

    st.subheader("Recent Events")

    if events:
        recent_events = list(reversed(events[-5:]))

        event_rows = []

        for event in recent_events:
            event_rows.append(
                {
                    "Event Type": first_value(
                        event, "event_type", "type"
                    ),
                    "System": first_value(
                        event, "system", "source"
                    ),
                    "Timestamp": format_timestamp(
                        first_value(
                            event, "timestamp", "created_at", "event_time"
                        )
                    ),
                    "Details": first_value(
                        event, "details", "description", "message"
                    ),
                }
            )

        st.dataframe(
            pd.DataFrame(event_rows),
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info("No events returned by the API.")


# ============================================================
# FINDINGS PAGE
# ============================================================

elif page == "Findings":

    st.subheader("Finding Management")

    st.markdown(
        """
        Investigate violations, inspect their supporting evidence,
        and record remediation through the API.
        """
    )

    if findings_error:
        st.error(f"Could not retrieve findings: {findings_error}")
        st.stop()

    if not findings:
        st.success("No findings were returned by the API.")
        st.stop()

    all_statuses = sorted(
        {
            normalize_status(finding.get("status"))
            for finding in findings
        }
    )

    all_severities = sorted(
        {
            normalize_severity(finding.get("severity"))
            for finding in findings
        }
    )

    filter_col1, filter_col2, filter_col3 = st.columns(3)

    with filter_col1:
        selected_statuses = st.multiselect(
            "Filter by status",
            options=all_statuses,
            default=all_statuses,
        )

    with filter_col2:
        selected_severities = st.multiselect(
            "Filter by severity",
            options=all_severities,
            default=all_severities,
        )

    with filter_col3:
        search_text = st.text_input(
            "Search findings",
            placeholder="Control ID, title, evidence...",
        )

    filtered_findings = []

    for finding in findings:
        status = normalize_status(finding.get("status"))
        severity = normalize_severity(finding.get("severity"))

        if status not in selected_statuses:
            continue

        if severity not in selected_severities:
            continue

        searchable_text = json.dumps(
            finding,
            ensure_ascii=False,
            default=str,
        ).lower()

        if search_text and search_text.lower() not in searchable_text:
            continue

        filtered_findings.append(finding)

    st.caption(
        f"Showing {len(filtered_findings)} of {len(findings)} findings"
    )

    if not filtered_findings:
        st.info("No findings match your filters.")

    for index, finding in enumerate(filtered_findings):

        finding_id = first_value(
            finding, "id", "finding_id"
        )

        control_id = first_value(
            finding, "control_id", "control"
        )

        severity = normalize_severity(finding.get("severity"))
        status = normalize_status(finding.get("status"))

        title = first_value(
            finding,
            "title",
            "description",
            "message",
            default=f"Finding {finding_id}",
        )

        heading = (
            f"{severity} | {control_id} | "
            f"{title} | {status}"
        )

        with st.expander(heading, expanded=False):

            col1, col2, col3 = st.columns(3)

            col1.markdown("**Finding ID**")
            col1.code(str(finding_id))

            col2.markdown("**Severity**")
            col2.markdown(
                f"<span style='color:{severity_color(severity)};"
                f"font-weight:bold'>{severity}</span>",
                unsafe_allow_html=True,
            )

            col3.markdown("**Status**")
            col3.markdown(
                f"<span style='color:{status_color(status)};"
                f"font-weight:bold'>{status}</span>",
                unsafe_allow_html=True,
            )

            st.markdown("### Description")

            st.write(
                first_value(
                    finding,
                    "description",
                    "message",
                    "title",
                    default="No description provided.",
                )
            )

            st.markdown("### Finding Details")

            detail_col1, detail_col2 = st.columns(2)

            with detail_col1:
                st.markdown("**Control**")
                st.write(control_id)

                st.markdown("**Affected system**")
                st.write(
                    first_value(
                        finding,
                        "system",
                        "affected_system",
                    )
                )

                st.markdown("**Affected user/account**")
                st.write(
                    first_value(
                        finding,
                        "employee_id",
                        "user_id",
                        "account_id",
                        "username",
                    )
                )

                st.markdown("**Detected at**")
                st.write(
                    format_timestamp(
                        first_value(
                            finding,
                            "detected_at",
                            "created_at",
                        )
                    )
                )

            with detail_col2:
                st.markdown("**Elapsed hours**")
                st.write(
                    first_value(
                        finding,
                        "elapsed_hours",
                    )
                )

                st.markdown("**Expected hours**")
                st.write(
                    first_value(
                        finding,
                        "expected_hours",
                        "threshold_hours",
                    )
                )

                st.markdown("**Termination time**")
                st.write(
                    format_timestamp(
                        finding.get("termination_time")
                    )
                )

                st.markdown("**Resolved at**")
                st.write(
                    format_timestamp(
                        finding.get("resolved_at")
                    )
                )

            st.markdown("### Evidence")

            evidence = finding.get("evidence")

            if evidence is None:
                st.info("No evidence was attached to this finding.")
            elif isinstance(evidence, (dict, list)):
                st.json(evidence)
            else:
                try:
                    parsed_evidence = json.loads(str(evidence))
                    st.json(parsed_evidence)
                except (ValueError, TypeError):
                    st.code(str(evidence), language=None)

            st.markdown("### Recommended Remediation")

            recommendation = first_value(
                finding,
                "recommendation",
                "remediation",
                "recommended_action",
            )

            st.info(display_value(recommendation))

            if status == "OPEN":

                st.markdown("### Resolve Finding")

                st.caption(
                    "Record remediation only after the underlying "
                    "compliance issue has been addressed."
                )

                with st.form(
                    key=f"resolve_form_{finding_id}_{index}"
                ):
                    resolution_note = st.text_area(
                        "Resolution notes",
                        placeholder=(
                            "Describe the corrective action, "
                            "verification performed, and evidence."
                        ),
                        key=f"resolution_note_{finding_id}_{index}",
                    )

                    submitted = st.form_submit_button(
                        "Mark as resolved",
                        type="primary",
                        use_container_width=True,
                    )

                    if submitted:

                        if not resolution_note.strip():
                            st.error(
                                "Enter resolution notes before "
                                "resolving this finding."
                            )

                        else:
                            with st.spinner("Recording resolution..."):
                                result, error = api_post(
                                    f"/findings/{finding_id}/resolve",
                                    {
                                        "resolution_note": (
                                            resolution_note.strip()
                                        )
                                    },
                                )

                            if error:
                                st.error(
                                    "Could not resolve the finding. "
                                    f"API response: {error}"
                                )
                            else:
                                st.success(
                                    "Resolution request completed."
                                )

                                st.json(result)

                                st.cache_data.clear()
                                st.rerun()

            else:
                st.success(
                    f"This finding is marked {status}."
                )

                if finding.get("resolution_note"):
                    st.markdown("**Resolution notes**")
                    st.write(finding["resolution_note"])


# ============================================================
# CONTROLS PAGE
# ============================================================

elif page == "Controls":

    st.subheader("Compliance Controls")

    st.markdown(
        """
        Review the policies used by the compliance engine.
        Control changes are sent to the existing backend API.
        """
    )

    if controls_error:
        st.error(f"Could not load controls: {controls_error}")
        st.stop()

    if not controls:
        st.info("No controls were returned by the API.")
        st.stop()

    for index, control in enumerate(controls):

        control_id = first_value(
            control, "control_id", "id"
        )

        name = first_value(
            control, "name", "title"
        )

        with st.expander(
            f"{control_id} — {name}",
            expanded=True,
        ):

            st.json(control)

            enabled_value = first_value(
                control,
                "enabled",
                "is_enabled",
                default=True,
            )

            if isinstance(enabled_value, str):
                enabled_value = (
                    enabled_value.strip().lower()
                    in ("true", "1", "yes", "enabled")
                )

            enabled_value = bool(enabled_value)

            threshold_value = first_value(
                control,
                "threshold_hours",
                "expected_hours",
                "deadline_hours",
                default=24,
            )

            try:
                threshold_value = int(float(threshold_value))
            except (ValueError, TypeError):
                threshold_value = 24

            with st.form(f"control_form_{control_id}_{index}"):

                new_enabled = st.checkbox(
                    "Control enabled",
                    value=enabled_value,
                    key=f"enabled_{control_id}_{index}",
                )

                new_threshold = st.number_input(
                    "Threshold (hours)",
                    min_value=1,
                    max_value=8760,
                    value=max(1, min(8760, threshold_value)),
                    step=1,
                    key=f"threshold_{control_id}_{index}",
                )

                save_control = st.form_submit_button(
                    "Save control settings",
                    use_container_width=True,
                )

                if save_control:

                    payload = {
                        "enabled": new_enabled,
                        "threshold_hours": int(new_threshold),
                    }

                    result, error = api_patch(
                        f"/controls/{control_id}",
                        payload,
                    )

                    if error:
                        st.error(
                            "Could not update the control. "
                            f"API response: {error}"
                        )
                    else:
                        st.success("Control settings updated.")
                        st.json(result)
                        st.rerun()


# ============================================================
# EVENTS PAGE
# ============================================================

elif page == "Events":

    st.subheader("Security Event Stream")

    st.markdown(
        """
        Review the events ingested by Compliance Sentinel.
        These events provide the input used to evaluate compliance.
        """
    )

    if events_error:
        st.error(f"Could not retrieve events: {events_error}")
        st.stop()

    if not events:
        st.info("No events were returned by the API.")
        st.stop()

    event_rows = []

    for event in events:
        event_rows.append(
            {
                "Timestamp": format_timestamp(
                    first_value(
                        event,
                        "timestamp",
                        "created_at",
                        "event_time",
                    )
                ),
                "Event Type": first_value(
                    event, "event_type", "type"
                ),
                "System": first_value(
                    event, "system", "source"
                ),
                "Employee": first_value(
                    event,
                    "employee_id",
                    "user_id",
                ),
                "Account": first_value(
                    event,
                    "account_id",
                    "username",
                ),
                "Details": first_value(
                    event,
                    "details",
                    "description",
                    "message",
                ),
            }
        )

    events_df = pd.DataFrame(event_rows)

    search_events = st.text_input(
        "Search events",
        placeholder="Search by system, event type, user...",
    )

    if search_events:
        mask = events_df.astype(str).apply(
            lambda column: column.str.contains(
                search_events,
                case=False,
                na=False,
                regex=False,
            )
        ).any(axis=1)

        events_df = events_df[mask]

    st.caption(f"{len(events_df)} events")

    st.dataframe(
        events_df,
        use_container_width=True,
        hide_index=True,
    )

    with st.expander("Inspect raw event data"):
        st.json(events)


# ============================================================
# AUDIT TRAIL PAGE
# ============================================================

elif page == "Audit Trail":

    st.subheader("Audit Trail")

    st.markdown(
        """
        Review recorded system actions, including finding-resolution
        activity when supported by the backend audit log.
        """
    )

    if audit_error:
        st.error(f"Could not retrieve audit log: {audit_error}")
        st.stop()

    if not audit_entries:
        st.info(
            "No audit entries have been returned. "
            "Entries will appear when the backend records auditable actions."
        )
        st.stop()

    audit_rows = []

    for entry in audit_entries:
        audit_rows.append(
            {
                "Timestamp": format_timestamp(
                    first_value(
                        entry,
                        "timestamp",
                        "created_at",
                        "event_time",
                    )
                ),
                "Action": first_value(
                    entry,
                    "action",
                    "action_type",
                    "event_type",
                    "operation",
                ),
                "Entity": first_value(
                    entry,
                    "entity_type",
                    "resource_type",
                    "entity",
                ),
                "Entity ID": first_value(
                    entry,
                    "entity_id",
                    "resource_id",
                    "finding_id",
                ),
                "Details": first_value(
                    entry,
                    "details",
                    "message",
                    "description",
                    "resolution_note",
                ),
            }
        )

    audit_df = pd.DataFrame(audit_rows)

    search_audit = st.text_input(
        "Search audit records",
        placeholder="Action, entity, ID, details...",
    )

    if search_audit:
        mask = audit_df.astype(str).apply(
            lambda column: column.str.contains(
                search_audit,
                case=False,
                na=False,
                regex=False,
            )
        ).any(axis=1)

        audit_df = audit_df[mask]

    st.caption(f"{len(audit_df)} audit records")

    st.dataframe(
        audit_df,
        use_container_width=True,
        hide_index=True,
    )

    with st.expander("Inspect raw audit records"):
        st.json(audit_entries)


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Compliance Sentinel | Continuous Compliance Drift Detection "
    "| FastAPI + SQLite + Streamlit"
)