import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import requests


BASE_URL = os.getenv(
    "COMPLIANCE_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

TIMEOUT = 10


# ============================================================
# HELPERS
# ============================================================

def unique_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def send_event(
    event_type,
    employee_id,
    system_name,
    event_time,
    **kwargs,
):
    payload = {
        "event_type": event_type,
        "employee_id": employee_id,
        "system_name": system_name,
        "event_time": event_time.isoformat(),
        **kwargs,
    }

    response = requests.post(
        f"{BASE_URL}/events",
        json=payload,
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, (
        f"Event ingestion failed: "
        f"{response.status_code} {response.text}"
    )

    return response.json()


def get_findings():
    response = requests.get(
        f"{BASE_URL}/findings",
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert isinstance(data, list), (
        "Expected /findings to return a list."
    )

    return data


def get_audit_log():
    response = requests.get(
        f"{BASE_URL}/audit-log",
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert isinstance(data, list), (
        "Expected /audit-log to return a list."
    )

    return data


def find_open_finding(control_id, employee_id, system_name):
    return [
        finding
        for finding in get_findings()
        if finding.get("control_id") == control_id
        and finding.get("employee_id") == employee_id
        and finding.get("system_name") == system_name
        and str(finding.get("status", "")).upper() == "OPEN"
    ]


def set_control_deadline(control_id, deadline_hours):
    response = requests.patch(
        f"{BASE_URL}/controls/{control_id}",
        json={
            "deadline_hours": deadline_hours,
            "enabled": True,
        },
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, (
        f"Could not configure {control_id}: "
        f"{response.status_code} {response.text}"
    )


# ============================================================
# BASIC API TESTS
# ============================================================

def test_api_health():
    response = requests.get(
        f"{BASE_URL}/health",
        timeout=TIMEOUT,
    )

    assert response.status_code == 200
    assert response.json().get("status") == "ok"


def test_controls_endpoint():
    response = requests.get(
        f"{BASE_URL}/controls",
        timeout=TIMEOUT,
    )

    assert response.status_code == 200

    controls = response.json()
    assert isinstance(controls, list)

    control_ids = {control.get("id") for control in controls}

    assert {"AC-01", "AC-02", "CM-01"}.issubset(control_ids)


def test_findings_endpoint():
    response = requests.get(
        f"{BASE_URL}/findings",
        timeout=TIMEOUT,
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_events_endpoint():
    response = requests.get(
        f"{BASE_URL}/events",
        timeout=TIMEOUT,
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_audit_log_endpoint():
    response = requests.get(
        f"{BASE_URL}/audit-log",
        timeout=TIMEOUT,
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


# ============================================================
# AC-01: ACCESS REVOCATION
# ============================================================

def test_ac01_detects_and_resolves_active_terminated_employee():
    employee = unique_id("TEST-EMP")
    system = unique_id("TEST-AWS")

    set_control_deadline("AC-01", 1)

    now = datetime.now(timezone.utc)

    termination_time = now - timedelta(hours=4)
    active_time = now - timedelta(hours=2)

    # Event 1: Employee is terminated.
    send_event(
        event_type="employee_terminated",
        employee_id=employee,
        system_name="HR",
        event_time=termination_time,
    )

    # Event 2: Their account is still active after the deadline.
    send_event(
        event_type="account_status",
        employee_id=employee,
        system_name=system,
        event_time=active_time,
        account_status="active",
    )

    findings = find_open_finding(
        "AC-01",
        employee,
        system,
    )

    assert findings, (
        "AC-01 failed to detect active access after termination."
    )

    finding = findings[0]

    assert finding.get("severity") == "HIGH"
    assert finding.get("evidence") is not None

    # Event 3: Corrective action disables the account.
    result = send_event(
        event_type="account_status",
        employee_id=employee,
        system_name=system,
        event_time=now + timedelta(seconds=1),
        account_status="disabled",
    )

    assert not find_open_finding(
        "AC-01",
        employee,
        system,
    ), "AC-01 finding remained open after account disablement."

    assert any(
        item.get("status") == "RESOLVED"
        for item in result.get("evaluation", [])
    ), "AC-01 did not report successful resolution."


# ============================================================
# AC-02: PRIVILEGED ACCOUNT OWNERSHIP
# ============================================================

def test_ac02_detects_and_resolves_missing_account_owner():
    employee = unique_id("TEST-ADMIN")
    system = unique_id("TEST-CLOUD")

    now = datetime.now(timezone.utc)

    # Event 1: Privileged account has no owner.
    send_event(
        event_type="privileged_account",
        employee_id=employee,
        system_name=system,
        event_time=now,
        privileged=True,
        owner=None,
    )

    findings = find_open_finding(
        "AC-02",
        employee,
        system,
    )

    assert findings, (
        "AC-02 failed to detect a privileged account without an owner."
    )

    finding = findings[0]

    assert finding.get("severity") == "HIGH"
    assert finding.get("evidence") is not None

    # Event 2: Corrective action assigns an owner.
    result = send_event(
        event_type="privileged_account",
        employee_id=employee,
        system_name=system,
        event_time=now + timedelta(seconds=1),
        privileged=True,
        owner="compliance-test-owner",
    )

    assert not find_open_finding(
        "AC-02",
        employee,
        system,
    ), "AC-02 finding remained open after owner assignment."

    assert any(
        item.get("status") == "RESOLVED"
        for item in result.get("evaluation", [])
    ), "AC-02 did not report successful resolution."


# ============================================================
# CM-01: CRITICAL CLOUD CHANGE REVIEW
# ============================================================

def test_cm01_detects_and_resolves_unreviewed_critical_change():
    employee = unique_id("TEST-CHANGE")
    system = unique_id("TEST-CLOUD")
    change_id = unique_id("TEST-CHG")

    now = datetime.now(timezone.utc)

    # Configure a zero-hour deadline for this test.
    set_control_deadline("CM-01", 0)

    # Event 1: A critical cloud change happened two hours ago.
    send_event(
        event_type="cloud_change",
        employee_id=employee,
        system_name=system,
        event_time=now - timedelta(hours=2),
        change_id=change_id,
        change_description="Automated compliance integration test",
        critical=True,
        review_status="pending",
    )

    findings = find_open_finding(
        "CM-01",
        change_id,
        system,
    )

    assert findings, (
        "CM-01 failed to detect the unreviewed critical cloud change."
    )

    finding = findings[0]

    assert finding.get("severity") == "CRITICAL"
    assert finding.get("evidence") is not None

    # Event 2: The same cloud change is reviewed.
    result = send_event(
        event_type="cloud_change_review",
        employee_id=employee,
        system_name=system,
        event_time=now + timedelta(seconds=1),
        change_id=change_id,
        review_status="reviewed",
    )

    assert not find_open_finding(
        "CM-01",
        change_id,
        system,
    ), "CM-01 finding remained open after review."

    assert any(
        item.get("status") == "RESOLVED"
        for item in result.get("evaluation", [])
    ), "CM-01 did not report successful resolution."


# ============================================================
# AUDIT TRAIL VERIFICATION
# ============================================================

def test_audit_log_endpoint_returns_list():
    entries = get_audit_log()

    assert isinstance(entries, list)