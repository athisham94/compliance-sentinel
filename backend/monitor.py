"""
Compliance Sentinel — Continuous Monitoring Engine

Periodically reevaluates stored compliance events without requiring
new events to arrive.

Uses the existing SQLite database and finding lifecycle.
"""

import json
import logging
from datetime import datetime, timezone

from backend.main import (
    connect,
    parse_dt,
    evaluate_employee,
    resolve_findings,
)

logger = logging.getLogger("compliance_sentinel.monitor")


def utc_now():
    return datetime.now(timezone.utc)


def _run_compliance_monitor():
    """
    Run one monitoring cycle.

    AC-01:
        Reevaluate employees with termination or account-status events.

    AC-02:
        Reevaluate the latest privileged-account state for each
        employee/system pair.

    CM-01:
        Reevaluate critical cloud changes against the configured
        review deadline.
    """
    logger.info("Starting compliance monitoring cycle.")

    results = {
        "ac01_evaluated": 0,
        "ac02_evaluated": 0,
        "cm01_evaluated": 0,
        "errors": [],
    }

    # --------------------------------------------------------
    # AC-01: Access revocation
    # --------------------------------------------------------

    with connect() as con:
        employees = con.execute("""
            SELECT DISTINCT employee_id
            FROM events
            WHERE event_type IN (
                'employee_terminated',
                'account_status'
            )
              AND employee_id IS NOT NULL
        """).fetchall()

    for row in employees:
        employee_id = row["employee_id"]

        try:
            evaluate_employee(employee_id)
            results["ac01_evaluated"] += 1

        except Exception as exc:
            logger.exception(
                "AC-01 monitoring failed for employee %s",
                employee_id,
            )
            results["errors"].append({
                "control_id": "AC-01",
                "employee_id": employee_id,
                "error": str(exc),
            })

    # --------------------------------------------------------
    # AC-02: Privileged account ownership
    # --------------------------------------------------------

    with connect() as con:
        privileged_events = con.execute("""
            SELECT id, employee_id, system_name, event_time, payload
            FROM events
            WHERE event_type = 'privileged_account'
            ORDER BY event_time ASC, id ASC
        """).fetchall()

    latest_privileged = {}

    for row in privileged_events:
        key = (row["employee_id"], row["system_name"])
        latest_privileged[key] = row

    for row in latest_privileged.values():
        try:
            payload = json.loads(row["payload"])

            if payload.get("privileged") is not True:
                continue

            employee_id = row["employee_id"] or "UNKNOWN"
            system_name = row["system_name"]
            owner = payload.get("owner")

            if owner and str(owner).strip():
                resolve_findings(
                    "AC-02",
                    employee_id,
                    system_name,
                    "Monitoring confirmed an assigned account owner.",
                    {"owner": owner, "event_id": row["id"]},
                )

            else:
                from backend.main import create_finding

                create_finding(
                    "AC-02",
                    employee_id,
                    system_name,
                    "HIGH",
                    0,
                    0,
                    {
                        "event_id": row["id"],
                        "event_time": row["event_time"],
                        "privileged": True,
                        "owner": owner,
                        "source": "continuous_monitor",
                    },
                    (
                        f"Assign an accountable owner to the "
                        f"privileged account in {system_name}."
                    ),
                )

            results["ac02_evaluated"] += 1

        except Exception as exc:
            logger.exception(
                "AC-02 monitoring failed for event %s",
                row["id"],
            )
            results["errors"].append({
                "control_id": "AC-02",
                "event_id": row["id"],
                "error": str(exc),
            })

    # --------------------------------------------------------
    # CM-01: Critical cloud change review
    # --------------------------------------------------------

    with connect() as con:
        changes = con.execute("""
            SELECT id, employee_id, system_name, event_time, payload
            FROM events
            WHERE event_type = 'cloud_change'
            ORDER BY event_time ASC, id ASC
        """).fetchall()

        control = con.execute("""
            SELECT enabled, deadline_hours
            FROM controls
            WHERE id = 'CM-01'
        """).fetchone()

        review_rows = con.execute("""
            SELECT id, system_name, event_time, payload
            FROM events
            WHERE event_type = 'cloud_change_review'
            ORDER BY event_time ASC, id ASC
        """).fetchall()

    reviews_by_change = {}

    for review in review_rows:
        review_payload = json.loads(review["payload"])
        change_id = review_payload.get("change_id")

        if not change_id:
            continue

        if str(review_payload.get("review_status", "")).lower() != "reviewed":
            continue

        key = (review["system_name"], change_id)

        reviews_by_change.setdefault(key, []).append(
            parse_dt(review["event_time"])
        )

    if control and control["enabled"]:
        deadline_hours = int(control["deadline_hours"])
        current_time = utc_now()

        from backend.main import create_finding

        for row in changes:
            try:
                payload = json.loads(row["payload"])

                if payload.get("critical") is not True:
                    continue

                change_time = parse_dt(row["event_time"])
                elapsed_hours = (
                    current_time - change_time
                ).total_seconds() / 3600

                if elapsed_hours <= deadline_hours:
                    continue

                change_id = payload.get("change_id")
                if not change_id:
                    change_id = f"event-{row['id']}"

                review_times = reviews_by_change.get(
                    (row["system_name"], change_id),
                    [],
                )

                reviewed = any(
                    review_time >= change_time
                    for review_time in review_times
                )

                if reviewed:
                    resolve_findings(
                        "CM-01",
                        change_id,
                        row["system_name"],
                        "Monitoring confirmed that the cloud change was reviewed.",
                        {"change_id": change_id},
                    )
                    continue

                create_finding(
                    "CM-01",
                    change_id,
                    row["system_name"],
                    "CRITICAL",
                    elapsed_hours,
                    deadline_hours,
                    {
                        "event_id": row["id"],
                        "change_id": change_id,
                        "change_description": payload.get(
                            "change_description"
                        ),
                        "critical": True,
                        "change_time": row["event_time"],
                        "review_status": "unreviewed",
                        "elapsed_hours": round(elapsed_hours, 2),
                        "source": "continuous_monitor",
                    },
                    (
                        "Review the critical cloud change immediately "
                        "and revert or mitigate it if unauthorized."
                    ),
                )

                results["cm01_evaluated"] += 1

            except Exception as exc:
                logger.exception(
                    "CM-01 monitoring failed for event %s",
                    row["id"],
                )
                results["errors"].append({
                    "control_id": "CM-01",
                    "event_id": row["id"],
                    "error": str(exc),
                })

    logger.info(
        "Monitoring cycle complete: %s",
        results,
    )

    return results


def run_compliance_monitor():
    """
    Execute one monitoring cycle and persist its outcome.

    A cycle with control-level errors is recorded as PARTIAL.
    An unexpected exception is recorded as FAILED and then re-raised.
    """

    started_at = utc_now().isoformat()

    with connect() as con:
        cursor = con.execute(
            """
            INSERT INTO monitoring_runs (
                started_at, status, errors, summary
            )
            VALUES (?, 'RUNNING', '[]', '{}')
            """,
            (started_at,),
        )
        run_id = cursor.lastrowid

    try:
        results = _run_compliance_monitor()

        errors = results.get("errors", [])
        status = "PARTIAL" if errors else "SUCCESS"
        completed_at = utc_now().isoformat()

        summary = {
            "ac01_evaluated": results.get("ac01_evaluated", 0),
            "ac02_evaluated": results.get("ac02_evaluated", 0),
            "cm01_evaluated": results.get("cm01_evaluated", 0),
        }

        with connect() as con:
            con.execute(
                """
                UPDATE monitoring_runs
                SET completed_at = ?,
                    status = ?,
                    ac01_evaluated = ?,
                    ac02_evaluated = ?,
                    cm01_evaluated = ?,
                    error_count = ?,
                    errors = ?,
                    summary = ?
                WHERE id = ?
                """,
                (
                    completed_at,
                    status,
                    summary["ac01_evaluated"],
                    summary["ac02_evaluated"],
                    summary["cm01_evaluated"],
                    len(errors),
                    json.dumps(errors),
                    json.dumps(summary),
                    run_id,
                ),
            )

        logger.info(
            "Monitoring run %s finished with status %s",
            run_id,
            status,
        )
        return {**results, "run_id": run_id, "status": status}

    except Exception as exc:
        completed_at = utc_now().isoformat()
        errors = [{"error": str(exc)}]

        with connect() as con:
            con.execute(
                """
                UPDATE monitoring_runs
                SET completed_at = ?,
                    status = 'FAILED',
                    error_count = 1,
                    errors = ?
                WHERE id = ?
                """,
                (completed_at, json.dumps(errors), run_id),
            )

        logger.exception("Monitoring run %s failed", run_id)
        raise
