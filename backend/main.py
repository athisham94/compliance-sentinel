from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import logging
import os

from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler


# ============================================================
# CONFIGURATION
# ============================================================

DB_PATH = Path(__file__).resolve().parent.parent / "compliance_sentinel.db"

app = FastAPI(
    title="Compliance Sentinel API",
    version="1.0.0",
    description="Continuous compliance drift detection and remediation tracking.",
)


# ============================================================
# DATABASE
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def parse_dt(value):
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            employee_id TEXT,
            system_name TEXT NOT NULL,
            event_time TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS controls (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            deadline_hours INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_id TEXT NOT NULL,
            employee_id TEXT NOT NULL,
            system_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            termination_time TEXT,
            detected_at TEXT NOT NULL,
            elapsed_hours REAL NOT NULL DEFAULT 0,
            expected_hours INTEGER NOT NULL DEFAULT 0,
            evidence TEXT NOT NULL DEFAULT '{}',
            recommendation TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

        # Migrate older findings tables without deleting existing records.
        columns = {
            row["name"]
            for row in con.execute("PRAGMA table_info(findings)").fetchall()
        }

        additions = {
            "termination_time": "TEXT",
            "resolved_at": "TEXT",
            "resolution_note": "TEXT",
        }

        for column, definition in additions.items():
            if column not in columns:
                con.execute(
                    f"ALTER TABLE findings ADD COLUMN {column} {definition}"
                )

        columns = {
            row["name"]
            for row in con.execute("PRAGMA table_info(findings)").fetchall()
        }

        if "termination_time" in columns:
            con.execute("""
                UPDATE findings
                SET termination_time = detected_at
                WHERE termination_time IS NULL OR termination_time = ''
            """)

        controls = [
            (
                "AC-01",
                "Timely access revocation",
                "Revoke employee access within the configured deadline after termination.",
                24,
                1,
            ),
            (
                "AC-02",
                "Privileged account ownership",
                "Every privileged account must have an assigned owner.",
                0,
                1,
            ),
            (
                "CM-01",
                "Critical cloud change review",
                "Critical cloud configuration changes must be reviewed within the configured deadline.",
                1,
                1,
            ),
        ]

        for control in controls:
            con.execute("""
                INSERT OR IGNORE INTO controls
                (id, name, description, deadline_hours, enabled)
                VALUES (?, ?, ?, ?, ?)
            """, control)


init_db()



# ============================================================
# CONTINUOUS COMPLIANCE MONITORING
# ============================================================

logger = logging.getLogger("compliance_sentinel.monitor")

MONITOR_INTERVAL_SECONDS = int(
    os.getenv("COMPLIANCE_MONITOR_INTERVAL_SECONDS", "60")
)


def run_compliance_monitor():
    """
    Reevaluate stored events periodically.

    Uses the existing detection functions so findings continue
    to use the same database schema and lifecycle logic.
    """
    try:
        with connect() as con:
            employee_rows = con.execute("""
                SELECT DISTINCT employee_id
                FROM events
                WHERE event_type IN (
                    'employee_terminated',
                    'account_status'
                )
                  AND employee_id IS NOT NULL
            """).fetchall()

            privileged_rows = con.execute("""
                SELECT id, employee_id, system_name, event_time, payload
                FROM events
                WHERE event_type = 'privileged_account'
                ORDER BY id
            """).fetchall()

            change_rows = con.execute("""
                SELECT id, employee_id, system_name, event_time, payload
                FROM events
                WHERE event_type = 'cloud_change'
                ORDER BY id
            """).fetchall()

        # AC-01: Check employees whose accounts may remain active.
        for row in employee_rows:
            employee_id = row["employee_id"]

            try:
                evaluate_employee(employee_id)
            except Exception:
                logger.exception(
                    "AC-01 evaluation failed for employee %s",
                    employee_id,
                )

        # AC-02: Reevaluate the latest privileged-account state
        # for each employee/system combination.
        latest_privileged = {}

        for row in privileged_rows:
            key = (row["employee_id"], row["system_name"])
            latest_privileged[key] = row

        for row in latest_privileged.values():
            try:
                payload = json.loads(row["payload"])

                if payload.get("privileged") is True:
                    if not payload.get("owner"):
                        # Reuse the existing evaluator by creating
                        # an EventIn instance from the stored event.
                        event = EventIn(
                            event_type="privileged_account",
                            employee_id=row["employee_id"] or "UNKNOWN",
                            system_name=row["system_name"],
                            event_time=parse_dt(row["event_time"]),
                            privileged=True,
                            owner=payload.get("owner"),
                            details=payload,
                        )

                        evaluate_privileged_account(event, row["id"])

            except Exception:
                logger.exception(
                    "AC-02 evaluation failed for event %s",
                    row["id"],
                )

        # CM-01: Reevaluate critical changes against their review status
        # and the current configured deadline.
        for row in change_rows:
            try:
                payload = json.loads(row["payload"])

                if payload.get("critical") is True:
                    event = EventIn(
                        event_type="cloud_change",
                        employee_id=row["employee_id"] or "UNKNOWN",
                        system_name=row["system_name"],
                        event_time=parse_dt(row["event_time"]),
                        change_id=payload.get("change_id"),
                        change_description=payload.get(
                            "change_description"
                        ),
                        critical=True,
                        review_status=payload.get("review_status"),
                        details=payload,
                    )

                    evaluate_cloud_change(event, row["id"])

            except Exception:
                logger.exception(
                    "CM-01 evaluation failed for event %s",
                    row["id"],
                )

        logger.info("Continuous compliance evaluation completed.")

    except Exception:
        logger.exception("Continuous compliance monitoring failed.")


# ============================================================
# SCHEDULER LIFECYCLE
# ============================================================

scheduler = BackgroundScheduler(timezone="UTC")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    scheduler.add_job(
        run_compliance_monitor,
        trigger="interval",
        seconds=MONITOR_INTERVAL_SECONDS,
        id="continuous_compliance_monitor",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    if not scheduler.running:
        scheduler.start()

    logger.info(
        "Continuous compliance monitor started; interval=%s seconds.",
        MONITOR_INTERVAL_SECONDS,
    )

    try:
        yield
    finally:
        if scheduler.running:
            scheduler.shutdown(wait=False)


app.router.lifespan_context = lifespan


# ============================================================
# REQUEST MODELS
# ============================================================

class EventIn(BaseModel):
    event_type: str
    employee_id: str = "UNKNOWN"
    system_name: str = "HR"
    event_time: datetime

    account_status: Optional[str] = None
    privileged: Optional[bool] = None
    owner: Optional[str] = None

    change_id: Optional[str] = None
    change_description: Optional[str] = None
    critical: Optional[bool] = None
    review_status: Optional[str] = None

    details: dict = Field(default_factory=dict)


class ControlUpdate(BaseModel):
    deadline_hours: int = Field(..., ge=0, le=720)
    enabled: Optional[bool] = None


class ResolveRequest(BaseModel):
    note: str = Field(
        default="Reviewed and resolved by operator.",
        max_length=500,
    )


# ============================================================
# AUDIT LOG
# ============================================================

def audit(finding_id, action, details):
    with connect() as con:
        con.execute("""
            INSERT INTO audit_log
            (finding_id, action, details, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            finding_id,
            action,
            json.dumps(details),
            now_iso(),
        ))


# ============================================================
# EVENT STORAGE
# ============================================================

def event_payload(event):
    return {
        "account_status": event.account_status,
        "privileged": event.privileged,
        "owner": event.owner,
        "change_id": event.change_id,
        "change_description": event.change_description,
        "critical": event.critical,
        "review_status": event.review_status,
        **event.details,
    }


def save_event(event):
    payload = event_payload(event)

    with connect() as con:
        cursor = con.execute("""
            INSERT INTO events
            (event_type, employee_id, system_name, event_time, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            event.event_type,
            event.employee_id,
            event.system_name,
            event.event_time.isoformat(),
            json.dumps(payload),
            now_iso(),
        ))

        return cursor.lastrowid


# ============================================================
# FINDING LIFECYCLE
# ============================================================

def create_finding(
    control_id,
    employee_id,
    system_name,
    severity,
    elapsed,
    expected,
    evidence,
    recommendation,
):
    termination_time = (
        evidence.get("termination_time")
        or evidence.get("change_time")
        or evidence.get("event_time")
        or now_iso()
    )

    with connect() as con:
        existing = con.execute("""
            SELECT id
            FROM findings
            WHERE control_id = ?
              AND employee_id = ?
              AND system_name = ?
              AND status = 'OPEN'
            ORDER BY id DESC
            LIMIT 1
        """, (
            control_id,
            employee_id,
            system_name,
        )).fetchone()

        if existing:
            finding_id = existing["id"]

            con.execute("""
                UPDATE findings
                SET severity = ?,
                    termination_time = ?,
                    detected_at = ?,
                    elapsed_hours = ?,
                    expected_hours = ?,
                    evidence = ?,
                    recommendation = ?
                WHERE id = ?
            """, (
                severity,
                termination_time,
                now_iso(),
                round(elapsed, 2),
                expected,
                json.dumps(evidence),
                recommendation,
                finding_id,
            ))

            return finding_id

        cursor = con.execute("""
            INSERT INTO findings (
                control_id,
                employee_id,
                system_name,
                severity,
                status,
                termination_time,
                detected_at,
                elapsed_hours,
                expected_hours,
                evidence,
                recommendation
            )
            VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?)
        """, (
            control_id,
            employee_id,
            system_name,
            severity,
            termination_time,
            now_iso(),
            round(elapsed, 2),
            expected,
            json.dumps(evidence),
            recommendation,
        ))

        finding_id = cursor.lastrowid

    audit(
        finding_id,
        "DETECTED",
        {"control_id": control_id, "severity": severity},
    )

    return finding_id


def resolve_findings(control_id, employee_id, system_name, note, evidence=None):
    with connect() as con:
        findings = con.execute("""
            SELECT id
            FROM findings
            WHERE control_id = ?
              AND employee_id = ?
              AND system_name = ?
              AND status = 'OPEN'
        """, (
            control_id,
            employee_id,
            system_name,
        )).fetchall()

        for finding in findings:
            con.execute("""
                UPDATE findings
                SET status = 'RESOLVED',
                    resolved_at = ?,
                    resolution_note = ?
                WHERE id = ?
            """, (
                now_iso(),
                note,
                finding["id"],
            ))

    for finding in findings:
        audit(
            finding["id"],
            "AUTO_RESOLVED",
            {"note": note, "evidence": evidence or {}},
        )

    return len(findings)


# ============================================================
# AC-01: ACCESS REVOCATION
# ============================================================

def evaluate_employee(employee_id):
    with connect() as con:
        termination = con.execute("""
            SELECT *
            FROM events
            WHERE employee_id = ?
              AND event_type = 'employee_terminated'
            ORDER BY event_time DESC, id DESC
            LIMIT 1
        """, (employee_id,)).fetchone()

        control = con.execute("""
            SELECT *
            FROM controls
            WHERE id = 'AC-01'
        """).fetchone()

        account_events = con.execute("""
            SELECT *
            FROM events
            WHERE employee_id = ?
              AND event_type = 'account_status'
            ORDER BY event_time, id
        """, (employee_id,)).fetchall()

    if not termination or not control or not control["enabled"]:
        return []

    termination_dt = parse_dt(termination["event_time"])
    deadline = int(control["deadline_hours"])

    latest_status = {}

    for row in account_events:
        if parse_dt(row["event_time"]) >= termination_dt:
            latest_status[row["system_name"]] = row

    results = []

    for system, row in latest_status.items():
        payload = json.loads(row["payload"])
        status = str(payload.get("account_status", "unknown")).lower()

        observed_dt = parse_dt(row["event_time"])
        elapsed = (observed_dt - termination_dt).total_seconds() / 3600

        evidence = {
            "termination_event_id": termination["id"],
            "account_event_id": row["id"],
            "termination_time": termination["event_time"],
            "observed_time": row["event_time"],
            "account_status": status,
        }

        if status == "active" and elapsed > deadline:
            finding_id = create_finding(
                "AC-01",
                employee_id,
                system,
                "HIGH",
                elapsed,
                deadline,
                evidence,
                (
                    f"Disable {system} access for {employee_id}; "
                    "revoke active sessions and rotate exposed "
                    "credentials if applicable."
                ),
            )

            results.append({
                "finding_id": finding_id,
                "control_id": "AC-01",
                "system_name": system,
                "status": "DRIFT_FOUND",
            })

        elif status == "disabled":
            count = resolve_findings(
                "AC-01",
                employee_id,
                system,
                "Account-status event confirms access is disabled.",
                evidence,
            )

            if count:
                results.append({
                    "control_id": "AC-01",
                    "system_name": system,
                    "status": "RESOLVED",
                    "resolved_count": count,
                })

    return results


# ============================================================
# AC-02: PRIVILEGED ACCOUNT OWNERSHIP
# ============================================================

def evaluate_privileged_account(event, event_id):
    if event.privileged is not True:
        return []

    if event.owner and event.owner.strip():
        count = resolve_findings(
            "AC-02",
            event.employee_id,
            event.system_name,
            "An accountable owner has been assigned.",
            {"event_id": event_id, "owner": event.owner},
        )

        if count:
            return [{
                "control_id": "AC-02",
                "status": "RESOLVED",
                "resolved_count": count,
            }]

        return []

    evidence = {
        "event_id": event_id,
        "event_time": event.event_time.isoformat(),
        "privileged": True,
        "owner": event.owner,
        "details": event.details,
    }

    finding_id = create_finding(
        "AC-02",
        event.employee_id,
        event.system_name,
        "HIGH",
        0,
        0,
        evidence,
        f"Assign an accountable owner to the privileged account in {event.system_name}.",
    )

    return [{
        "finding_id": finding_id,
        "control_id": "AC-02",
        "status": "DRIFT_FOUND",
    }]


# ============================================================
# CM-01: CRITICAL CLOUD CHANGE REVIEW
# ============================================================

def evaluate_cloud_change(event, event_id):
    if event.critical is not True:
        return []

    with connect() as con:
        control = con.execute("""
            SELECT *
            FROM controls
            WHERE id = 'CM-01'
        """).fetchone()

        reviews = con.execute("""
            SELECT *
            FROM events
            WHERE event_type = 'cloud_change_review'
              AND system_name = ?
            ORDER BY event_time DESC, id DESC
        """, (event.system_name,)).fetchall()

    if not control or not control["enabled"]:
        return []

    reviewed = False

    for review in reviews:
        payload = json.loads(review["payload"])

        if (
            event.change_id
            and payload.get("change_id") == event.change_id
            and str(payload.get("review_status", "")).lower() == "reviewed"
            and parse_dt(review["event_time"]) >= parse_dt(
                event.event_time.isoformat()
            )
        ):
            reviewed = True
            break

    elapsed = max(
        0,
        (
            datetime.now(timezone.utc)
            - parse_dt(event.event_time.isoformat())
        ).total_seconds() / 3600,
    )

    deadline = int(control["deadline_hours"])
    change_key = event.change_id or f"event-{event_id}"

    if reviewed:
        count = resolve_findings(
            "CM-01",
            change_key,
            event.system_name,
            "Matching cloud-change review was received.",
        )

        if count:
            return [{
                "control_id": "CM-01",
                "status": "RESOLVED",
                "resolved_count": count,
            }]

        return []

    if elapsed <= deadline:
        return []

    evidence = {
        "event_id": event_id,
        "change_id": event.change_id,
        "change_description": event.change_description,
        "critical": True,
        "change_time": event.event_time.isoformat(),
        "review_status": "unreviewed",
        "elapsed_hours": round(elapsed, 2),
    }

    finding_id = create_finding(
        "CM-01",
        change_key,
        event.system_name,
        "CRITICAL",
        elapsed,
        deadline,
        evidence,
        "Review the critical cloud change immediately and revert or mitigate it if unauthorized.",
    )

    return [{
        "finding_id": finding_id,
        "control_id": "CM-01",
        "status": "DRIFT_FOUND",
    }]


def evaluate_late_cloud_review(event):
    if str(event.review_status).lower() != "reviewed":
        return []

    if not event.change_id:
        return []

    with connect() as con:
        changes = con.execute("""
            SELECT *
            FROM events
            WHERE event_type = 'cloud_change'
              AND system_name = ?
            ORDER BY event_time DESC
        """, (event.system_name,)).fetchall()

    for change in changes:
        payload = json.loads(change["payload"])

        if (
            payload.get("change_id") == event.change_id
            and payload.get("critical") is True
            and parse_dt(event.event_time.isoformat())
            >= parse_dt(change["event_time"])
        ):
            count = resolve_findings(
                "CM-01",
                event.change_id,
                event.system_name,
                "A matching cloud-change review was received.",
                {"change_id": event.change_id},
            )

            if count:
                return [{
                    "control_id": "CM-01",
                    "change_id": event.change_id,
                    "status": "RESOLVED",
                    "resolved_count": count,
                }]

    return []


# ============================================================
# EVENT ROUTER
# ============================================================

def evaluate_all(event, event_id):
    if event.event_type in {"employee_terminated", "account_status"}:
        return evaluate_employee(event.employee_id)

    if event.event_type == "privileged_account":
        return evaluate_privileged_account(event, event_id)

    if event.event_type == "cloud_change":
        return evaluate_cloud_change(event, event_id)

    if event.event_type == "cloud_change_review":
        return evaluate_late_cloud_review(event)

    return []


# ============================================================
# API
# ============================================================

@app.get("/")
def root():
    return {
        "service": "Compliance Sentinel API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "Compliance Sentinel API",
        "time": now_iso(),
    }


@app.get("/controls")
def get_controls():
    with connect() as con:
        return [
            dict(row)
            for row in con.execute(
                "SELECT * FROM controls ORDER BY id"
            ).fetchall()
        ]


@app.patch("/controls/{control_id}")
def update_control(control_id: str, body: ControlUpdate):
    with connect() as con:
        existing = con.execute(
            "SELECT id FROM controls WHERE id = ?",
            (control_id,),
        ).fetchone()

        if not existing:
            raise HTTPException(404, "Control not found.")

        if body.enabled is None:
            con.execute("""
                UPDATE controls
                SET deadline_hours = ?
                WHERE id = ?
            """, (body.deadline_hours, control_id))
        else:
            con.execute("""
                UPDATE controls
                SET deadline_hours = ?, enabled = ?
                WHERE id = ?
            """, (
                body.deadline_hours,
                int(body.enabled),
                control_id,
            ))

    return {
        "control_id": control_id,
        "deadline_hours": body.deadline_hours,
        "enabled": body.enabled,
    }


@app.post("/events")
def ingest_event(event: EventIn):
    allowed = {
        "employee_terminated",
        "account_status",
        "privileged_account",
        "cloud_change",
        "cloud_change_review",
    }

    if event.event_type not in allowed:
        raise HTTPException(
            400,
            f"Unsupported event_type. Choose from {sorted(allowed)}.",
        )

    if (
        event.event_type == "account_status"
        and event.account_status not in {"active", "disabled", "unknown"}
    ):
        raise HTTPException(
            400,
            "account_status must be active, disabled, or unknown.",
        )

    if (
        event.event_type == "cloud_change_review"
        and event.review_status not in {"reviewed", "pending"}
    ):
        raise HTTPException(
            400,
            "review_status must be reviewed or pending.",
        )

    event_id = save_event(event)
    results = evaluate_all(event, event_id)

    return {
        "event_id": event_id,
        "accepted": True,
        "evaluation": results,
    }


@app.get("/events")
def list_events(limit: int = 200):
    limit = max(1, min(limit, 1000))

    with connect() as con:
        rows = con.execute("""
            SELECT *
            FROM events
            ORDER BY event_time DESC, id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    output = []

    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        output.append(item)

    return output


@app.get("/findings")
def list_findings(status: Optional[str] = None):
    with connect() as con:
        if status:
            rows = con.execute("""
                SELECT *
                FROM findings
                WHERE status = ?
                ORDER BY detected_at DESC, id DESC
            """, (status.upper(),)).fetchall()
        else:
            rows = con.execute("""
                SELECT *
                FROM findings
                ORDER BY detected_at DESC, id DESC
            """).fetchall()

    output = []

    for row in rows:
        item = dict(row)
        item["evidence"] = json.loads(item["evidence"])
        output.append(item)

    return output


@app.post("/findings/{finding_id}/resolve")
def resolve_finding(
    finding_id: int,
    body: ResolveRequest = ResolveRequest(),
):
    with connect() as con:
        finding = con.execute("""
            SELECT id, status
            FROM findings
            WHERE id = ?
        """, (finding_id,)).fetchone()

        if not finding:
            raise HTTPException(404, "Finding not found.")

        if finding["status"] == "RESOLVED":
            return {
                "finding_id": finding_id,
                "status": "RESOLVED",
                "message": "Finding was already resolved.",
            }

        con.execute("""
            UPDATE findings
            SET status = 'RESOLVED',
                resolved_at = ?,
                resolution_note = ?
            WHERE id = ?
        """, (
            now_iso(),
            body.note,
            finding_id,
        ))

    audit(
        finding_id,
        "MANUAL_RESOLVED",
        {"note": body.note},
    )

    return {
        "finding_id": finding_id,
        "status": "RESOLVED",
    }


@app.get("/audit-log")
def get_audit_log(limit: int = 200):
    limit = max(1, min(limit, 1000))

    with connect() as con:
        rows = con.execute("""
            SELECT *
            FROM audit_log
            ORDER BY created_at DESC, id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    output = []

    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item["details"])
        output.append(item)

    return output