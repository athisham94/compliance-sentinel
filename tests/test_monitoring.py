"""API tests for continuous monitoring and monitoring run history."""

import os

import requests


BASE_URL = os.getenv(
    "COMPLIANCE_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

TIMEOUT = 10


def test_monitoring_status_endpoint():
    response = requests.get(
        f"{BASE_URL}/monitoring/status",
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert "scheduler_running" in data
    assert isinstance(data["scheduler_running"], bool)
    assert "has_run" in data
    assert isinstance(data["has_run"], bool)
    assert "latest_run" in data

    if data["has_run"]:
        latest = data["latest_run"]

        assert isinstance(latest, dict)
        assert latest["status"] in (
            "RUNNING",
            "SUCCESS",
            "PARTIAL",
            "FAILED",
        )
        assert "id" in latest
        assert "started_at" in latest
        assert "error_count" in latest


def test_monitoring_run_history_endpoint():
    response = requests.get(
        f"{BASE_URL}/monitoring/runs?limit=10",
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert isinstance(data, dict)
    assert isinstance(data.get("count"), int)
    assert isinstance(data.get("runs"), list)
    assert len(data["runs"]) <= 10

    for run in data["runs"]:
        assert "id" in run
        assert "started_at" in run
        assert run["status"] in (
            "RUNNING",
            "SUCCESS",
            "PARTIAL",
            "FAILED",
        )
        assert isinstance(run.get("error_count"), int)
        assert isinstance(run.get("errors"), list)


def test_monitoring_run_history_limit_validation():
    response = requests.get(
        f"{BASE_URL}/monitoring/runs?limit=0",
        timeout=TIMEOUT,
    )

    assert response.status_code == 400, response.text
