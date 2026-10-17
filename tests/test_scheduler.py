"""Tests for the Compliance Sentinel background scheduler."""

from unittest.mock import patch

from backend import scheduler


def test_start_scheduler_registers_monitor_job():
    """Starting the scheduler registers a periodic monitoring job."""

    if scheduler.scheduler.running:
        scheduler.stop_scheduler()

    with patch("backend.monitor.run_compliance_monitor") as monitor:
        scheduler.start_scheduler()

        try:
            jobs = scheduler.scheduler.get_jobs()

            assert any(job.id == "compliance_monitor" for job in jobs)
            monitor.assert_not_called()
        finally:
            scheduler.stop_scheduler()


def test_stop_scheduler_is_safe_when_not_running():
    """Stopping an inactive scheduler must be safe."""

    if scheduler.scheduler.running:
        scheduler.stop_scheduler()

    scheduler.stop_scheduler()

    assert not scheduler.scheduler.running
