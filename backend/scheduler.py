"""
Compliance Sentinel — Background Scheduler

Runs compliance monitoring automatically every 60 seconds.
"""

import logging
import os

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger("compliance_sentinel.scheduler")

scheduler = BackgroundScheduler(timezone="UTC")


def start_scheduler():
    """Start the monitoring scheduler once the API starts."""

    if scheduler.running:
        logger.info("Compliance monitoring scheduler is already running.")
        return

    # Import lazily to avoid circular imports.
    from backend.monitor import run_compliance_monitor

    interval_seconds = int(
        os.getenv("COMPLIANCE_MONITOR_INTERVAL_SECONDS", "60")
    )

    scheduler.add_job(
        run_compliance_monitor,
        trigger="interval",
        seconds=interval_seconds,
        id="compliance_monitor",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    scheduler.start()

    logger.info(
        "Compliance monitoring scheduler started; interval=%s seconds.",
        interval_seconds,
    )


def stop_scheduler():
    """Stop the scheduler cleanly when the API shuts down."""

    if scheduler.running:
        scheduler.shutdown(wait=True)
        logger.info("Compliance monitoring scheduler stopped.")