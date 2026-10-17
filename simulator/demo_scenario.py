from datetime import datetime, timedelta, timezone
import requests

API = "http://127.0.0.1:8000"
now = datetime.now(timezone.utc)
employee = "EMP-2048"

events = [
    {
        "event_type": "employee_terminated", "employee_id": employee,
        "system_name": "HR", "event_time": (now - timedelta(hours=30)).isoformat(),
        "details": {"source": "synthetic_demo", "reason": "employment_ended"}
    },
    {
        "event_type": "account_status", "employee_id": employee,
        "system_name": "GitHub", "event_time": (now - timedelta(hours=2)).isoformat(),
        "account_status": "active",
        "details": {"account": "emp-2048@example.invalid", "source": "synthetic_demo"}
    },
    {
        "event_type": "account_status", "employee_id": employee,
        "system_name": "AWS", "event_time": (now - timedelta(hours=1)).isoformat(),
        "account_status": "active",
        "details": {"account": "demo-emp-2048", "source": "synthetic_demo"}
    },
    {
        "event_type": "account_status", "employee_id": employee,
        "system_name": "SAP", "event_time": (now - timedelta(minutes=30)).isoformat(),
        "account_status": "disabled",
        "details": {"account": "EMP2048", "source": "synthetic_demo"}
    },
    {
        "event_type": "privileged_account", "employee_id": "admin-cloud-07",
        "system_name": "AWS", "event_time": (now - timedelta(minutes=10)).isoformat(),
        "privileged": True, "owner": None,
        "details": {"account_type": "administrator", "source": "synthetic_demo"}
    },
    {
        "event_type": "cloud_change", "employee_id": "change-9001",
        "system_name": "AWS", "event_time": (now - timedelta(hours=3)).isoformat(),
        "change_id": "CHANGE-9001",
        "change_description": "Public access enabled on a production storage resource",
        "critical": True,
        "details": {"resource": "production-storage-demo", "source": "synthetic_demo"}
    }
]

for event in events:
    response = requests.post(f"{API}/events", json=event, timeout=5)
    print(response.status_code, response.json())

print("\nDemo events submitted. Refresh the dashboard to see findings.")
