from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import SuspiciousIP
from django.core.cache import cache

SENSITIVE_PATHS = ["/admin", "/login"]


@shared_task
def detect_anomalies():
    """
    Detect IPs with >100 requests/hour or access to sensitive paths.
    Stores them in SuspiciousIP table.
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # Assuming request counts are being logged in cache or middleware
    ip_request_data = cache.get("ip_request_data", {})

    for ip, data in ip_request_data.items():
        request_count = data.get("count", 0)
        paths = data.get("paths", [])

        if request_count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                reason="Exceeded 100 requests/hour"
            )

        if any(path in paths for path in SENSITIVE_PATHS):
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                reason=f"Accessed sensitive path(s): {', '.join(paths)}"
            )

    return "Anomaly detection completed."
