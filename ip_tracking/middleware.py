import logging
from django.utils.timezone import now
from .models import RequestLog

logger = logging.getLogger(__name__)

class IPLoggingMiddleware:
    """
    Middleware to log the IP address, timestamp, and path of every request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path
        timestamp = now()

        # Save to DB
        RequestLog.objects.create(
            ip_address=ip_address,
            path=path,
            timestamp=timestamp
        )

        # Also log for debugging
        logger.info(f"IP: {ip_address} accessed {path} at {timestamp}")

        return self.get_response(request)

    def get_client_ip(self, request):
        """
        Retrieve IP from headers or META.
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip
