import logging
from django.utils.timezone import now
from .models import RequestLog
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog, BlockedIP
from django.core.cache import cache
from ipgeolocation import IpGeoLocation


logger = logging.getLogger(__name__)

class IPLoggingMiddleware(MiddlewareMixin):
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
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip

    def get_geolocation(self, ip):
        # Check cache first (24h = 86400 seconds)
        cached_data = cache.get(f"geo_{ip}")
        if cached_data:
            return cached_data

        try:
            geo = IpGeoLocation(ip)
            data = {
                "country": geo.country_name or "Unknown",
                "city": geo.city or "Unknown",
            }
        except Exception:
            data = {"country": "Unknown", "city": "Unknown"}

        cache.set(f"geo_{ip}", data, timeout=86400)
        return data

    def process_request(self, request):
        ip = self.get_client_ip(request)
        path = request.path


        # 🚫 Block if IP is in blacklist
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP is blocked.")

        # 🌍 Get geolocation info
        geo_data = self.get_geolocation(ip)

        # ✅ Log request with geolocation
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=geo_data["country"],
            city=geo_data["city"],
        )
        ip_data = cache.get("ip_request_data", {})
        if ip not in ip_data:
            ip_data[ip] = {"count": 0, "paths": []}

        ip_data[ip]["count"] += 1
        ip_data[ip]["paths"].append(path)

        cache.set("ip_request_data", ip_data, timeout=3600)  # keep for 1 hour

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")