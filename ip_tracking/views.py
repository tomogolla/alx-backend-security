from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from ratelimit.decorators import ratelimit


@csrf_exempt
@ratelimit(key="ip", rate="5/m", method="POST", block=True)
def anonymous_login_view(request):
    """
    Rate-limited login view for anonymous users
    Max 5 requests/minute per IP
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({"message": "Login successful"})
        return JsonResponse({"error": "Invalid credentials"}, status=401)

    return JsonResponse({"error": "POST required"},
                        status=400) 
