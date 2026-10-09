from django.conf import settings
from django.shortcuts import redirect


class LoginRequiredMiddleware:
    """Require authentication for all pages except selected public paths."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        public_prefixes = [
            settings.LOGIN_URL,
            "/accounts/logout/",
            "/static/",
        ]

        if request.user.is_authenticated or any(path.startswith(p) for p in public_prefixes):
            return self.get_response(request)

        return redirect(f"{settings.LOGIN_URL}?next={path}")
