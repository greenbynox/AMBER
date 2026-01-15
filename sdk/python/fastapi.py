from typing import Callable, Optional
from .ember_sdk import capture_exception


def add_fastapi_handlers(app, user_resolver: Optional[Callable] = None):
    @app.exception_handler(Exception)
    async def ember_exception_handler(request, exc):
        context = {
            "tags": {
                "method": request.method,
                "path": request.url.path,
            }
        }
        if user_resolver:
            context["user"] = user_resolver(request)
        capture_exception(exc, context)
        raise exc
