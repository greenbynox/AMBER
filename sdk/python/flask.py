from typing import Callable, Optional
from flask import request
from .ember_sdk import capture_exception


def add_flask_handlers(app, user_resolver: Optional[Callable] = None):
    @app.errorhandler(Exception)
    def ember_exception_handler(exc):
        context = {
            "tags": {
                "method": request.method,
                "path": request.path,
            }
        }
        if user_resolver:
            context["user"] = user_resolver(request)
        capture_exception(exc, context)
        return exc
