from .ember_sdk import capture_exception


class EmberMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        context = {
            "tags": {
                "method": request.method,
                "path": request.path,
            }
        }
        capture_exception(exception, context)
        return None
