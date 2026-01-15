# Python SDK (EMBER)

## Usage
```python
import ember_sdk as ember

ember.init(
    endpoint="http://localhost:3001",
    project_id="demo",
    api_key="<project-key>",
    environment="local",
    release="dev",
    auto_capture=True,
)

ember.add_breadcrumb("checkout:start", category="ui")

try:
    raise Exception("Boom")
except Exception as err:
    ember.capture_exception(err, {
        "tags": {"feature": "checkout"},
        "user": {"id": "42", "email": "dev@local"}
    })
```

## FastAPI
```python
from ember_sdk import add_fastapi_handlers

add_fastapi_handlers(app, user_resolver=lambda req: {"id": "42"})
```

## Django
Ajoutez le middleware `EmberMiddleware`.

## Flask
```python
from ember_sdk import add_flask_handlers

add_flask_handlers(app, user_resolver=lambda req: {"email": "dev@local"})
```
