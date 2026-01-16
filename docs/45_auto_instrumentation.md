# Auto‑instrumentation

## Objectif
L’auto‑instrumentation capture automatiquement les exceptions non gérées et enrichit shows events with breadcrumbs (HTTP, logs, framework context) sans modifier chaque endpoint.

## Node.js
- `autoCapture: true` installe les handlers `uncaughtException` et `unhandledRejection`.
- Middleware Express ajoute breadcrumbs HTTP et relie l’erreur à la requête.

```js
const ember = require("@ember/sdk");
const { emberRequestHandler, emberErrorHandler } = require("@ember/sdk/express");

ember.init({ endpoint, projectId, apiKey, autoCapture: true });
app.use(emberRequestHandler());
app.use(emberErrorHandler());
```

## Python
- `auto_capture=True` installe l’excepthook global.
- Helpers FastAPI/Flask/Django ajoutent contexte HTTP.

```python
import ember_sdk as ember
from ember_sdk import add_fastapi_handlers

ember.init(endpoint=endpoint, project_id=project_id, api_key=api_key, auto_capture=True)
add_fastapi_handlers(app)
```

## Bonnes pratiques
- Ajoutez un `release` pour corréler les régressions.
- Utilisez `add_breadcrumb` pour tracer les étapes clés.
- Filtrez les erreurs connues côté SDK si besoin.
