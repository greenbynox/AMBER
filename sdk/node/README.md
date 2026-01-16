# Node SDK (EMBER)

## Local installation
```
cd sdk/node
npm install
```

## Usage
```js
const ember = require("@ember/sdk");

ember.init({
  endpoint: "http://localhost:3001",
  projectId: "demo",
  apiKey: "<project-key>",
  environment: "local",
  release: "dev",
  autoCapture: true,
});

ember.addBreadcrumb("checkout:start", { category: "ui" });

try {
  throw new Error("Boom");
} catch (err) {
  ember.captureException(err, {
    tags: { feature: "checkout" },
    user: { id: "42", email: "dev@local" },
  });
}
```

Auto‑capture installe `uncaughtException` + `unhandledRejection`.

## Express (middleware)
```js
const { emberRequestHandler, emberErrorHandler } = require("@ember/sdk/express");

app.use(emberRequestHandler({
  userResolver: (req) => ({ id: req.user?.id, email: req.user?.email })
}));

app.use(emberErrorHandler());
```
