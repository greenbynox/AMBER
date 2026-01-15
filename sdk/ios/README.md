# Ember iOS SDK (minimal)

## Usage
```swift
let client = EmberClient(
    projectId: "project-id",
    apiKey: "api-key",
    ingestUrl: "https://ingest.your-ember.tld"
)

client.captureMessage(level: "info", message: "Hello from iOS")

struct Boom: Error {}
client.captureError(Boom())
```
