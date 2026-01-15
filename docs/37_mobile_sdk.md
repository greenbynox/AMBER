# Mobile SDKs (Android / iOS)

## Android
Minimal SDK dans `sdk/android`.

Exemple:
```kotlin
val client = EmberClient("project-id", "api-key", "https://ingest.your-ember.tld")
client.captureMessage("info", "Hello Android")
```

## iOS
Minimal SDK dans `sdk/ios`.

Exemple:
```swift
let client = EmberClient(projectId: "project-id", apiKey: "api-key", ingestUrl: "https://ingest.your-ember.tld")
client.captureMessage(level: "info", message: "Hello iOS")
```
