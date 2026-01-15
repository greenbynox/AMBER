# Ember Android SDK (minimal)

## Usage
```kotlin
import ember.EmberClient

val client = EmberClient(
    "project-id",
    "api-key",
    "https://ingest.your-ember.tld"
)

client.captureMessage("info", "Hello from Android")

try {
    throw RuntimeException("boom")
} catch (e: Exception) {
    client.captureError(e, mapOf("module" to "checkout"), "1.0.0", "prod")
}
```
