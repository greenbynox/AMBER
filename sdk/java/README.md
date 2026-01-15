# Ember Java SDK

## Installation

Use Maven with the local module:

- GroupId: `io.ember`
- ArtifactId: `ember-java`
- Version: `0.1.0`

## Usage

```java
import ember.EmberClient;
import java.util.Map;

EmberClient client = new EmberClient(
    "<project_id>",
    "<api_key>",
    "https://ingest.your-ember.tld"
);

try {
    client.captureMessage("info", "Hello from Java", Map.of("service", "api"), "1.0.0", "prod");
} catch (Exception e) {
    // handle
}
```

## Capture errors

```java
try {
    throw new RuntimeException("boom");
} catch (Exception e) {
    client.captureError(e, Map.of("module", "checkout"), "1.0.0", "prod");
}
```

## Servlet Filter (auto-instrumentation)
```java
import ember.EmberFilter;

// enregistrement via votre framework web (Spring Boot / Servlet)
// new EmberFilter(client)
```
