# Ember Go SDK

Minimal Go SDK to send errors and messages to AMBER.

## Installation
```bash
cd sdk/go
```

## Usage
```go
package main

import (
  "context"
  "log"
  "github.com/amber/ember-go"
)

func main() {
  client, err := ember.NewClient("project-id", "api-key", "http://localhost:3001")
  if err != nil {
    log.Fatal(err)
  }

  _ = client.CaptureError(context.Background(), err,
    ember.WithUser("123", "dev@example.com"),
    ember.WithRelease("1.2.3"),
    ember.WithEnv("prod"),
  )
}
```

## HTTP middleware
```go
mux := http.NewServeMux()
// routes...

handler := ember.Middleware(client, mux)
http.ListenAndServe(":8080", handler)
```
