# Ember .NET SDK

## Usage

```csharp
using Ember.Sdk;

var client = new EmberClient(
    "<project_id>",
    "<api_key>",
    "https://ingest.your-ember.tld"
);

await client.CaptureMessageAsync("info", "Hello from .NET", new Dictionary<string, string>
{
    { "service", "api" }
}, "1.0.0", "prod");
```

## Capture errors

```csharp
try
{
    throw new InvalidOperationException("boom");
}
catch (Exception ex)
{
    await client.CaptureErrorAsync(ex, new Dictionary<string, string>
    {
        { "module", "checkout" }
    }, "1.0.0", "prod");
}
```

## ASP.NET Core middleware
```csharp
using Ember.Sdk;

app.UseEmber(client);
```
