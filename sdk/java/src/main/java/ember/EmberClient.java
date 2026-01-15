package ember;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class EmberClient {
    private final String projectId;
    private final String apiKey;
    private final String ingestUrl;
    private final HttpClient httpClient;

    public EmberClient(String projectId, String apiKey, String ingestUrl) {
        if (projectId == null || projectId.isBlank() || apiKey == null || apiKey.isBlank() || ingestUrl == null || ingestUrl.isBlank()) {
            throw new IllegalArgumentException("projectId, apiKey, ingestUrl requis");
        }
        this.projectId = projectId;
        this.apiKey = apiKey;
        this.ingestUrl = ingestUrl;
        this.httpClient = HttpClient.newHttpClient();
    }

    public void captureError(Exception ex, Map<String, String> tags, String release, String env) throws IOException, InterruptedException {
        if (ex == null) {
            return;
        }
        Map<String, Object> payload = buildPayload("error", ex.getClass().getSimpleName(), ex.getMessage(), tags, release, env);
        send(payload);
    }

    public void captureMessage(String level, String message, Map<String, String> tags, String release, String env) throws IOException, InterruptedException {
        if (message == null || message.isBlank()) {
            return;
        }
        String lvl = level == null || level.isBlank() ? "info" : level;
        Map<String, Object> payload = buildPayload(lvl, "Message", message, tags, release, env);
        send(payload);
    }

    private Map<String, Object> buildPayload(String level, String exceptionType, String message, Map<String, String> tags, String release, String env) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("event_id", String.valueOf(Instant.now().toEpochMilli()));
        payload.put("project_id", projectId);
        payload.put("timestamp", Instant.now().toString());
        payload.put("level", level);
        payload.put("message", message);

        Map<String, Object> exception = new HashMap<>();
        exception.put("type", exceptionType);
        exception.put("message", message == null ? "" : message);
        payload.put("exception", exception);

        if ((tags != null && !tags.isEmpty()) || release != null || env != null) {
            Map<String, Object> context = new HashMap<>();
            if (tags != null && !tags.isEmpty()) {
                context.put("tags", tags);
            }
            if (release != null && !release.isBlank()) {
                context.put("release", release);
            }
            if (env != null && !env.isBlank()) {
                context.put("env", env);
            }
            payload.put("context", context);
        }

        Map<String, Object> sdk = new HashMap<>();
        sdk.put("name", "ember-java");
        sdk.put("version", "0.1.0");
        payload.put("sdk", sdk);

        return payload;
    }

    private void send(Map<String, Object> payload) throws IOException, InterruptedException {
        String json = Json.stringify(payload);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(ingestUrl + "/ingest"))
                .header("Content-Type", "application/json")
                .header("x-ember-project", projectId)
                .header("x-ember-key", apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 300) {
            throw new IOException("ember ingest error: " + response.statusCode());
        }
    }

    private static class Json {
        static String stringify(Object obj) {
            return new com.google.gson.Gson().toJson(obj);
        }
    }
}
