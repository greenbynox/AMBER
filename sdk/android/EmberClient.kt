package ember

import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID

class EmberClient(
    private val projectId: String,
    private val apiKey: String,
    private val ingestUrl: String,
) {
    init {
        require(projectId.isNotBlank()) { "projectId requis" }
        require(apiKey.isNotBlank()) { "apiKey requis" }
        require(ingestUrl.isNotBlank()) { "ingestUrl requis" }
    }

    fun captureMessage(level: String, message: String, tags: Map<String, String>? = null, release: String? = null, env: String? = null) {
        if (message.isBlank()) return
        val payload = buildPayload(level.ifBlank { "info" }, "Message", message, tags, release, env)
        send(payload)
    }

    fun captureError(error: Throwable, tags: Map<String, String>? = null, release: String? = null, env: String? = null) {
        val message = error.message ?: "Erreur inconnue"
        val payload = buildPayload("error", error.javaClass.simpleName, message, tags, release, env)
        send(payload)
    }

    private fun buildPayload(level: String, exceptionType: String, message: String, tags: Map<String, String>?, release: String?, env: String?): String {
        val context = mutableListOf<String>()
        tags?.takeIf { it.isNotEmpty() }?.let {
            val tagsJson = it.entries.joinToString(",") { entry -> "\"${entry.key}\":\"${entry.value}\"" }
            context.add("\"tags\":{${tagsJson}}")
        }
        release?.takeIf { it.isNotBlank() }?.let { context.add("\"release\":\"$it\"") }
        env?.takeIf { it.isNotBlank() }?.let { context.add("\"env\":\"$it\"") }

        val contextJson = if (context.isNotEmpty()) ",\"context\":{${context.joinToString(",")}}" else ""

        return "{" +
            "\"event_id\":\"${UUID.randomUUID()}\"," +
            "\"project_id\":\"$projectId\"," +
            "\"timestamp\":\"${java.time.Instant.now()}\"," +
            "\"level\":\"$level\"," +
            "\"message\":\"${escape(message)}\"," +
            "\"exception\":{\"type\":\"${escape(exceptionType)}\",\"message\":\"${escape(message)}\"}," +
            "\"sdk\":{\"name\":\"ember-android\",\"version\":\"0.1.0\"}" +
            contextJson +
            "}"
    }

    private fun send(payload: String) {
        val url = URL(ingestUrl.trimEnd('/') + "/ingest")
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("x-ember-key", apiKey)
        connection.doOutput = true
        OutputStreamWriter(connection.outputStream).use { writer ->
            writer.write(payload)
        }
        connection.inputStream.close()
        connection.disconnect()
    }

    private fun escape(value: String): String {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
    }
}
