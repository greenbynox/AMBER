import Foundation

public final class EmberClient {
    private let projectId: String
    private let apiKey: String
    private let ingestUrl: String

    public init(projectId: String, apiKey: String, ingestUrl: String) {
        self.projectId = projectId
        self.apiKey = apiKey
        self.ingestUrl = ingestUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    public func captureMessage(level: String, message: String, tags: [String: String]? = nil, release: String? = nil, env: String? = nil) {
        guard !message.isEmpty else { return }
        let payload = buildPayload(level: level.isEmpty ? "info" : level, exceptionType: "Message", message: message, tags: tags, release: release, env: env)
        send(payload: payload)
    }

    public func captureError(_ error: Error, tags: [String: String]? = nil, release: String? = nil, env: String? = nil) {
        let message = (error as NSError).localizedDescription
        let payload = buildPayload(level: "error", exceptionType: String(describing: type(of: error)), message: message, tags: tags, release: release, env: env)
        send(payload: payload)
    }

    private func buildPayload(level: String, exceptionType: String, message: String, tags: [String: String]?, release: String?, env: String?) -> [String: Any] {
        var payload: [String: Any] = [
            "event_id": UUID().uuidString,
            "project_id": projectId,
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "level": level,
            "message": message,
            "exception": [
                "type": exceptionType,
                "message": message
            ],
            "sdk": [
                "name": "ember-ios",
                "version": "0.1.0"
            ]
        ]

        var context: [String: Any] = [:]
        if let tags = tags, !tags.isEmpty { context["tags"] = tags }
        if let release = release, !release.isEmpty { context["release"] = release }
        if let env = env, !env.isEmpty { context["env"] = env }
        if !context.isEmpty { payload["context"] = context }

        return payload
    }

    private func send(payload: [String: Any]) {
        guard let url = URL(string: ingestUrl + "/ingest") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "x-ember-key")

        let data = try? JSONSerialization.data(withJSONObject: payload)
        request.httpBody = data

        URLSession.shared.dataTask(with: request).resume()
    }
}
