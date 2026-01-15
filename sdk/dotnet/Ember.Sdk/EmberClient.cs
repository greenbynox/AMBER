using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Ember.Sdk
{
    public class EmberClient
    {
        private readonly string _projectId;
        private readonly string _apiKey;
        private readonly string _ingestUrl;
        private readonly HttpClient _httpClient;

        public EmberClient(string projectId, string apiKey, string ingestUrl, HttpClient? httpClient = null)
        {
            if (string.IsNullOrWhiteSpace(projectId) || string.IsNullOrWhiteSpace(apiKey) || string.IsNullOrWhiteSpace(ingestUrl))
            {
                throw new ArgumentException("projectId, apiKey, ingestUrl requis");
            }

            _projectId = projectId;
            _apiKey = apiKey;
            _ingestUrl = ingestUrl.TrimEnd('/');
            _httpClient = httpClient ?? new HttpClient();
        }

        public Task CaptureMessageAsync(string? level, string message, Dictionary<string, string>? tags = null, string? release = null, string? env = null)
        {
            if (string.IsNullOrWhiteSpace(message))
            {
                return Task.CompletedTask;
            }

            var lvl = string.IsNullOrWhiteSpace(level) ? "info" : level;
            var payload = BuildPayload(lvl, "Message", message, tags, release, env);
            return SendAsync(payload);
        }

        public Task CaptureErrorAsync(Exception ex, Dictionary<string, string>? tags = null, string? release = null, string? env = null)
        {
            if (ex == null)
            {
                return Task.CompletedTask;
            }

            var payload = BuildPayload("error", ex.GetType().Name, ex.Message, tags, release, env);
            return SendAsync(payload);
        }

        private Dictionary<string, object> BuildPayload(string level, string exceptionType, string? message, Dictionary<string, string>? tags, string? release, string? env)
        {
            var payload = new Dictionary<string, object>
            {
                ["event_id"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(),
                ["project_id"] = _projectId,
                ["timestamp"] = DateTimeOffset.UtcNow.ToString("O"),
                ["level"] = level,
                ["message"] = message ?? string.Empty,
                ["exception"] = new Dictionary<string, object>
                {
                    ["type"] = exceptionType,
                    ["message"] = message ?? string.Empty
                },
                ["sdk"] = new Dictionary<string, object>
                {
                    ["name"] = "ember-dotnet",
                    ["version"] = "0.1.0"
                }
            };

            if ((tags != null && tags.Count > 0) || !string.IsNullOrWhiteSpace(release) || !string.IsNullOrWhiteSpace(env))
            {
                var context = new Dictionary<string, object>();
                if (tags != null && tags.Count > 0)
                {
                    context["tags"] = tags;
                }

                if (!string.IsNullOrWhiteSpace(release))
                {
                    context["release"] = release;
                }

                if (!string.IsNullOrWhiteSpace(env))
                {
                    context["env"] = env;
                }

                payload["context"] = context;
            }

            return payload;
        }

        private async Task SendAsync(Dictionary<string, object> payload)
        {
            var json = JsonSerializer.Serialize(payload);
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_ingestUrl}/ingest")
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
            request.Headers.Add("x-ember-project", _projectId);
            request.Headers.Add("x-ember-key", _apiKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
            if ((int)response.StatusCode >= 300)
            {
                throw new HttpRequestException($"ember ingest error: {(int)response.StatusCode}");
            }
        }
    }
}
