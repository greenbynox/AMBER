package ember

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type EventLevel string

const (
	LevelError   EventLevel = "error"
	LevelWarning EventLevel = "warning"
	LevelInfo    EventLevel = "info"
	LevelDebug   EventLevel = "debug"
)

type Client struct {
	ProjectID string
	APIKey    string
	IngestURL string
	HTTP      *http.Client
}

type EventEnvelope struct {
	EventID   string        `json:"event_id"`
	ProjectID string        `json:"project_id"`
	Timestamp string        `json:"timestamp"`
	Level     EventLevel    `json:"level"`
	Message   *string       `json:"message,omitempty"`
	Exception Exception     `json:"exception"`
	Context   *EventContext `json:"context,omitempty"`
	SDK       *SDKInfo      `json:"sdk,omitempty"`
}

type Exception struct {
	Kind       string       `json:"type"`
	Message    string       `json:"message"`
	Stacktrace []StackFrame `json:"stacktrace,omitempty"`
}

type StackFrame struct {
	Function string  `json:"function"`
	Filename string  `json:"filename"`
	Line     int64   `json:"line"`
	Col      *int64  `json:"col,omitempty"`
	Module   *string `json:"module,omitempty"`
	InApp    *bool   `json:"in_app,omitempty"`
}

type EventContext struct {
	User    *UserContext      `json:"user,omitempty"`
	Tags    map[string]string `json:"tags,omitempty"`
	Env     *string           `json:"env,omitempty"`
	Release *string           `json:"release,omitempty"`
}

type UserContext struct {
	ID    *string `json:"id,omitempty"`
	Email *string `json:"email,omitempty"`
}

type SDKInfo struct {
	Name    *string `json:"name,omitempty"`
	Version *string `json:"version,omitempty"`
}

func NewClient(projectID, apiKey, ingestURL string) (*Client, error) {
	if projectID == "" || apiKey == "" || ingestURL == "" {
		return nil, errors.New("projectID, apiKey, ingestURL requis")
	}
	return &Client{
		ProjectID: projectID,
		APIKey:    apiKey,
		IngestURL: ingestURL,
		HTTP:      &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func (c *Client) CaptureError(ctx context.Context, err error, opts ...EventOption) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	envelope := EventEnvelope{
		EventID:   newEventID(),
		ProjectID: c.ProjectID,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     LevelError,
		Message:   &message,
		Exception: Exception{
			Kind:    "Error",
			Message: message,
		},
		SDK: &SDKInfo{
			Name:    stringPtr("ember-go"),
			Version: stringPtr("0.1.0"),
		},
	}
	for _, opt := range opts {
		opt(&envelope)
	}
	return c.send(ctx, &envelope)
}

func (c *Client) CaptureMessage(ctx context.Context, level EventLevel, msg string, opts ...EventOption) error {
	if msg == "" {
		return nil
	}
	envelope := EventEnvelope{
		EventID:   newEventID(),
		ProjectID: c.ProjectID,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Message:   &msg,
		Exception: Exception{
			Kind:    "Message",
			Message: msg,
		},
		SDK: &SDKInfo{
			Name:    stringPtr("ember-go"),
			Version: stringPtr("0.1.0"),
		},
	}
	for _, opt := range opts {
		opt(&envelope)
	}
	return c.send(ctx, &envelope)
}

func (c *Client) send(ctx context.Context, envelope *EventEnvelope) error {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	endpoint := c.IngestURL + "/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-ember-project", c.ProjectID)
	req.Header.Set("x-ember-key", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return errors.New("ember ingest error")
	}
	return nil
}

type EventOption func(*EventEnvelope)

func WithUser(id, email string) EventOption {
	return func(ev *EventEnvelope) {
		if id == "" && email == "" {
			return
		}
		user := UserContext{}
		if id != "" {
			user.ID = &id
		}
		if email != "" {
			user.Email = &email
		}
		ev.Context = ensureContext(ev.Context)
		ev.Context.User = &user
	}
}

func WithTags(tags map[string]string) EventOption {
	return func(ev *EventEnvelope) {
		if len(tags) == 0 {
			return
		}
		ev.Context = ensureContext(ev.Context)
		ev.Context.Tags = tags
	}
}

func WithRelease(release string) EventOption {
	return func(ev *EventEnvelope) {
		if release == "" {
			return
		}
		ev.Context = ensureContext(ev.Context)
		ev.Context.Release = &release
	}
}

func WithEnv(env string) EventOption {
	return func(ev *EventEnvelope) {
		if env == "" {
			return
		}
		ev.Context = ensureContext(ev.Context)
		ev.Context.Env = &env
	}
}

func ensureContext(ctx *EventContext) *EventContext {
	if ctx == nil {
		return &EventContext{}
	}
	return ctx
}

func stringPtr(value string) *string {
	return &value
}

func newEventID() string {
	return time.Now().UTC().Format("20060102150405.000000000")
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func Middleware(client *Client, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if client == nil {
			next.ServeHTTP(w, r)
			return
		}
		wrapped := &responseWriter{ResponseWriter: w, status: 200}
		defer func() {
			if rec := recover(); rec != nil {
				err := fmt.Errorf("panic: %v", rec)
				_ = client.CaptureError(context.Background(), err, WithTags(map[string]string{
					"method": r.Method,
					"path":   r.URL.Path,
				}))
				panic(rec)
			}
		}()
		next.ServeHTTP(wrapped, r)
		if wrapped.status >= 500 {
			_ = client.CaptureMessage(context.Background(), LevelError, "http 5xx", WithTags(map[string]string{
				"method": r.Method,
				"path":   r.URL.Path,
				"status": fmt.Sprintf("%d", wrapped.status),
			}))
		}
	})
}
