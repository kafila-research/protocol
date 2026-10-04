package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sending the rendezvous's log to an OpenTelemetry endpoint.
//
// A test across people's own machines is studied from what every party
// logged, the rendezvous included: which sessions opened, who joined, what
// failed. Kafila's processes send theirs through the OpenTelemetry SDK; this
// binary stays a few megabytes of standard library, so it sends the same
// records itself, as OTLP/JSON over HTTP, which every OTLP endpoint accepts.
//
// Records at Info and above go to the endpoint as well as to stderr, sent in
// batches every second and flushed on shutdown. Debug never leaves the
// machine. It is configured from the environment as any OpenTelemetry SDK is:
// OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_HEADERS (comma-separated
// key=value, values percent-encoded) and OTEL_SERVICE_NAME, plus
// KAFILA_INSTALL_ID to say which rendezvous it is. Without an endpoint
// nothing is sent.

// version is the build's version, set with -X main.version.
var version = "dev"

const (
	otlpEvery    = time.Second
	otlpBatch    = 512
	otlpQueue    = 8192
	otlpDeadline = 10 * time.Second
)

// otlpConfig is where to send, from the environment.
type otlpConfig struct {
	endpoint string // the base, without /v1/logs
	headers  map[string]string
	service  string
	install  string
}

func otlpFromEnv() (otlpConfig, bool) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		return otlpConfig{}, false
	}
	return otlpConfig{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		headers:  parseOTLPHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")),
		service:  cmp.Or(os.Getenv("OTEL_SERVICE_NAME"), "kafila-rendezvous"),
		install:  os.Getenv("KAFILA_INSTALL_ID"),
	}, true
}

func parseOTLPHeaders(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || k == "" {
			continue
		}
		if decoded, err := url.PathUnescape(v); err == nil {
			v = decoded
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// otlpExporter batches records and posts them.
type otlpExporter struct {
	cfg      otlpConfig
	client   *http.Client
	resource []otlpKeyValue
	queue    chan otlpRecord
	flushed  chan struct{}
	once     sync.Once
	warnOnce sync.Once
}

func newOTLPExporter(cfg otlpConfig) *otlpExporter {
	host, _ := os.Hostname()
	e := &otlpExporter{
		cfg:    cfg,
		client: &http.Client{Timeout: otlpDeadline},
		resource: []otlpKeyValue{
			stringKV("service.name", cfg.service),
			stringKV("service.version", version),
			stringKV("os.type", runtime.GOOS),
			stringKV("host.arch", runtime.GOARCH),
			stringKV("host.name", host),
			stringKV("kafila.install_id", cfg.install),
		},
		queue:   make(chan otlpRecord, otlpQueue),
		flushed: make(chan struct{}),
	}
	go e.run()
	return e
}

// enqueue never blocks: a full queue drops the record, since the rendezvous's
// own work comes first.
func (e *otlpExporter) enqueue(r otlpRecord) {
	select {
	case e.queue <- r:
	default:
	}
}

func (e *otlpExporter) run() {
	defer close(e.flushed)
	tick := time.NewTicker(otlpEvery)
	defer tick.Stop()
	var batch []otlpRecord
	for {
		select {
		case r, ok := <-e.queue:
			if !ok {
				e.post(batch)
				return
			}
			batch = append(batch, r)
			if len(batch) >= otlpBatch {
				e.post(batch)
				batch = nil
			}
		case <-tick.C:
			if len(batch) > 0 {
				e.post(batch)
				batch = nil
			}
		}
	}
}

// close sends what is queued, waiting at most timeout.
func (e *otlpExporter) close(timeout time.Duration) {
	e.once.Do(func() { close(e.queue) })
	select {
	case <-e.flushed:
	case <-time.After(timeout):
	}
}

func (e *otlpExporter) post(batch []otlpRecord) {
	if len(batch) == 0 {
		return
	}
	body, err := json.Marshal(otlpLogs{ResourceLogs: []otlpResourceLogs{{
		Resource:  otlpResource{Attributes: e.resource},
		ScopeLogs: []otlpScopeLogs{{Scope: otlpScope{Name: "rendezvous"}, LogRecords: batch}},
	}}})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.cfg.endpoint+"/v1/logs", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.cfg.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
	if err != nil {
		// Said once, to stderr only: a rendezvous that cannot reach its
		// telemetry goes on serving, and logging every failure would only
		// queue more records that cannot be sent.
		e.warnOnce.Do(func() { fmt.Fprintf(os.Stderr, "rendezvous: telemetry not sent: %v\n", err) })
	}
}

// otlpHandler writes every record to the local handler, as before, and
// queues those at Info and above for the exporter.
type otlpHandler struct {
	local  slog.Handler
	export *otlpExporter
	// attrs were added with WithAttrs, each named under the group in effect
	// when it was added, as slog does.
	attrs []otlpKeyValue
	group string
}

func (h *otlpHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.local.Enabled(ctx, level) || level >= slog.LevelInfo
}

func (h *otlpHandler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.local.Enabled(ctx, r.Level) {
		err = h.local.Handle(ctx, r)
	}
	if r.Level < slog.LevelInfo {
		return err
	}
	rec := otlpRecord{
		TimeUnixNano:   strconv.FormatInt(r.Time.UnixNano(), 10),
		SeverityNumber: severityNumber(r.Level),
		SeverityText:   r.Level.String(),
		Body:           otlpAnyValue{StringValue: &r.Message},
	}
	rec.Attributes = append(rec.Attributes, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		rec.Attributes = append(rec.Attributes, attrKV(h.group, a))
		return true
	})
	h.export.enqueue(rec)
	return err
}

func (h *otlpHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	kept := append([]otlpKeyValue(nil), h.attrs...)
	for _, a := range attrs {
		kept = append(kept, attrKV(h.group, a))
	}
	return &otlpHandler{local: h.local.WithAttrs(attrs), export: h.export, attrs: kept, group: h.group}
}

func (h *otlpHandler) WithGroup(name string) slog.Handler {
	group := name
	if h.group != "" {
		group = h.group + "." + name
	}
	return &otlpHandler{local: h.local.WithGroup(name), export: h.export, attrs: h.attrs, group: group}
}

func severityNumber(l slog.Level) int {
	switch {
	case l >= slog.LevelError:
		return 17
	case l >= slog.LevelWarn:
		return 13
	case l >= slog.LevelInfo:
		return 9
	default:
		return 5
	}
}

func attrKV(group string, a slog.Attr) otlpKeyValue {
	key := a.Key
	if group != "" {
		key = group + "." + key
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindInt64:
		s := strconv.FormatInt(v.Int64(), 10)
		return otlpKeyValue{Key: key, Value: otlpAnyValue{IntValue: &s}}
	case slog.KindUint64:
		s := strconv.FormatUint(v.Uint64(), 10)
		return otlpKeyValue{Key: key, Value: otlpAnyValue{IntValue: &s}}
	case slog.KindFloat64:
		f := v.Float64()
		return otlpKeyValue{Key: key, Value: otlpAnyValue{DoubleValue: &f}}
	case slog.KindBool:
		b := v.Bool()
		return otlpKeyValue{Key: key, Value: otlpAnyValue{BoolValue: &b}}
	default:
		return stringKV(key, v.String())
	}
}

func stringKV(key, value string) otlpKeyValue {
	return otlpKeyValue{Key: key, Value: otlpAnyValue{StringValue: &value}}
}

// The OTLP/JSON shapes this sends: logs, as the protobuf's JSON mapping has
// them, with 64-bit integers as strings.
type (
	otlpLogs struct {
		ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
	}
	otlpResourceLogs struct {
		Resource  otlpResource    `json:"resource"`
		ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
	}
	otlpResource struct {
		Attributes []otlpKeyValue `json:"attributes"`
	}
	otlpScopeLogs struct {
		Scope      otlpScope    `json:"scope"`
		LogRecords []otlpRecord `json:"logRecords"`
	}
	otlpScope struct {
		Name string `json:"name"`
	}
	otlpRecord struct {
		TimeUnixNano   string         `json:"timeUnixNano"`
		SeverityNumber int            `json:"severityNumber"`
		SeverityText   string         `json:"severityText"`
		Body           otlpAnyValue   `json:"body"`
		Attributes     []otlpKeyValue `json:"attributes,omitempty"`
	}
	otlpKeyValue struct {
		Key   string       `json:"key"`
		Value otlpAnyValue `json:"value"`
	}
	otlpAnyValue struct {
		StringValue *string  `json:"stringValue,omitempty"`
		IntValue    *string  `json:"intValue,omitempty"`
		DoubleValue *float64 `json:"doubleValue,omitempty"`
		BoolValue   *bool    `json:"boolValue,omitempty"`
	}
)
