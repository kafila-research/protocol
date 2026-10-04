package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// collector is an OTLP endpoint that keeps what it is sent.
type collector struct {
	mu      sync.Mutex
	bodies  []otlpLogs
	paths   []string
	headers []http.Header
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var logs otlpLogs
	_ = json.Unmarshal(raw, &logs)
	c.mu.Lock()
	c.bodies = append(c.bodies, logs)
	c.paths = append(c.paths, r.URL.Path)
	c.headers = append(c.headers, r.Header.Clone())
	c.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (c *collector) records() []otlpRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []otlpRecord
	for _, b := range c.bodies {
		for _, rl := range b.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				out = append(out, sl.LogRecords...)
			}
		}
	}
	return out
}

func attr(r otlpRecord, key string) *otlpAnyValue {
	for _, kv := range r.Attributes {
		if kv.Key == key {
			v := kv.Value
			return &v
		}
	}
	return nil
}

// Records at Info and above reach the endpoint as OTLP/JSON, labelled with
// the rendezvous's resource and carrying their attributes with their types;
// debug stays on the machine; the headers arrive decoded; and closing sends
// what was still queued.
func TestTheRendezvousSendsItsLogAsOTLP(t *testing.T) {
	c := &collector{}
	srv := httptest.NewServer(c)
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL+"/otlp/")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Basic%20dXNlcjp0b2tlbg==")
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("KAFILA_INSTALL_ID", "rendezvous-test")

	cfg, ok := otlpFromEnv()
	if !ok {
		t.Fatal("not configured from the environment")
	}
	export := newOTLPExporter(cfg)
	log := slog.New(&otlpHandler{local: slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}), export: export})
	log.Debug("detail")
	log.Info("member joined", "session", "s1", "peers", 2, "relayed", true)
	log.With("session", "s2").WithGroup("relay").Warn("queue full", "dropped", 3)
	export.close(5 * time.Second)

	recs := c.records()
	if len(recs) != 2 {
		t.Fatalf("%d records sent, want the info and the warning", len(recs))
	}
	joined := recs[0]
	if *joined.Body.StringValue != "member joined" || joined.SeverityNumber != 9 {
		t.Errorf("first record %+v", joined)
	}
	if v := attr(joined, "peers"); v == nil || v.IntValue == nil || *v.IntValue != "2" {
		t.Errorf("peers sent as %+v, want the integer 2", v)
	}
	if v := attr(joined, "relayed"); v == nil || v.BoolValue == nil || !*v.BoolValue {
		t.Errorf("relayed sent as %+v, want true", v)
	}
	warned := recs[1]
	if warned.SeverityNumber != 13 || attr(warned, "session") == nil || attr(warned, "relay.dropped") == nil {
		t.Errorf("second record %+v", warned)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paths[0] != "/otlp/v1/logs" {
		t.Errorf("posted to %s", c.paths[0])
	}
	if got := c.headers[0].Get("Authorization"); got != "Basic dXNlcjp0b2tlbg==" {
		t.Errorf("Authorization %q", got)
	}
	resource := map[string]string{}
	for _, kv := range c.bodies[0].ResourceLogs[0].Resource.Attributes {
		resource[kv.Key] = *kv.Value.StringValue
	}
	if resource["service.name"] != "kafila-rendezvous" || resource["kafila.install_id"] != "rendezvous-test" {
		t.Errorf("resource %v", resource)
	}
}

// Without an endpoint nothing is sent.
func TestNoEndpointNoTelemetry(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	if _, ok := otlpFromEnv(); ok {
		t.Fatal("configured with no endpoint")
	}
}
