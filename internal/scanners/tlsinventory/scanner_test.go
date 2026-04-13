package tlsinventory

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/config"
)

func TestScanTargetSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server.StartTLS()
	defer server.Close()

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}

	scannedAt := time.Date(2026, time.April, 13, 13, 0, 0, 0, time.UTC)
	scanner := Scanner{
		Now: func() time.Time { return scannedAt },
	}

	result := scanner.ScanTarget(context.Background(), config.Target{
		Name: "primary-site",
		Host: host,
		Port: portNumber,
	})

	if !result.Reachable {
		t.Fatalf("result.Reachable = false, want true; errors = %v", result.Errors)
	}
	if result.Name != "primary-site" {
		t.Fatalf("result.Name = %q, want %q", result.Name, "primary-site")
	}
	if result.Host != host {
		t.Fatalf("result.Host = %q, want %q", result.Host, host)
	}
	if result.Port != portNumber {
		t.Fatalf("result.Port = %d, want %d", result.Port, portNumber)
	}
	if !result.ScannedAt.Equal(scannedAt) {
		t.Fatalf("result.ScannedAt = %v, want %v", result.ScannedAt, scannedAt)
	}
	if result.Address == "" {
		t.Fatal("result.Address = empty, want populated remote address")
	}
	if result.TLSVersion != "TLS 1.2" {
		t.Fatalf("result.TLSVersion = %q, want %q", result.TLSVersion, "TLS 1.2")
	}
	if result.CipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("result.CipherSuite = %q, want %q", result.CipherSuite, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	}
	if len(result.Errors) != 0 {
		t.Fatalf("len(result.Errors) = %d, want 0; errors = %v", len(result.Errors), result.Errors)
	}
}

func TestScanTargetFailure(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	scanner := Scanner{
		Timeout: 2 * time.Second,
		Now: func() time.Time {
			return time.Date(2026, time.April, 13, 13, 30, 0, 0, time.UTC)
		},
	}

	result := scanner.ScanTarget(context.Background(), config.Target{
		Host: host,
		Port: portNumber,
	})

	if result.Reachable {
		t.Fatal("result.Reachable = true, want false")
	}
	if result.TLSVersion != "" {
		t.Fatalf("result.TLSVersion = %q, want empty", result.TLSVersion)
	}
	if result.CipherSuite != "" {
		t.Fatalf("result.CipherSuite = %q, want empty", result.CipherSuite)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("len(result.Errors) = %d, want 1; errors = %v", len(result.Errors), result.Errors)
	}
	if !strings.Contains(result.Errors[0], "tls connection failed:") {
		t.Fatalf("result.Errors[0] = %q, want tls connection failure prefix", result.Errors[0])
	}
}
