package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTargetsArg(t *testing.T) {
	t.Parallel()

	targets, err := parseTargetsArg("127.0.0.1:443,[::1]:8443")
	if err != nil {
		t.Fatalf("parseTargetsArg() error = %v", err)
	}

	if got, want := len(targets), 2; got != want {
		t.Fatalf("len(targets) = %d, want %d", got, want)
	}
	if targets[0].Host != "127.0.0.1" || targets[0].Port != 443 {
		t.Fatalf("targets[0] = %#v, want host 127.0.0.1 port 443", targets[0])
	}
	if targets[1].Host != "::1" || targets[1].Port != 8443 {
		t.Fatalf("targets[1] = %#v, want host ::1 port 8443", targets[1])
	}
}

func TestRunScanTLSRejectsConfigAndTargetsTogether(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"scan",
		"tls",
		"--config", "examples/targets.yaml",
		"--targets", "127.0.0.1:443",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "use either --config or --targets, not both") {
		t.Fatalf("stderr = %q, want config/targets conflict", stderr.String())
	}
}

func TestRunScanTLSWritesOutputs(t *testing.T) {
	t.Parallel()

	server := testTLSServer(t)
	defer server.Close()

	host, port := splitServerAddress(t, server.Listener.Addr().String())
	tempDir := t.TempDir()
	markdownPath := filepath.Join(tempDir, "report.md")
	jsonPath := filepath.Join(tempDir, "report.json")

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"scan",
		"tls",
		"--targets", net.JoinHostPort(host, port),
		"--output", markdownPath,
		"--json", jsonPath,
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty when file outputs are requested", stdout.String())
	}

	markdownData, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatalf("ReadFile(markdown) error = %v", err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile(json) error = %v", err)
	}

	if !strings.Contains(string(markdownData), "# Surveyor TLS Inventory Report") {
		t.Fatalf("markdown output missing report heading\n%s", string(markdownData))
	}
	if !strings.Contains(string(jsonData), "\"classification\": \"modern_tls_classical_identity\"") {
		t.Fatalf("json output missing classification\n%s", string(jsonData))
	}
}

func TestRunScanTLSWritesMarkdownToStdout(t *testing.T) {
	t.Parallel()

	server := testTLSServer(t)
	defer server.Close()

	host, port := splitServerAddress(t, server.Listener.Addr().String())

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"scan",
		"tls",
		"--targets", net.JoinHostPort(host, port),
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# Surveyor TLS Inventory Report") {
		t.Fatalf("stdout missing report heading\n%s", stdout.String())
	}
}

func fixedNow() time.Time {
	return time.Date(2026, time.April, 14, 2, 0, 0, 0, time.UTC)
}

func testTLSServer(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server.StartTLS()

	return server
}

func splitServerAddress(t *testing.T, address string) (string, string) {
	t.Helper()

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	return host, port
}
