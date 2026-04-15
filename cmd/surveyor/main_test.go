package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/core"
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

func TestRunHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "Commands:") {
		t.Fatalf("stdout = %q, want top-level help text", stdout.String())
	}
	if !strings.Contains(stdout.String(), "discover local") {
		t.Fatalf("stdout = %q, want discover command in top-level help", stdout.String())
	}
	if !strings.Contains(stdout.String(), "audit local") {
		t.Fatalf("stdout = %q, want audit command in top-level help", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunAuditHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "surveyor audit local") {
		t.Fatalf("stdout = %q, want audit help text", stdout.String())
	}
}

func TestRunAuditLocalHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "local", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stderr.String(), "Examples:") {
		t.Fatalf("stderr = %q, want audit command-specific help", stderr.String())
	}
}

func TestRunAuditLocalWritesMarkdownToStdout(t *testing.T) {
	originalRunner := newLocalAuditRunner
	t.Cleanup(func() {
		newLocalAuditRunner = originalRunner
	})
	newLocalAuditRunner = func(func() time.Time) localAuditRunner {
		return stubLocalAuditRunner{
			results: []core.AuditResult{
				{
					DiscoveredEndpoint: core.DiscoveredEndpoint{
						ScopeKind: core.EndpointScopeKindLocal,
						Host:      "127.0.0.1",
						Port:      443,
						Transport: "tcp",
						State:     "listening",
						Hints: []core.DiscoveryHint{
							{Protocol: "tls", Confidence: "low", Evidence: []string{"transport=tcp", "port=443"}},
						},
					},
					Selection: core.AuditSelection{
						Status:          core.AuditSelectionStatusSelected,
						SelectedScanner: "tls",
						Reason:          "tls hint on tcp/443",
					},
				},
			},
		}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "local"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "# Surveyor Local Audit Report") {
		t.Fatalf("stdout = %q, want audit markdown output", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunAuditLocalRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "local", "extra"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr = %q, want positional argument rejection", stderr.String())
	}
}

func TestRunAuditLocalWritesOutputs(t *testing.T) {
	originalRunner := newLocalAuditRunner
	t.Cleanup(func() {
		newLocalAuditRunner = originalRunner
	})
	newLocalAuditRunner = func(func() time.Time) localAuditRunner {
		return stubLocalAuditRunner{
			results: []core.AuditResult{
				{
					DiscoveredEndpoint: core.DiscoveredEndpoint{
						ScopeKind: core.EndpointScopeKindLocal,
						Host:      "0.0.0.0",
						Port:      443,
						Transport: "tcp",
						State:     "listening",
					},
					Selection: core.AuditSelection{
						Status:          core.AuditSelectionStatusSelected,
						SelectedScanner: "tls",
						Reason:          "tls hint on tcp/443",
					},
				},
			},
		}
	}

	tempDir := t.TempDir()
	markdownPath := filepath.Join(tempDir, "audit.md")
	jsonPath := filepath.Join(tempDir, "audit.json")

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"audit",
		"local",
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

	if !strings.Contains(string(markdownData), "# Surveyor Local Audit Report") {
		t.Fatalf("markdown output missing audit heading\n%s", string(markdownData))
	}
	if !strings.Contains(string(jsonData), "\"total_endpoints\": 1") {
		t.Fatalf("json output missing audit summary\n%s", string(jsonData))
	}
}

func TestRunAuditLocalFailsOnRunnerError(t *testing.T) {
	originalRunner := newLocalAuditRunner
	t.Cleanup(func() {
		newLocalAuditRunner = originalRunner
	})
	newLocalAuditRunner = func(func() time.Time) localAuditRunner {
		return stubLocalAuditRunner{err: errors.New("audit failed")}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "local"}, &stdout, &stderr, fixedNow)

	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "audit local: audit failed") {
		t.Fatalf("stderr = %q, want runner error", stderr.String())
	}
}

func TestRunDiscoverHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "surveyor discover local") {
		t.Fatalf("stdout = %q, want discovery help text", stdout.String())
	}
}

func TestRunDiscoverLocalHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "local", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stderr.String(), "Examples:") {
		t.Fatalf("stderr = %q, want discovery command-specific help", stderr.String())
	}
}

func TestRunDiscoverLocalWritesMarkdownToStdout(t *testing.T) {
	originalDiscoverer := newLocalDiscoverer
	t.Cleanup(func() {
		newLocalDiscoverer = originalDiscoverer
	})
	newLocalDiscoverer = func() localDiscoverer {
		return stubLocalDiscoverer{
			results: []core.DiscoveredEndpoint{
				{
					ScopeKind: core.EndpointScopeKindLocal,
					Host:      "127.0.0.1",
					Port:      443,
					Transport: "tcp",
					State:     "listening",
					Hints: []core.DiscoveryHint{
						{Protocol: "tls", Confidence: "low", Evidence: []string{"transport=tcp", "port=443"}},
					},
				},
			},
		}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "local"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "# Surveyor Discovery Report") {
		t.Fatalf("stdout = %q, want discovery markdown output", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunDiscoverLocalRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "local", "extra"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr = %q, want positional argument rejection", stderr.String())
	}
}

func TestRunDiscoverLocalWritesOutputs(t *testing.T) {
	originalDiscoverer := newLocalDiscoverer
	t.Cleanup(func() {
		newLocalDiscoverer = originalDiscoverer
	})
	newLocalDiscoverer = func() localDiscoverer {
		return stubLocalDiscoverer{
			results: []core.DiscoveredEndpoint{
				{
					ScopeKind: core.EndpointScopeKindLocal,
					Host:      "0.0.0.0",
					Port:      443,
					Transport: "tcp",
					State:     "listening",
				},
			},
		}
	}

	tempDir := t.TempDir()
	markdownPath := filepath.Join(tempDir, "discovery.md")
	jsonPath := filepath.Join(tempDir, "discovery.json")

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"discover",
		"local",
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

	if !strings.Contains(string(markdownData), "# Surveyor Discovery Report") {
		t.Fatalf("markdown output missing discovery heading\n%s", string(markdownData))
	}
	if !strings.Contains(string(jsonData), "\"total_endpoints\": 1") {
		t.Fatalf("json output missing discovery summary\n%s", string(jsonData))
	}
}

func TestRunDiscoverLocalFailsOnEnumeratorError(t *testing.T) {
	originalDiscoverer := newLocalDiscoverer
	t.Cleanup(func() {
		newLocalDiscoverer = originalDiscoverer
	})
	newLocalDiscoverer = func() localDiscoverer {
		return stubLocalDiscoverer{err: errors.New("enumeration failed")}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "local"}, &stdout, &stderr, fixedNow)

	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "discover local: enumeration failed") {
		t.Fatalf("stderr = %q, want enumerator error", stderr.String())
	}
}

func TestRunScanTLSHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"scan", "tls", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stderr.String(), "Examples:") {
		t.Fatalf("stderr = %q, want command-specific help", stderr.String())
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"nonesuch"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q, want unknown command error", stderr.String())
	}
}

func TestRunScanTLSRequiresInput(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"scan", "tls"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "one of --config or --targets is required") {
		t.Fatalf("stderr = %q, want missing input error", stderr.String())
	}
}

func TestRunScanTLSRejectsInvalidTargets(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"scan", "tls", "--targets", "127.0.0.1"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "must be in host:port form") {
		t.Fatalf("stderr = %q, want invalid target format error", stderr.String())
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

func TestRunScanTLSFailsOnInvalidOutputPath(t *testing.T) {
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
		"--output", filepath.Join(t.TempDir(), "missing", "report.md"),
	}, &stdout, &stderr, fixedNow)

	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write Markdown output") {
		t.Fatalf("stderr = %q, want write failure", stderr.String())
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

type stubLocalDiscoverer struct {
	results []core.DiscoveredEndpoint
	err     error
}

func (d stubLocalDiscoverer) Enumerate(context.Context) ([]core.DiscoveredEndpoint, error) {
	if d.err != nil {
		return nil, d.err
	}

	return d.results, nil
}

type stubLocalAuditRunner struct {
	results []core.AuditResult
	err     error
}

func (r stubLocalAuditRunner) Run(context.Context) ([]core.AuditResult, error) {
	if r.err != nil {
		return nil, r.err
	}

	return r.results, nil
}
