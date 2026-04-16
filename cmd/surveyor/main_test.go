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

	"github.com/steadytao/surveyor/internal/config"
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
	if !strings.Contains(stdout.String(), "discover remote") {
		t.Fatalf("stdout = %q, want canonical remote discovery command in top-level help", stdout.String())
	}
	if !strings.Contains(stdout.String(), "discover subnet") {
		t.Fatalf("stdout = %q, want remote discovery command in top-level help", stdout.String())
	}
	if !strings.Contains(stdout.String(), "audit local") {
		t.Fatalf("stdout = %q, want audit command in top-level help", stdout.String())
	}
	if !strings.Contains(stdout.String(), "audit remote") {
		t.Fatalf("stdout = %q, want canonical remote audit command in top-level help", stdout.String())
	}
	if !strings.Contains(stdout.String(), "audit subnet") {
		t.Fatalf("stdout = %q, want remote audit command in top-level help", stdout.String())
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
	if !strings.Contains(stdout.String(), "surveyor audit remote") {
		t.Fatalf("stdout = %q, want canonical remote audit help text", stdout.String())
	}
	if !strings.Contains(stdout.String(), "surveyor audit subnet") {
		t.Fatalf("stdout = %q, want subnet audit help text", stdout.String())
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
	newLocalAuditRunner = func(func() time.Time) auditRunner {
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
	if !strings.Contains(stdout.String(), "# Surveyor Audit Report") {
		t.Fatalf("stdout = %q, want audit markdown output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "## Scope") {
		t.Fatalf("stdout = %q, want report scope metadata", stdout.String())
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
	newLocalAuditRunner = func(func() time.Time) auditRunner {
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

	if !strings.Contains(string(markdownData), "# Surveyor Audit Report") {
		t.Fatalf("markdown output missing audit heading\n%s", string(markdownData))
	}
	if !strings.Contains(string(jsonData), "\"scope\": {") || !strings.Contains(string(jsonData), "\"scope_kind\": \"local\"") {
		t.Fatalf("json output missing local audit scope metadata\n%s", string(jsonData))
	}
}

func TestRunAuditLocalFailsOnRunnerError(t *testing.T) {
	originalRunner := newLocalAuditRunner
	t.Cleanup(func() {
		newLocalAuditRunner = originalRunner
	})
	newLocalAuditRunner = func(func() time.Time) auditRunner {
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

func TestRunAuditSubnetHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "subnet", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stderr.String(), "--cidr") {
		t.Fatalf("stderr = %q, want subnet audit flags", stderr.String())
	}
	if strings.Contains(stderr.String(), "  --targets-file") {
		t.Fatalf("stderr = %q, want no targets-file flag line in subnet alias help", stderr.String())
	}
	if !strings.Contains(stderr.String(), "only accepts --cidr, not --targets-file") {
		t.Fatalf("stderr = %q, want explicit CIDR-only alias guidance", stderr.String())
	}
}

func TestRunAuditRemoteHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "remote", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stderr.String(), "--targets-file") {
		t.Fatalf("stderr = %q, want targets-file flag in remote help", stderr.String())
	}
}

func TestRunAuditRemoteWritesMarkdownToStdout(t *testing.T) {
	originalRunner := newRemoteAuditRunner
	t.Cleanup(func() {
		newRemoteAuditRunner = originalRunner
	})
	newRemoteAuditRunner = func(config.RemoteScope, func() time.Time) auditRunner {
		return stubLocalAuditRunner{
			results: []core.AuditResult{
				{
					DiscoveredEndpoint: core.DiscoveredEndpoint{
						ScopeKind: core.EndpointScopeKindRemote,
						Host:      "10.0.0.10",
						Port:      443,
						Transport: "tcp",
						State:     "responsive",
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

	exitCode := run([]string{"audit", "remote", "--cidr", "10.0.0.0/30", "--ports", "443"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# Surveyor Audit Report") {
		t.Fatalf("stdout = %q, want audit markdown output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: cidr") || !strings.Contains(stdout.String(), "CIDR: 10.0.0.0/30") {
		t.Fatalf("stdout = %q, want canonical remote scope metadata", stdout.String())
	}
}

func TestRunAuditRemoteTargetsFileDryRunWritesPlan(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	targetsFile := filepath.Join(tempDir, "approved-hosts.txt")
	if err := os.WriteFile(targetsFile, []byte("10.0.0.10\nexample.com\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"audit",
		"remote",
		"--targets-file", targetsFile,
		"--ports", "443,8443",
		"--dry-run",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: targets_file") || !strings.Contains(stdout.String(), "Targets file: "+targetsFile) {
		t.Fatalf("stdout = %q, want targets-file execution plan metadata", stdout.String())
	}
}

func TestRunAuditRemoteTargetsFileRejectsExecution(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	targetsFile := filepath.Join(tempDir, "approved-hosts.txt")
	if err := os.WriteFile(targetsFile, []byte("10.0.0.10\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"audit",
		"remote",
		"--targets-file", targetsFile,
		"--ports", "443",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "audit remote --targets-file is not implemented yet") {
		t.Fatalf("stderr = %q, want clear targets-file boundary", stderr.String())
	}
}

func TestRunAuditSubnetRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "subnet", "--cidr", "10.0.0.0/30", "--ports", "443", "extra"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "audit subnet does not accept positional arguments") {
		t.Fatalf("stderr = %q, want positional argument rejection", stderr.String())
	}
}

func TestRunAuditSubnetRequiresScopeAndPorts(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "subnet"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "--cidr is required") {
		t.Fatalf("stderr = %q, want subnet scope validation error", stderr.String())
	}
}

func TestRunAuditSubnetWritesMarkdownToStdout(t *testing.T) {
	originalRunner := newRemoteAuditRunner
	t.Cleanup(func() {
		newRemoteAuditRunner = originalRunner
	})
	newRemoteAuditRunner = func(config.RemoteScope, func() time.Time) auditRunner {
		return stubLocalAuditRunner{
			results: []core.AuditResult{
				{
					DiscoveredEndpoint: core.DiscoveredEndpoint{
						ScopeKind: core.EndpointScopeKindRemote,
						Host:      "10.0.0.10",
						Port:      443,
						Transport: "tcp",
						State:     "responsive",
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

	exitCode := run([]string{"audit", "subnet", "--cidr", "10.0.0.0/30", "--ports", "443"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# Surveyor Audit Report") {
		t.Fatalf("stdout = %q, want audit markdown output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: cidr") || !strings.Contains(stdout.String(), "CIDR: 10.0.0.0/30") {
		t.Fatalf("stdout = %q, want remote scope metadata", stdout.String())
	}
}

func TestRunAuditSubnetWritesOutputs(t *testing.T) {
	originalRunner := newRemoteAuditRunner
	t.Cleanup(func() {
		newRemoteAuditRunner = originalRunner
	})
	newRemoteAuditRunner = func(config.RemoteScope, func() time.Time) auditRunner {
		return stubLocalAuditRunner{
			results: []core.AuditResult{
				{
					DiscoveredEndpoint: core.DiscoveredEndpoint{
						ScopeKind: core.EndpointScopeKindRemote,
						Host:      "10.0.0.10",
						Port:      443,
						Transport: "tcp",
						State:     "responsive",
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
	markdownPath := filepath.Join(tempDir, "audit-subnet.md")
	jsonPath := filepath.Join(tempDir, "audit-subnet.json")

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"audit",
		"subnet",
		"--cidr", "10.0.0.0/30",
		"--ports", "443",
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

	if !strings.Contains(string(markdownData), "# Surveyor Audit Report") {
		t.Fatalf("markdown output missing audit heading\n%s", string(markdownData))
	}
	if !strings.Contains(string(jsonData), "\"input_kind\": \"cidr\"") || !strings.Contains(string(jsonData), "\"cidr\": \"10.0.0.0/30\"") || !strings.Contains(string(jsonData), "\"profile\": \"cautious\"") || !strings.Contains(string(jsonData), "\"timeout\": \"3s\"") {
		t.Fatalf("json output missing remote audit metadata\n%s", string(jsonData))
	}
}

func TestRunAuditSubnetFailsOnRunnerError(t *testing.T) {
	originalRunner := newRemoteAuditRunner
	t.Cleanup(func() {
		newRemoteAuditRunner = originalRunner
	})
	newRemoteAuditRunner = func(config.RemoteScope, func() time.Time) auditRunner {
		return stubLocalAuditRunner{err: errors.New("remote audit failed")}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"audit", "subnet", "--cidr", "10.0.0.0/30", "--ports", "443"}, &stdout, &stderr, fixedNow)

	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "audit subnet: remote audit failed") {
		t.Fatalf("stderr = %q, want runner error", stderr.String())
	}
}

func TestRunAuditSubnetDryRunWritesPlan(t *testing.T) {
	originalRunner := newRemoteAuditRunner
	t.Cleanup(func() {
		newRemoteAuditRunner = originalRunner
	})

	called := false
	newRemoteAuditRunner = func(config.RemoteScope, func() time.Time) auditRunner {
		called = true
		return stubLocalAuditRunner{}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"audit",
		"subnet",
		"--cidr", "10.0.0.0/30",
		"--ports", "443,8443",
		"--dry-run",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if called {
		t.Fatal("newRemoteAuditRunner was called during dry run, want no network execution path")
	}
	if !strings.Contains(stdout.String(), "# Surveyor Execution Plan") {
		t.Fatalf("stdout = %q, want execution plan output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Supported scanners: tls") {
		t.Fatalf("stdout = %q, want audit dry-run scanner set", stdout.String())
	}
}

func TestRunAuditSubnetDryRunRejectsJSON(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"audit",
		"subnet",
		"--cidr", "10.0.0.0/30",
		"--ports", "443",
		"--dry-run",
		"--json", "plan.json",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "does not support --json") {
		t.Fatalf("stderr = %q, want dry-run json rejection", stderr.String())
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
	if !strings.Contains(stdout.String(), "surveyor discover remote") {
		t.Fatalf("stdout = %q, want canonical remote discovery help text", stdout.String())
	}
	if !strings.Contains(stdout.String(), "surveyor discover subnet") {
		t.Fatalf("stdout = %q, want subnet discovery help text", stdout.String())
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
	newLocalDiscoverer = func() discoverer {
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
	if !strings.Contains(stdout.String(), "## Scope") {
		t.Fatalf("stdout = %q, want report scope metadata", stdout.String())
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
	newLocalDiscoverer = func() discoverer {
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
	if !strings.Contains(string(jsonData), "\"scope\": {") || !strings.Contains(string(jsonData), "\"scope_kind\": \"local\"") {
		t.Fatalf("json output missing local discovery scope metadata\n%s", string(jsonData))
	}
}

func TestRunDiscoverLocalFailsOnEnumeratorError(t *testing.T) {
	originalDiscoverer := newLocalDiscoverer
	t.Cleanup(func() {
		newLocalDiscoverer = originalDiscoverer
	})
	newLocalDiscoverer = func() discoverer {
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

func TestRunDiscoverSubnetHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "subnet", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stderr.String(), "--cidr") {
		t.Fatalf("stderr = %q, want subnet discovery flags", stderr.String())
	}
	if strings.Contains(stderr.String(), "  --targets-file") {
		t.Fatalf("stderr = %q, want no targets-file flag line in subnet alias help", stderr.String())
	}
	if !strings.Contains(stderr.String(), "only accepts --cidr, not --targets-file") {
		t.Fatalf("stderr = %q, want explicit CIDR-only alias guidance", stderr.String())
	}
}

func TestRunDiscoverRemoteHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "remote", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stderr.String(), "--targets-file") {
		t.Fatalf("stderr = %q, want targets-file flag in remote help", stderr.String())
	}
}

func TestRunDiscoverRemoteWritesMarkdownToStdout(t *testing.T) {
	originalDiscoverer := newRemoteDiscoverer
	t.Cleanup(func() {
		newRemoteDiscoverer = originalDiscoverer
	})
	newRemoteDiscoverer = func(config.RemoteScope) discoverer {
		return stubLocalDiscoverer{
			results: []core.DiscoveredEndpoint{
				{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "10.0.0.10",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Hints: []core.DiscoveryHint{
						{Protocol: "tls", Confidence: "low", Evidence: []string{"transport=tcp", "port=443"}},
					},
				},
			},
		}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "remote", "--cidr", "10.0.0.0/30", "--ports", "443"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# Surveyor Discovery Report") {
		t.Fatalf("stdout = %q, want discovery markdown output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: cidr") || !strings.Contains(stdout.String(), "CIDR: 10.0.0.0/30") {
		t.Fatalf("stdout = %q, want canonical remote scope metadata", stdout.String())
	}
}

func TestRunDiscoverRemoteTargetsFileDryRunWritesPlan(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	targetsFile := filepath.Join(tempDir, "approved-hosts.txt")
	if err := os.WriteFile(targetsFile, []byte("10.0.0.10\nexample.com\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"discover",
		"remote",
		"--targets-file", targetsFile,
		"--ports", "443,8443",
		"--dry-run",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: targets_file") || !strings.Contains(stdout.String(), "Targets file: "+targetsFile) {
		t.Fatalf("stdout = %q, want targets-file execution plan metadata", stdout.String())
	}
}

func TestRunDiscoverRemoteTargetsFileWritesMarkdownToStdout(t *testing.T) {
	originalDiscoverer := newRemoteDiscoverer
	t.Cleanup(func() {
		newRemoteDiscoverer = originalDiscoverer
	})

	var gotScope config.RemoteScope
	newRemoteDiscoverer = func(scope config.RemoteScope) discoverer {
		gotScope = scope
		return stubLocalDiscoverer{
			results: []core.DiscoveredEndpoint{
				{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Hints: []core.DiscoveryHint{
						{Protocol: "tls", Confidence: "low", Evidence: []string{"transport=tcp", "port=443"}},
					},
				},
			},
		}
	}

	tempDir := t.TempDir()
	targetsFile := filepath.Join(tempDir, "approved-hosts.txt")
	if err := os.WriteFile(targetsFile, []byte("example.com\n10.0.0.10\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"discover",
		"remote",
		"--targets-file", targetsFile,
		"--ports", "443",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if gotScope.InputKind != config.RemoteScopeInputKindTargetsFile {
		t.Fatalf("scope.InputKind = %q, want targets_file", gotScope.InputKind)
	}
	if gotScope.TargetsFile != targetsFile {
		t.Fatalf("scope.TargetsFile = %q, want %q", gotScope.TargetsFile, targetsFile)
	}
	if strings.Join(gotScope.Hosts, ",") != "example.com,10.0.0.10" {
		t.Fatalf("scope.Hosts = %v, want declared host order", gotScope.Hosts)
	}
	if !strings.Contains(stdout.String(), "# Surveyor Discovery Report") {
		t.Fatalf("stdout = %q, want discovery markdown output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: targets_file") || !strings.Contains(stdout.String(), "Targets file: "+targetsFile) {
		t.Fatalf("stdout = %q, want targets-file report metadata", stdout.String())
	}
}

func TestRunDiscoverSubnetRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "subnet", "--cidr", "10.0.0.0/30", "--ports", "443", "extra"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "discover subnet does not accept positional arguments") {
		t.Fatalf("stderr = %q, want positional argument rejection", stderr.String())
	}
}

func TestRunDiscoverSubnetRequiresScopeAndPorts(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "subnet"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "--cidr is required") {
		t.Fatalf("stderr = %q, want subnet scope validation error", stderr.String())
	}
}

func TestRunDiscoverSubnetWritesMarkdownToStdout(t *testing.T) {
	originalDiscoverer := newRemoteDiscoverer
	t.Cleanup(func() {
		newRemoteDiscoverer = originalDiscoverer
	})
	newRemoteDiscoverer = func(config.RemoteScope) discoverer {
		return stubLocalDiscoverer{
			results: []core.DiscoveredEndpoint{
				{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "10.0.0.10",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Hints: []core.DiscoveryHint{
						{Protocol: "tls", Confidence: "low", Evidence: []string{"transport=tcp", "port=443"}},
					},
				},
			},
		}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "subnet", "--cidr", "10.0.0.0/30", "--ports", "443"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# Surveyor Discovery Report") {
		t.Fatalf("stdout = %q, want discovery markdown output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: cidr") || !strings.Contains(stdout.String(), "CIDR: 10.0.0.0/30") {
		t.Fatalf("stdout = %q, want remote scope metadata", stdout.String())
	}
}

func TestRunDiscoverSubnetWritesOutputs(t *testing.T) {
	originalDiscoverer := newRemoteDiscoverer
	t.Cleanup(func() {
		newRemoteDiscoverer = originalDiscoverer
	})
	newRemoteDiscoverer = func(config.RemoteScope) discoverer {
		return stubLocalDiscoverer{
			results: []core.DiscoveredEndpoint{
				{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "10.0.0.10",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
				},
			},
		}
	}

	tempDir := t.TempDir()
	markdownPath := filepath.Join(tempDir, "subnet.md")
	jsonPath := filepath.Join(tempDir, "subnet.json")

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"discover",
		"subnet",
		"--cidr", "10.0.0.0/30",
		"--ports", "443",
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
	if !strings.Contains(string(jsonData), "\"input_kind\": \"cidr\"") || !strings.Contains(string(jsonData), "\"cidr\": \"10.0.0.0/30\"") || !strings.Contains(string(jsonData), "\"profile\": \"cautious\"") || !strings.Contains(string(jsonData), "\"timeout\": \"3s\"") {
		t.Fatalf("json output missing remote discovery metadata\n%s", string(jsonData))
	}
}

func TestRunDiscoverSubnetFailsOnEnumeratorError(t *testing.T) {
	originalDiscoverer := newRemoteDiscoverer
	t.Cleanup(func() {
		newRemoteDiscoverer = originalDiscoverer
	})
	newRemoteDiscoverer = func(config.RemoteScope) discoverer {
		return stubLocalDiscoverer{err: errors.New("remote enumeration failed")}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"discover", "subnet", "--cidr", "10.0.0.0/30", "--ports", "443"}, &stdout, &stderr, fixedNow)

	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "discover subnet: remote enumeration failed") {
		t.Fatalf("stderr = %q, want enumerator error", stderr.String())
	}
}

func TestRunDiscoverSubnetDryRunWritesPlan(t *testing.T) {
	originalDiscoverer := newRemoteDiscoverer
	t.Cleanup(func() {
		newRemoteDiscoverer = originalDiscoverer
	})

	called := false
	newRemoteDiscoverer = func(config.RemoteScope) discoverer {
		called = true
		return stubLocalDiscoverer{}
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"discover",
		"subnet",
		"--cidr", "10.0.0.0/30",
		"--ports", "443,8443",
		"--dry-run",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if called {
		t.Fatal("newRemoteDiscoverer was called during dry run, want no network execution path")
	}
	if !strings.Contains(stdout.String(), "# Surveyor Execution Plan") {
		t.Fatalf("stdout = %q, want execution plan output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Network I/O: disabled (dry run)") {
		t.Fatalf("stdout = %q, want dry-run safety text", stdout.String())
	}
}

func TestRunDiscoverSubnetDryRunRejectsJSON(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"discover",
		"subnet",
		"--cidr", "10.0.0.0/30",
		"--ports", "443",
		"--dry-run",
		"--json", "plan.json",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "does not support --json") {
		t.Fatalf("stderr = %q, want dry-run json rejection", stderr.String())
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
