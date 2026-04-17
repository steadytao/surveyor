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
	"github.com/steadytao/surveyor/internal/outputs"
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
	if !strings.Contains(stdout.String(), "surveyor <command> [<args>...]") {
		t.Fatalf("stdout = %q, want standardised top-level usage", stdout.String())
	}
	if !strings.Contains(stdout.String(), "surveyor prioritize current.json") {
		t.Fatalf("stdout = %q, want top-level example text", stdout.String())
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
	if strings.Contains(stdout.String(), "during v0.5.x") {
		t.Fatalf("stdout = %q, want no expired compatibility-window wording", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunDiffHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"diff", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stderr.String(), "surveyor diff baseline.json current.json") {
		t.Fatalf("stderr = %q, want diff help text", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--group-by") || !strings.Contains(stderr.String(), "--include-environment") {
		t.Fatalf("stderr = %q, want workflow flag help text", stderr.String())
	}
}

func TestRunDiffRejectsMissingInputs(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"diff", "baseline.json"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "diff requires exactly two input files") {
		t.Fatalf("stderr = %q, want diff positional validation", stderr.String())
	}
}

func TestRunDiffWritesMarkdownToStdout(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	baselinePath := filepath.Join(tempDir, "baseline.json")
	currentPath := filepath.Join(tempDir, "current.json")

	writeTempAuditReport(t, baselinePath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 20, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.0.0/30",
			Ports:     []int{443},
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "example.com",
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
				TLSResult: &core.TargetResult{
					Host:                   "example.com",
					Port:                   443,
					ScannedAt:              time.Date(2026, time.April, 20, 1, 20, 0, 0, time.UTC),
					Reachable:              true,
					TLSVersion:             "TLS 1.2",
					CipherSuite:            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					LeafKeyAlgorithm:       "rsa",
					LeafSignatureAlgorithm: "sha256-rsa",
					Classification:         "legacy_tls_exposure",
					Findings: []core.Finding{
						{Code: "legacy-tls-version", Severity: core.SeverityHigh, Summary: "legacy"},
						{Code: "classical-certificate-identity", Severity: core.SeverityMedium, Summary: "classical"},
					},
					Warnings: []string{"baseline-warning"},
				},
			},
		},
		Summary: core.AuditSummary{
			TotalEndpoints:   1,
			TLSCandidates:    1,
			ScannedEndpoints: 1,
			SelectionBreakdown: map[string]int{
				"tls": 1,
			},
			VerifiedClassificationBreakdown: map[string]int{
				"legacy_tls_exposure": 1,
			},
		},
	})
	writeTempAuditReport(t, currentPath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.1.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 21, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.1.0/30",
			Ports:     []int{443},
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "example.com",
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
				TLSResult: &core.TargetResult{
					Host:                   "example.com",
					Port:                   443,
					ScannedAt:              time.Date(2026, time.April, 21, 1, 20, 0, 0, time.UTC),
					Reachable:              true,
					TLSVersion:             "TLS 1.3",
					CipherSuite:            "TLS_AES_128_GCM_SHA256",
					LeafKeyAlgorithm:       "rsa",
					LeafSignatureAlgorithm: "sha256-rsa",
					Classification:         "modern_tls_classical_identity",
					Findings: []core.Finding{
						{Code: "classical-certificate-identity", Severity: core.SeverityMedium, Summary: "classical"},
					},
				},
			},
		},
		Summary: core.AuditSummary{
			TotalEndpoints:   1,
			TLSCandidates:    1,
			ScannedEndpoints: 1,
			SelectionBreakdown: map[string]int{
				"tls": 1,
			},
			VerifiedClassificationBreakdown: map[string]int{
				"modern_tls_classical_identity": 1,
			},
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"diff", baselinePath, currentPath}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# Surveyor Diff Report") {
		t.Fatalf("stdout = %q, want diff markdown output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "classification_changed") || !strings.Contains(stdout.String(), "tls_version_changed") {
		t.Fatalf("stdout = %q, want rendered diff changes", stdout.String())
	}
}

func TestRunDiffSupportsTrailingFlagsAfterInputs(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	baselinePath := filepath.Join(tempDir, "baseline.json")
	currentPath := filepath.Join(tempDir, "current.json")
	markdownPath := filepath.Join(tempDir, "diff.md")
	jsonPath := filepath.Join(tempDir, "diff.json")

	writeTempTLSReport(t, baselinePath, core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 20, 1, 30, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
		Results: []core.TargetResult{
			{
				Host:                   "example.com",
				Port:                   443,
				ScannedAt:              time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
				Reachable:              true,
				TLSVersion:             "TLS 1.2",
				CipherSuite:            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "rsa",
				LeafSignatureAlgorithm: "sha256-rsa",
				Classification:         "legacy_tls_exposure",
			},
		},
		Summary: core.Summary{
			TotalTargets:       1,
			ReachableTargets:   1,
			UnreachableTargets: 0,
			ClassificationBreakdown: map[string]int{
				"legacy_tls_exposure": 1,
			},
		},
	})
	writeTempTLSReport(t, currentPath, core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 30, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
		Results: []core.TargetResult{
			{
				Host:                   "example.com",
				Port:                   443,
				ScannedAt:              time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
				Reachable:              true,
				TLSVersion:             "TLS 1.3",
				CipherSuite:            "TLS_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "rsa",
				LeafSignatureAlgorithm: "sha256-rsa",
				Classification:         "modern_tls_classical_identity",
			},
		},
		Summary: core.Summary{
			TotalTargets:       1,
			ReachableTargets:   1,
			UnreachableTargets: 0,
			ClassificationBreakdown: map[string]int{
				"modern_tls_classical_identity": 1,
			},
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"diff", baselinePath, currentPath, "-o", markdownPath, "-j", jsonPath}, &stdout, &stderr, fixedNow)

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

	if !strings.Contains(string(markdownData), "# Surveyor Diff Report") {
		t.Fatalf("markdown output missing diff heading\n%s", string(markdownData))
	}
	if !strings.Contains(string(jsonData), "\"report_kind\": \"diff\"") || !strings.Contains(string(jsonData), "\"changes\": [") {
		t.Fatalf("json output missing diff contract\n%s", string(jsonData))
	}
}

func TestRunDiffRejectsIncompatibleReports(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	baselinePath := filepath.Join(tempDir, "baseline.json")
	currentPath := filepath.Join(tempDir, "current.json")

	writeTempTLSReport(t, baselinePath, core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 20, 1, 30, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
	})
	writeTempAuditReport(t, currentPath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 30, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.0.0/30",
			Ports:     []int{443},
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"diff", baselinePath, currentPath}, &stdout, &stderr, fixedNow)

	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "report kind mismatch") {
		t.Fatalf("stderr = %q, want compatibility failure", stderr.String())
	}
}

func TestRunDiffRejectsWorkflowViewForTLSReports(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	baselinePath := filepath.Join(tempDir, "baseline.json")
	currentPath := filepath.Join(tempDir, "current.json")

	writeTempTLSReport(t, baselinePath, core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets"),
		GeneratedAt:    time.Date(2026, time.April, 25, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
	})
	writeTempTLSReport(t, currentPath, core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets"),
		GeneratedAt:    time.Date(2026, time.April, 25, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"diff", baselinePath, currentPath, "--group-by", "owner"}, &stdout, &stderr, fixedNow)

	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "supported only for audit input") {
		t.Fatalf("stderr = %q, want workflow-view rejection", stderr.String())
	}
}

func TestRunDiffAcceptsInventoryBackedAuditReports(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	baselinePath := filepath.Join(tempDir, "baseline.json")
	currentPath := filepath.Join(tempDir, "current.json")

	writeTempAuditReport(t, baselinePath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file examples/inventory-a.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 20, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind:     core.ReportScopeKindRemote,
			InputKind:     core.ReportInputKindInventoryFile,
			InventoryFile: "examples/inventory-a.yaml",
		},
	})
	writeTempAuditReport(t, currentPath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file examples/inventory-b.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 21, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind:     core.ReportScopeKindRemote,
			InputKind:     core.ReportInputKindInventoryFile,
			InventoryFile: "examples/inventory-b.yaml",
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"diff", baselinePath, currentPath}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Baseline scope: remote audit from inventory file examples/inventory-a.yaml") {
		t.Fatalf("stdout = %q, want inventory-backed diff scope", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Current scope: remote audit from inventory file examples/inventory-b.yaml") {
		t.Fatalf("stdout = %q, want current inventory-backed diff scope", stdout.String())
	}
}

func TestRunDiffAppliesWorkflowViewToAuditReports(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	baselinePath := filepath.Join(tempDir, "baseline.json")
	currentPath := filepath.Join(tempDir, "current.json")
	jsonPath := filepath.Join(tempDir, "diff.json")

	writeTempAuditReport(t, baselinePath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file examples/inventory.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 25, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind:     core.ReportScopeKindRemote,
			InputKind:     core.ReportInputKindInventoryFile,
			InventoryFile: "examples/inventory.yaml",
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "prod.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Owner:       "payments",
						Environment: "prod",
					},
				},
				Selection: core.AuditSelection{Status: core.AuditSelectionStatusSelected, SelectedScanner: "tls", Reason: "tls hint on tcp/443"},
			},
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "dev.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Owner:       "platform",
						Environment: "dev",
					},
				},
				Selection: core.AuditSelection{Status: core.AuditSelectionStatusSelected, SelectedScanner: "tls", Reason: "tls hint on tcp/443"},
			},
		},
	})
	writeTempAuditReport(t, currentPath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file examples/inventory.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 25, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind:     core.ReportScopeKindRemote,
			InputKind:     core.ReportInputKindInventoryFile,
			InventoryFile: "examples/inventory.yaml",
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "prod.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Owner:       "payments",
						Environment: "prod",
					},
				},
				Selection: core.AuditSelection{Status: core.AuditSelectionStatusSkipped, Reason: "endpoint did not respond during remote discovery"},
			},
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "dev.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Owner:       "platform",
						Environment: "dev",
					},
				},
				Selection: core.AuditSelection{Status: core.AuditSelectionStatusSkipped, Reason: "endpoint did not respond during remote discovery"},
			},
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"diff",
		baselinePath,
		currentPath,
		"--group-by", "owner",
		"--include-environment", "prod",
		"-j", jsonPath,
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile(json) error = %v", err)
	}

	jsonText := string(jsonData)
	if !strings.Contains(jsonText, `"workflow_view": {`) || !strings.Contains(jsonText, `"group_by": "owner"`) || !strings.Contains(jsonText, `"field": "environment"`) || !strings.Contains(jsonText, `"values": [`) || !strings.Contains(jsonText, `"prod"`) {
		t.Fatalf("json output missing workflow view\n%s", jsonText)
	}
	if !strings.Contains(jsonText, `"grouped_summaries": [`) || !strings.Contains(jsonText, `"group_by": "owner"`) || !strings.Contains(jsonText, `"key": "payments"`) {
		t.Fatalf("json output missing grouped summary\n%s", jsonText)
	}
	if strings.Contains(jsonText, "dev.example.com") {
		t.Fatalf("json output = %s, want filtered diff output without dev endpoint", jsonText)
	}
}

func TestRunPrioritizeHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"prioritize", "--help"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stderr.String(), "surveyor prioritize current.json") {
		t.Fatalf("stderr = %q, want prioritize help text", stderr.String())
	}
	if !strings.Contains(stderr.String(), "surveyor prioritise current.json") {
		t.Fatalf("stderr = %q, want prioritise alias in help text", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--group-by") || !strings.Contains(stderr.String(), "--include-tag") {
		t.Fatalf("stderr = %q, want workflow flag help text", stderr.String())
	}
}

func TestRunPrioritizeRejectsMissingInput(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"prioritize"}, &stdout, &stderr, fixedNow)

	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "prioritize requires exactly one input file") {
		t.Fatalf("stderr = %q, want prioritize positional validation", stderr.String())
	}
}

func TestRunPrioritizeWritesMarkdownToStdout(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	currentPath := filepath.Join(tempDir, "current.json")

	writeTempAuditReport(t, currentPath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 21, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.0.0/30",
			Ports:     []int{443},
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
				},
				Selection: core.AuditSelection{
					Status:          core.AuditSelectionStatusSelected,
					SelectedScanner: "tls",
					Reason:          "tls hint on tcp/443",
				},
				TLSResult: &core.TargetResult{
					Host:           "example.com",
					Port:           443,
					Reachable:      true,
					ScannedAt:      time.Date(2026, time.April, 21, 1, 20, 0, 0, time.UTC),
					Classification: "modern_tls_classical_identity",
					Findings: []core.Finding{
						{
							Code:           "classical-certificate-identity",
							Severity:       core.SeverityMedium,
							Summary:        "The observed certificate identity remains classical.",
							Evidence:       []string{"leaf_key_algorithm=rsa"},
							Recommendation: "Replace certificate identity.",
						},
					},
					Warnings: []string{"certificate metadata incomplete"},
				},
			},
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"prioritize", currentPath, "--profile", "migration-readiness"}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# Surveyor Prioritisation Report") {
		t.Fatalf("stdout = %q, want prioritisation markdown output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Profile: migration-readiness") || !strings.Contains(stdout.String(), "classical-certificate-identity") {
		t.Fatalf("stdout = %q, want rendered prioritisation details", stdout.String())
	}
}

func TestRunPrioritizeAcceptsInventoryBackedAuditReport(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	currentPath := filepath.Join(tempDir, "current.json")

	writeTempAuditReport(t, currentPath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file examples/inventory.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 21, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind:     core.ReportScopeKindRemote,
			InputKind:     core.ReportInputKindInventoryFile,
			InventoryFile: "examples/inventory.yaml",
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "api.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
				},
				Selection: core.AuditSelection{
					Status:          core.AuditSelectionStatusSelected,
					SelectedScanner: "tls",
					Reason:          "tls hint on tcp/443",
				},
				TLSResult: &core.TargetResult{
					Host:           "api.example.com",
					Port:           443,
					Reachable:      true,
					ScannedAt:      time.Date(2026, time.April, 21, 1, 20, 0, 0, time.UTC),
					Classification: "modern_tls_classical_identity",
					Findings: []core.Finding{
						{
							Code:           "classical-certificate-identity",
							Severity:       core.SeverityMedium,
							Summary:        "The observed certificate identity remains classical.",
							Evidence:       []string{"leaf_key_algorithm=rsa"},
							Recommendation: "Replace certificate identity.",
						},
					},
				},
			},
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"prioritize", currentPath}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Inventory file: examples/inventory.yaml") {
		t.Fatalf("stdout = %q, want inventory-backed prioritization scope", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Ports: per-entry inventory ports") {
		t.Fatalf("stdout = %q, want per-entry inventory port note", stdout.String())
	}
}

func TestRunPrioritizeAppliesWorkflowViewToAuditReports(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	currentPath := filepath.Join(tempDir, "current.json")
	jsonPath := filepath.Join(tempDir, "priorities.json")

	writeTempAuditReport(t, currentPath, core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file examples/inventory.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 25, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind:     core.ReportScopeKindRemote,
			InputKind:     core.ReportInputKindInventoryFile,
			InventoryFile: "examples/inventory.yaml",
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "prod.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Owner:       "payments",
						Environment: "prod",
						Tags:        []string{"external"},
					},
				},
				Selection: core.AuditSelection{Status: core.AuditSelectionStatusSelected, SelectedScanner: "tls", Reason: "tls hint on tcp/443"},
				TLSResult: &core.TargetResult{
					Host: "prod.example.com",
					Port: 443,
					Findings: []core.Finding{
						{Code: "legacy-tls-version", Severity: core.SeverityHigh, Summary: "Legacy TLS remains enabled."},
					},
				},
			},
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "dev.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Owner:       "platform",
						Environment: "dev",
						Tags:        []string{"internal"},
					},
				},
				Selection: core.AuditSelection{Status: core.AuditSelectionStatusSelected, SelectedScanner: "tls", Reason: "tls hint on tcp/443"},
				TLSResult: &core.TargetResult{
					Host: "dev.example.com",
					Port: 443,
					Findings: []core.Finding{
						{Code: "classical-certificate-identity", Severity: core.SeverityMedium, Summary: "The observed certificate identity remains classical."},
					},
				},
			},
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"prioritize",
		currentPath,
		"--group-by", "owner",
		"--include-tag", "external",
		"-j", jsonPath,
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile(json) error = %v", err)
	}

	jsonText := string(jsonData)
	if !strings.Contains(jsonText, `"workflow_view": {`) || !strings.Contains(jsonText, `"group_by": "owner"`) || !strings.Contains(jsonText, `"field": "tag"`) || !strings.Contains(jsonText, `"external"`) {
		t.Fatalf("json output missing workflow view\n%s", jsonText)
	}
	if !strings.Contains(jsonText, `"grouped_summaries": [`) || !strings.Contains(jsonText, `"key": "payments"`) {
		t.Fatalf("json output missing grouped summary\n%s", jsonText)
	}
	if strings.Contains(jsonText, "dev.example.com") {
		t.Fatalf("json output = %s, want filtered prioritization output without dev endpoint", jsonText)
	}
}

func TestRunPrioritizeSupportsTrailingFlagsAfterInput(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	currentPath := filepath.Join(tempDir, "current.json")
	markdownPath := filepath.Join(tempDir, "priorities.md")
	jsonPath := filepath.Join(tempDir, "priorities.json")

	writeTempTLSReport(t, currentPath, core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 30, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
		Results: []core.TargetResult{
			{
				Host:           "example.com",
				Port:           443,
				ScannedAt:      time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
				Reachable:      false,
				Classification: "unreachable",
				Findings: []core.Finding{
					{
						Code:     "target-unreachable",
						Severity: core.SeverityMedium,
						Summary:  "The target could not be reached with a TLS connection.",
						Evidence: []string{"dial timeout"},
					},
				},
				Errors: []string{"dial timeout"},
			},
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"prioritize", currentPath, "--profile", "change-risk", "-o", markdownPath, "-j", jsonPath}, &stdout, &stderr, fixedNow)

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

	if !strings.Contains(string(markdownData), "# Surveyor Prioritisation Report") {
		t.Fatalf("markdown output missing prioritisation heading\n%s", string(markdownData))
	}
	if !strings.Contains(string(jsonData), "\"report_kind\": \"prioritization\"") || !strings.Contains(string(jsonData), "\"profile\": \"change-risk\"") {
		t.Fatalf("json output missing prioritization contract\n%s", string(jsonData))
	}
}

func TestRunPrioritizeRejectsUnsupportedReportKind(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	currentPath := filepath.Join(tempDir, "current.json")

	writeTempDiscoveryReport(t, currentPath, core.DiscoveryReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindDiscovery, core.ReportScopeKindLocal, "local discovery"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 30, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindLocal,
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"prioritize", currentPath}, &stdout, &stderr, fixedNow)

	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "report_kind \"discovery\" is not supported for prioritization") {
		t.Fatalf("stderr = %q, want unsupported report kind failure", stderr.String())
	}
}

func TestRunPrioritizeRejectsWorkflowViewForTLSReports(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	currentPath := filepath.Join(tempDir, "current.json")

	writeTempTLSReport(t, currentPath, core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets"),
		GeneratedAt:    time.Date(2026, time.April, 25, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"prioritize", currentPath, "--group-by", "owner"}, &stdout, &stderr, fixedNow)

	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "supported only for audit input") {
		t.Fatalf("stderr = %q, want workflow-view rejection", stderr.String())
	}
}

func TestRunPrioritiseAliasWritesMarkdownToStdout(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	currentPath := filepath.Join(tempDir, "current.json")

	writeTempTLSReport(t, currentPath, core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 30, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
		Results: []core.TargetResult{
			{
				Host:           "down.example.com",
				Port:           443,
				ScannedAt:      time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
				Reachable:      false,
				Classification: "unreachable",
				Findings: []core.Finding{
					{
						Code:     "target-unreachable",
						Severity: core.SeverityMedium,
						Summary:  "The target could not be reached with a TLS connection.",
					},
				},
			},
		},
	})

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{"prioritise", currentPath}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# Surveyor Prioritisation Report") {
		t.Fatalf("stdout = %q, want prioritisation markdown output", stdout.String())
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
	if strings.Contains(stderr.String(), "  --inventory-file") {
		t.Fatalf("stderr = %q, want no inventory-file flag line in subnet alias help", stderr.String())
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
	if !strings.Contains(stderr.String(), "--inventory-file") {
		t.Fatalf("stderr = %q, want inventory-file flag in remote help", stderr.String())
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

func TestRunAuditRemoteInventoryFileDryRunWritesPlan(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "inventory.yaml")
	if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
		"version: 1",
		"entries:",
		"  - host: example.com",
		"    ports: [443, 8443]",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"audit",
		"remote",
		"--inventory-file", inventoryFile,
		"--dry-run",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: inventory_file") ||
		!strings.Contains(stdout.String(), "Inventory file: "+inventoryFile) ||
		!strings.Contains(stdout.String(), "Ports: per-entry inventory ports") {
		t.Fatalf("stdout = %q, want inventory-file execution plan metadata", stdout.String())
	}
}

func TestRunAuditRemoteInventoryFileWritesOutputs(t *testing.T) {
	t.Parallel()

	originalRunner := newRemoteAuditRunner
	t.Cleanup(func() {
		newRemoteAuditRunner = originalRunner
	})

	var gotScope config.RemoteScope
	newRemoteAuditRunner = func(scope config.RemoteScope, _ func() time.Time) auditRunner {
		gotScope = scope
		return stubLocalAuditRunner{
			results: []core.AuditResult{
				{
					DiscoveredEndpoint: core.DiscoveredEndpoint{
						ScopeKind: core.EndpointScopeKindRemote,
						Host:      "example.com",
						Port:      443,
						Transport: "tcp",
						State:     "responsive",
						Inventory: &core.InventoryAnnotation{
							Ports:       []int{443},
							Owner:       "Platform",
							Environment: "prod",
						},
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

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "inventory.yaml")
	if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
		"version: 1",
		"entries:",
		"  - host: example.com",
		"    ports: [443]",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	jsonPath := filepath.Join(tempDir, "audit.json")
	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"audit",
		"remote",
		"--inventory-file", inventoryFile,
		"--json", jsonPath,
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if gotScope.InputKind != config.RemoteScopeInputKindInventoryFile {
		t.Fatalf("scope.InputKind = %q, want inventory_file", gotScope.InputKind)
	}
	if gotScope.InventoryFile != inventoryFile {
		t.Fatalf("scope.InventoryFile = %q, want %q", gotScope.InventoryFile, inventoryFile)
	}
	if len(gotScope.Targets) != 1 {
		t.Fatalf("len(scope.Targets) = %d, want 1", len(gotScope.Targets))
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty when only JSON output is requested", stdout.String())
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile(json) error = %v", err)
	}
	if !strings.Contains(string(jsonData), "\"input_kind\": \"inventory_file\"") ||
		!strings.Contains(string(jsonData), "\"inventory_file\": ") ||
		!strings.Contains(string(jsonData), "\"owner\": \"Platform\"") {
		t.Fatalf("json output = %s, want inventory-backed audit metadata and annotation", string(jsonData))
	}
}

func TestRunAuditRemoteTargetsFileWritesMarkdownToStdout(t *testing.T) {
	originalRunner := newRemoteAuditRunner
	t.Cleanup(func() {
		newRemoteAuditRunner = originalRunner
	})

	var gotScope config.RemoteScope
	newRemoteAuditRunner = func(scope config.RemoteScope, _ func() time.Time) auditRunner {
		gotScope = scope
		return stubLocalAuditRunner{
			results: []core.AuditResult{
				{
					DiscoveredEndpoint: core.DiscoveredEndpoint{
						ScopeKind: core.EndpointScopeKindRemote,
						Host:      "example.com",
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

	tempDir := t.TempDir()
	targetsFile := filepath.Join(tempDir, "approved-hosts.txt")
	if err := os.WriteFile(targetsFile, []byte("example.com\n10.0.0.10\n"), 0o644); err != nil {
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
	if !strings.Contains(stdout.String(), "# Surveyor Audit Report") {
		t.Fatalf("stdout = %q, want audit markdown output", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: targets_file") || !strings.Contains(stdout.String(), "Targets file: "+targetsFile) {
		t.Fatalf("stdout = %q, want targets-file report metadata", stdout.String())
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
	if strings.Contains(stderr.String(), "  --inventory-file") {
		t.Fatalf("stderr = %q, want no inventory-file flag line in subnet alias help", stderr.String())
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
	if !strings.Contains(stderr.String(), "--inventory-file") {
		t.Fatalf("stderr = %q, want inventory-file flag in remote help", stderr.String())
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

func TestRunDiscoverRemoteInventoryFileDryRunWritesPlan(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "inventory.yaml")
	if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
		"version: 1",
		"entries:",
		"  - host: example.com",
		"    ports: [443, 8443]",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"discover",
		"remote",
		"--inventory-file", inventoryFile,
		"--dry-run",
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Input kind: inventory_file") ||
		!strings.Contains(stdout.String(), "Inventory file: "+inventoryFile) ||
		!strings.Contains(stdout.String(), "Ports: per-entry inventory ports") {
		t.Fatalf("stdout = %q, want inventory-file execution plan metadata", stdout.String())
	}
}

func TestRunDiscoverRemoteInventoryFileWritesOutputs(t *testing.T) {
	t.Parallel()

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
					Inventory: &core.InventoryAnnotation{
						Ports:       []int{443},
						Owner:       "Platform",
						Environment: "prod",
					},
				},
			},
		}
	}

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "inventory.yaml")
	if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
		"version: 1",
		"entries:",
		"  - host: example.com",
		"    ports: [443]",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	jsonPath := filepath.Join(tempDir, "discovery.json")
	var stdout strings.Builder
	var stderr strings.Builder

	exitCode := run([]string{
		"discover",
		"remote",
		"--inventory-file", inventoryFile,
		"--json", jsonPath,
	}, &stdout, &stderr, fixedNow)

	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if gotScope.InputKind != config.RemoteScopeInputKindInventoryFile {
		t.Fatalf("scope.InputKind = %q, want inventory_file", gotScope.InputKind)
	}
	if gotScope.InventoryFile != inventoryFile {
		t.Fatalf("scope.InventoryFile = %q, want %q", gotScope.InventoryFile, inventoryFile)
	}
	if len(gotScope.Targets) != 1 {
		t.Fatalf("len(scope.Targets) = %d, want 1", len(gotScope.Targets))
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty when only JSON output is requested", stdout.String())
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile(json) error = %v", err)
	}
	if !strings.Contains(string(jsonData), "\"input_kind\": \"inventory_file\"") ||
		!strings.Contains(string(jsonData), "\"inventory_file\": ") ||
		!strings.Contains(string(jsonData), "\"owner\": \"Platform\"") {
		t.Fatalf("json output = %s, want inventory-backed discovery metadata and annotation", string(jsonData))
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

func writeTempTLSReport(t *testing.T, path string, report core.Report) {
	t.Helper()

	data, err := outputs.MarshalJSON(report)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func writeTempAuditReport(t *testing.T, path string, report core.AuditReport) {
	t.Helper()

	data, err := outputs.MarshalAuditJSON(report)
	if err != nil {
		t.Fatalf("MarshalAuditJSON() error = %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func writeTempDiscoveryReport(t *testing.T, path string, report core.DiscoveryReport) {
	t.Helper()

	data, err := outputs.MarshalDiscoveryJSON(report)
	if err != nil {
		t.Fatalf("MarshalDiscoveryJSON() error = %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
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
