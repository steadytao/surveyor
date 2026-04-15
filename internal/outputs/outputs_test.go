package outputs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

func TestBuildReportSummary(t *testing.T) {
	t.Parallel()

	report := BuildReport([]core.TargetResult{
		{
			Name:           "primary-site",
			Host:           "example.com",
			Port:           443,
			ScannedAt:      time.Date(2026, time.April, 14, 1, 0, 0, 0, time.UTC),
			Reachable:      true,
			Classification: "modern_tls_classical_identity",
		},
		{
			Host:           "legacy.example.com",
			Port:           443,
			ScannedAt:      time.Date(2026, time.April, 14, 1, 1, 0, 0, time.UTC),
			Reachable:      false,
			Classification: "unreachable",
		},
	}, time.Date(2026, time.April, 14, 1, 30, 0, 0, time.UTC))

	if report.Summary.TotalTargets != 2 {
		t.Fatalf("report.Summary.TotalTargets = %d, want 2", report.Summary.TotalTargets)
	}
	if report.Summary.ReachableTargets != 1 {
		t.Fatalf("report.Summary.ReachableTargets = %d, want 1", report.Summary.ReachableTargets)
	}
	if report.Summary.UnreachableTargets != 1 {
		t.Fatalf("report.Summary.UnreachableTargets = %d, want 1", report.Summary.UnreachableTargets)
	}
	if report.Summary.ClassificationBreakdown["modern_tls_classical_identity"] != 1 {
		t.Fatalf("classification count for modern_tls_classical_identity = %d, want 1", report.Summary.ClassificationBreakdown["modern_tls_classical_identity"])
	}
	if report.Summary.ClassificationBreakdown["unreachable"] != 1 {
		t.Fatalf("classification count for unreachable = %d, want 1", report.Summary.ClassificationBreakdown["unreachable"])
	}
}

func TestBuildDiscoveryReportSummary(t *testing.T) {
	t.Parallel()

	report := BuildDiscoveryReport([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "0.0.0.0",
			Port:      443,
			Transport: "tcp",
			State:     "listening",
			Hints: []core.DiscoveryHint{
				{Protocol: "tls", Confidence: "low"},
				{Protocol: "tls", Confidence: "low"},
			},
		},
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "127.0.0.1",
			Port:      53,
			Transport: "udp",
			State:     "bound",
		},
	}, time.Date(2026, time.April, 15, 1, 30, 0, 0, time.UTC))

	if report.Summary.TotalEndpoints != 2 {
		t.Fatalf("report.Summary.TotalEndpoints = %d, want 2", report.Summary.TotalEndpoints)
	}
	if report.Summary.TCPEndpoints != 1 {
		t.Fatalf("report.Summary.TCPEndpoints = %d, want 1", report.Summary.TCPEndpoints)
	}
	if report.Summary.UDPEndpoints != 1 {
		t.Fatalf("report.Summary.UDPEndpoints = %d, want 1", report.Summary.UDPEndpoints)
	}
	if report.Summary.HintBreakdown["tls"] != 1 {
		t.Fatalf("hint count for tls = %d, want 1", report.Summary.HintBreakdown["tls"])
	}
}

func TestBuildAuditReportSummary(t *testing.T) {
	t.Parallel()

	report := BuildAuditReport([]core.AuditResult{
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
			TLSResult: &core.TargetResult{
				Host:           "127.0.0.1",
				Port:           443,
				ScannedAt:      time.Date(2026, time.April, 16, 2, 0, 0, 0, time.UTC),
				Reachable:      true,
				Classification: "modern_tls_classical_identity",
			},
		},
		{
			DiscoveredEndpoint: core.DiscoveredEndpoint{
				ScopeKind: core.EndpointScopeKindLocal,
				Host:      "127.0.0.1",
				Port:      5353,
				Transport: "udp",
				State:     "bound",
			},
			Selection: core.AuditSelection{
				Status: core.AuditSelectionStatusSkipped,
				Reason: "no supported scanner for udp endpoint",
			},
		},
	}, time.Date(2026, time.April, 16, 2, 30, 0, 0, time.UTC))

	if report.Summary.TotalEndpoints != 2 {
		t.Fatalf("report.Summary.TotalEndpoints = %d, want 2", report.Summary.TotalEndpoints)
	}
	if report.Summary.TLSCandidates != 1 {
		t.Fatalf("report.Summary.TLSCandidates = %d, want 1", report.Summary.TLSCandidates)
	}
	if report.Summary.ScannedEndpoints != 1 {
		t.Fatalf("report.Summary.ScannedEndpoints = %d, want 1", report.Summary.ScannedEndpoints)
	}
	if report.Summary.SkippedEndpoints != 1 {
		t.Fatalf("report.Summary.SkippedEndpoints = %d, want 1", report.Summary.SkippedEndpoints)
	}
	if report.Summary.SelectionBreakdown["tls"] != 1 {
		t.Fatalf("selection count for tls = %d, want 1", report.Summary.SelectionBreakdown["tls"])
	}
	if report.Summary.VerifiedClassificationBreakdown["modern_tls_classical_identity"] != 1 {
		t.Fatalf("verified classification count = %d, want 1", report.Summary.VerifiedClassificationBreakdown["modern_tls_classical_identity"])
	}
}

func TestMarshalJSON(t *testing.T) {
	t.Parallel()

	report := sampleReport()

	data, err := MarshalJSON(report)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}

	want := readGoldenFile(t, "report.golden.json")
	if string(data) != want {
		t.Fatalf("json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalDiscoveryJSON(t *testing.T) {
	t.Parallel()

	report := sampleDiscoveryReport()

	data, err := MarshalDiscoveryJSON(report)
	if err != nil {
		t.Fatalf("MarshalDiscoveryJSON() error = %v", err)
	}

	want := readGoldenFile(t, "discovery.golden.json")
	if string(data) != want {
		t.Fatalf("discovery json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalAuditJSON(t *testing.T) {
	t.Parallel()

	report := sampleAuditReport()

	data, err := MarshalAuditJSON(report)
	if err != nil {
		t.Fatalf("MarshalAuditJSON() error = %v", err)
	}

	want := readGoldenFile(t, "audit.golden.json")
	if string(data) != want {
		t.Fatalf("audit json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestRenderMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleReport()

	markdown := RenderMarkdown(report)
	want := readGoldenFile(t, "report.golden.md")
	if markdown != want {
		t.Fatalf("markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderDiscoveryMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleDiscoveryReport()

	markdown := RenderDiscoveryMarkdown(report)
	want := readGoldenFile(t, "discovery.golden.md")
	if markdown != want {
		t.Fatalf("discovery markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderAuditMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleAuditReport()

	markdown := RenderAuditMarkdown(report)
	want := readGoldenFile(t, "audit.golden.md")
	if markdown != want {
		t.Fatalf("audit markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func readGoldenFile(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", "outputs", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}

	// Golden text files may be checked out with CRLF on some runners. Normalize
	// here so the tests assert content, not Git line-ending policy.
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func sampleReport() core.Report {
	return BuildReport([]core.TargetResult{
		{
			Name:                   "primary-site",
			Host:                   "example.com",
			Port:                   443,
			Address:                "203.0.113.10:443",
			ScannedAt:              time.Date(2026, time.April, 14, 1, 0, 0, 0, time.UTC),
			Reachable:              true,
			TLSVersion:             "TLS 1.3",
			CipherSuite:            "TLS_AES_128_GCM_SHA256",
			LeafKeyAlgorithm:       "rsa",
			LeafKeySize:            2048,
			LeafSignatureAlgorithm: "sha256-rsa",
			CertificateChain: []core.CertificateRef{
				{
					Subject:            "CN=example.com",
					Issuer:             "CN=Example CA",
					SerialNumber:       "1",
					NotBefore:          time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC),
					NotAfter:           time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
					DNSNames:           []string{"example.com", "www.example.com"},
					PublicKeyAlgorithm: "rsa",
					PublicKeySize:      2048,
					SignatureAlgorithm: "sha256-rsa",
				},
			},
			Classification: "modern_tls_classical_identity",
			Findings: []core.Finding{
				{
					Code:           "classical-certificate-identity",
					Severity:       core.SeverityMedium,
					Summary:        "The observed certificate identity remains classical.",
					Evidence:       []string{"leaf_key_algorithm=rsa", "leaf_signature_algorithm=sha256-rsa"},
					Recommendation: "Inventory certificate replacement and related PKI dependencies as part of migration planning.",
				},
			},
		},
		{
			Host:           "legacy.example.com",
			Port:           443,
			ScannedAt:      time.Date(2026, time.April, 14, 1, 1, 0, 0, time.UTC),
			Reachable:      false,
			Classification: "unreachable",
			Errors:         []string{"tls connection failed: connection attempt failed"},
			Findings: []core.Finding{
				{
					Code:     "target-unreachable",
					Severity: core.SeverityMedium,
					Summary:  "The target could not be reached with a TLS connection.",
					Evidence: []string{"tls connection failed: connection attempt failed"},
				},
			},
		},
	}, time.Date(2026, time.April, 14, 1, 30, 0, 0, time.UTC))
}

func sampleDiscoveryReport() core.DiscoveryReport {
	return BuildDiscoveryReportWithMetadata([]core.DiscoveredEndpoint{
		{
			ScopeKind:   core.EndpointScopeKindLocal,
			Host:        "0.0.0.0",
			Port:        443,
			Transport:   "tcp",
			State:       "listening",
			PID:         4321,
			ProcessName: "local-service",
			Executable:  "C:\\Program Files\\Surveyor Test\\local-service.exe",
			Hints: []core.DiscoveryHint{
				{
					Protocol:   "tls",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=443"},
				},
			},
		},
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "127.0.0.1",
			Port:      5353,
			Transport: "udp",
			State:     "bound",
			PID:       9876,
			Warnings:  []string{"process metadata unavailable"},
		},
	}, time.Date(2026, time.April, 15, 1, 45, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind: core.EndpointScopeKindLocal,
	}, nil)
}

func sampleAuditReport() core.AuditReport {
	return BuildAuditReportWithMetadata([]core.AuditResult{
		{
			DiscoveredEndpoint: core.DiscoveredEndpoint{
				ScopeKind:   core.EndpointScopeKindLocal,
				Host:        "0.0.0.0",
				Port:        443,
				Transport:   "tcp",
				State:       "listening",
				PID:         4321,
				ProcessName: "local-service",
				Executable:  "C:\\Program Files\\Surveyor Test\\local-service.exe",
				Hints: []core.DiscoveryHint{
					{
						Protocol:   "tls",
						Confidence: "low",
						Evidence:   []string{"transport=tcp", "port=443"},
					},
				},
			},
			Selection: core.AuditSelection{
				Status:          core.AuditSelectionStatusSelected,
				SelectedScanner: "tls",
				Reason:          "tls hint on tcp/443",
			},
			TLSResult: &core.TargetResult{
				Host:                   "127.0.0.1",
				Port:                   443,
				ScannedAt:              time.Date(2026, time.April, 16, 2, 0, 0, 0, time.UTC),
				Reachable:              true,
				TLSVersion:             "TLS 1.3",
				CipherSuite:            "TLS_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "rsa",
				LeafKeySize:            2048,
				LeafSignatureAlgorithm: "sha256-rsa",
				Classification:         "modern_tls_classical_identity",
			},
		},
		{
			DiscoveredEndpoint: core.DiscoveredEndpoint{
				ScopeKind: core.EndpointScopeKindLocal,
				Host:      "127.0.0.1",
				Port:      5353,
				Transport: "udp",
				State:     "bound",
				PID:       9876,
				Warnings:  []string{"process metadata unavailable"},
			},
			Selection: core.AuditSelection{
				Status: core.AuditSelectionStatusSkipped,
				Reason: "no supported scanner for udp endpoint",
			},
		},
	}, time.Date(2026, time.April, 16, 2, 30, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind: core.EndpointScopeKindLocal,
	}, nil)
}
