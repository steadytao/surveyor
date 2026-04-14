package outputs

import (
	"os"
	"path/filepath"
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

func TestRenderMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleReport()

	markdown := RenderMarkdown(report)
	want := readGoldenFile(t, "report.golden.md")
	if markdown != want {
		t.Fatalf("markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func readGoldenFile(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", "outputs", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}

	return string(data)
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
