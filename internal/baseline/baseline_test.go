package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

func TestParseReportHeader(t *testing.T) {
	t.Parallel()

	header, err := ParseReportHeader([]byte(`{
  "schema_version": "1.0",
  "tool_version": "dev",
  "report_kind": "tls_scan",
  "scope_kind": "explicit",
  "scope_description": "explicit TLS targets from config",
  "generated_at": "2026-04-20T01:00:00Z",
  "scope": {
    "scope_kind": "explicit",
    "input_kind": "config"
  }
}`))
	if err != nil {
		t.Fatalf("ParseReportHeader() error = %v", err)
	}

	if got, want := header.ReportKind, core.ReportKindTLSScan; got != want {
		t.Fatalf("header.ReportKind = %q, want %q", got, want)
	}
	if got, want := header.ScopeKind, core.ReportScopeKindExplicit; got != want {
		t.Fatalf("header.ScopeKind = %q, want %q", got, want)
	}
	if header.Scope == nil {
		t.Fatal("header.Scope = nil, want populated scope")
	}
	if got, want := header.Scope.InputKind, core.ReportInputKindConfig; got != want {
		t.Fatalf("header.Scope.InputKind = %q, want %q", got, want)
	}
}

func TestReadReportHeader(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	data := `{
  "schema_version": "1.0",
  "tool_version": "dev",
  "report_kind": "audit",
  "scope_kind": "remote",
  "scope_description": "remote audit from targets file approved-hosts.txt over ports 443",
  "generated_at": "2026-04-20T01:00:00Z",
  "scope": {
    "scope_kind": "remote",
    "input_kind": "targets_file",
    "targets_file": "approved-hosts.txt",
    "ports": [443]
  }
}`

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	header, err := ReadReportHeader(path)
	if err != nil {
		t.Fatalf("ReadReportHeader() error = %v", err)
	}

	if got, want := header.Scope.TargetsFile, "approved-hosts.txt"; got != want {
		t.Fatalf("header.Scope.TargetsFile = %q, want %q", got, want)
	}
}

func TestParseReportHeaderRejectsMissingScopeMetadata(t *testing.T) {
	t.Parallel()

	_, err := ParseReportHeader([]byte(`{
  "schema_version": "1.0",
  "tool_version": "dev",
  "report_kind": "audit",
  "scope_kind": "remote",
  "scope_description": "remote audit within CIDR 10.0.0.0/30 over ports 443",
  "generated_at": "2026-04-20T01:00:00Z"
}`))
	if err == nil || !strings.Contains(err.Error(), "missing scope metadata") {
		t.Fatalf("ParseReportHeader() error = %v, want missing scope metadata", err)
	}
}

func TestValidateCompatibilityTLS(t *testing.T) {
	t.Parallel()

	baseline := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
	}
	current := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
	}

	comparison, err := ValidateCompatibility(baseline, current)
	if err != nil {
		t.Fatalf("ValidateCompatibility() error = %v", err)
	}
	if comparison.ScopeChanged {
		t.Fatal("comparison.ScopeChanged = true, want false")
	}
}

func TestValidateCompatibilityAuditAllowsScopeDifference(t *testing.T) {
	t.Parallel()

	baseline := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.0.0/30",
			Ports:     []int{443},
		},
	}
	current := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.1.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.1.0/30",
			Ports:     []int{443},
		},
	}

	comparison, err := ValidateCompatibility(baseline, current)
	if err != nil {
		t.Fatalf("ValidateCompatibility() error = %v", err)
	}
	if !comparison.ScopeChanged {
		t.Fatal("comparison.ScopeChanged = false, want true")
	}
}

func TestValidateCompatibilityRejectsMismatchedReportKinds(t *testing.T) {
	t.Parallel()

	baseline := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
	}
	current := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.0.0/30",
			Ports:     []int{443},
		},
	}

	_, err := ValidateCompatibility(baseline, current)
	if err == nil || !strings.Contains(err.Error(), "report kind mismatch") {
		t.Fatalf("ValidateCompatibility() error = %v, want report kind mismatch", err)
	}
}

func TestValidateCompatibilityRejectsUnsupportedReportKind(t *testing.T) {
	t.Parallel()

	header := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindDiscovery, core.ReportScopeKindRemote, "remote discovery within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.0.0/30",
			Ports:     []int{443},
		},
	}

	_, err := ValidateCompatibility(header, header)
	if err == nil || !strings.Contains(err.Error(), `not supported for diffing yet`) {
		t.Fatalf("ValidateCompatibility() error = %v, want unsupported discovery diff input", err)
	}
}

func TestValidateCompatibilityRejectsUnsupportedSchemaMajor(t *testing.T) {
	t.Parallel()

	baseline := ReportHeader{
		ReportMetadata: core.ReportMetadata{
			SchemaVersion:    "2.0",
			ToolVersion:      "dev",
			ReportKind:       core.ReportKindTLSScan,
			ScopeKind:        core.ReportScopeKindExplicit,
			ScopeDescription: "explicit TLS targets from config",
		},
		GeneratedAt: time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
	}
	current := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
	}

	_, err := ValidateCompatibility(baseline, current)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("ValidateCompatibility() error = %v, want unsupported schema major", err)
	}
}

func TestValidateCompatibilityRejectsAuditScopeKindMismatch(t *testing.T) {
	t.Parallel()

	baseline := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindLocal, "local audit"),
		GeneratedAt:    time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindLocal,
		},
	}
	current := ReportHeader{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.0.0/30",
			Ports:     []int{443},
		},
	}

	_, err := ValidateCompatibility(baseline, current)
	if err == nil || !strings.Contains(err.Error(), "scope kind mismatch") {
		t.Fatalf("ValidateCompatibility() error = %v, want scope kind mismatch", err)
	}
}

func TestIdentityKeys(t *testing.T) {
	t.Parallel()

	if got, want := TargetResultIdentityKey(core.TargetResult{Host: "EXAMPLE.COM", Port: 443}), "example.com|443"; got != want {
		t.Fatalf("TargetResultIdentityKey() = %q, want %q", got, want)
	}

	endpoint := core.DiscoveredEndpoint{
		ScopeKind: core.EndpointScopeKindRemote,
		Host:      "2001:0DB8::1",
		Port:      8443,
		Transport: "TCP",
	}
	if got, want := DiscoveredEndpointIdentityKey(endpoint), "remote|2001:db8::1|8443|tcp"; got != want {
		t.Fatalf("DiscoveredEndpointIdentityKey() = %q, want %q", got, want)
	}

	audit := core.AuditResult{DiscoveredEndpoint: endpoint}
	if got, want := AuditResultIdentityKey(audit), "remote|2001:db8::1|8443|tcp"; got != want {
		t.Fatalf("AuditResultIdentityKey() = %q, want %q", got, want)
	}
}
