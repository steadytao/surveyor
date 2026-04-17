package prioritize

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

func TestParseProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    Profile
		wantErr bool
	}{
		{name: "default", input: "", want: ProfileMigrationReadiness},
		{name: "migration readiness", input: "migration-readiness", want: ProfileMigrationReadiness},
		{name: "change risk", input: "change-risk", want: ProfileChangeRisk},
		{name: "invalid", input: "critical-first", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseProfile(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseProfile() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseProfile() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseProfile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildTLSReportMigrationReadiness(t *testing.T) {
	t.Parallel()

	source := core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
		Results: []core.TargetResult{
			{
				Host:           "legacy.example.com",
				Port:           443,
				Reachable:      true,
				ScannedAt:      time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
				TLSVersion:     "TLS 1.0",
				Classification: "legacy_tls_exposure",
				Findings: []core.Finding{
					{
						Code:           "legacy-tls-version",
						Severity:       core.SeverityHigh,
						Summary:        "The service negotiated a legacy TLS version.",
						Evidence:       []string{"tls_version=TLS 1.0"},
						Recommendation: "Upgrade transport posture.",
					},
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
	}

	report, err := BuildTLSReport(source, ProfileMigrationReadiness, time.Date(2026, time.April, 23, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildTLSReport() error = %v", err)
	}

	if got, want := report.ReportKind, core.ReportKindPrioritization; got != want {
		t.Fatalf("report.ReportKind = %q, want %q", got, want)
	}
	if got, want := report.SourceReportKind, core.ReportKindTLSScan; got != want {
		t.Fatalf("report.SourceReportKind = %q, want %q", got, want)
	}
	if got, want := report.Profile, ProfileMigrationReadiness; got != want {
		t.Fatalf("report.Profile = %q, want %q", got, want)
	}
	if got, want := report.Summary.TotalItems, 3; got != want {
		t.Fatalf("report.Summary.TotalItems = %d, want %d", got, want)
	}
	if got, want := report.Items[0].Code, "legacy-tls-version"; got != want {
		t.Fatalf("report.Items[0].Code = %q, want %q", got, want)
	}
	if got, want := report.Items[1].Code, "classical-certificate-identity"; got != want {
		t.Fatalf("report.Items[1].Code = %q, want %q", got, want)
	}
	if got, want := report.Items[2].Code, "endpoint-warnings"; got != want {
		t.Fatalf("report.Items[2].Code = %q, want %q", got, want)
	}
	if report.Items[0].Rank != 1 || report.Items[1].Rank != 2 || report.Items[2].Rank != 3 {
		t.Fatalf("item ranks = [%d %d %d], want [1 2 3]", report.Items[0].Rank, report.Items[1].Rank, report.Items[2].Rank)
	}
}

func TestBuildTLSReportChangeRisk(t *testing.T) {
	t.Parallel()

	source := core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
		Results: []core.TargetResult{
			{
				Host:           "down.example.com",
				Port:           443,
				Reachable:      false,
				ScannedAt:      time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
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
			{
				Host:           "classical.example.com",
				Port:           443,
				Reachable:      true,
				ScannedAt:      time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
				Classification: "modern_tls_classical_identity",
				Findings: []core.Finding{
					{
						Code:     "classical-certificate-identity",
						Severity: core.SeverityMedium,
						Summary:  "The observed certificate identity remains classical.",
						Evidence: []string{"leaf_key_algorithm=rsa"},
					},
				},
			},
		},
	}

	report, err := BuildTLSReport(source, ProfileChangeRisk, time.Date(2026, time.April, 23, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildTLSReport() error = %v", err)
	}

	if got, want := report.Items[0].Code, "target-unreachable"; got != want {
		t.Fatalf("report.Items[0].Code = %q, want %q", got, want)
	}
	if got, want := report.Items[1].Code, "classical-certificate-identity"; got != want {
		t.Fatalf("report.Items[1].Code = %q, want %q", got, want)
	}
}

func TestBuildAuditReportIncludesSkippedSelection(t *testing.T) {
	t.Parallel()

	source := core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
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
					Host:      "10.0.0.10",
					Port:      443,
					Transport: "tcp",
					State:     "candidate",
					Errors:    []string{"connection refused"},
				},
				Selection: core.AuditSelection{
					Status: core.AuditSelectionStatusSkipped,
					Reason: "endpoint did not respond during remote discovery",
				},
			},
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
					ScannedAt:      time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
					Classification: "modern_tls_classical_identity",
					Findings: []core.Finding{
						{
							Code:     "classical-certificate-identity",
							Severity: core.SeverityMedium,
							Summary:  "The observed certificate identity remains classical.",
							Evidence: []string{"leaf_key_algorithm=rsa"},
						},
					},
				},
			},
		},
	}

	report, err := BuildAuditReport(source, ProfileChangeRisk, time.Date(2026, time.April, 23, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}

	gotCodes := make([]string, 0, len(report.Items))
	for _, item := range report.Items {
		gotCodes = append(gotCodes, item.Code)
	}
	slices.Sort(gotCodes)
	wantCodes := []string{"audit-selection-skipped", "classical-certificate-identity"}
	if !slices.Equal(gotCodes, wantCodes) {
		t.Fatalf("report item codes = %v, want %v", gotCodes, wantCodes)
	}

	if got, want := report.Items[0].Code, "audit-selection-skipped"; got != want {
		t.Fatalf("report.Items[0].Code = %q, want %q", got, want)
	}
	if got, want := report.Items[0].TargetIdentity, "remote|10.0.0.10|443|tcp"; got != want {
		t.Fatalf("report.Items[0].TargetIdentity = %q, want %q", got, want)
	}
}

func TestBuildAuditReportIsDeterministic(t *testing.T) {
	t.Parallel()

	source := core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindLocal, "local audit"),
		GeneratedAt:    time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindLocal,
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindLocal,
					Host:      "127.0.0.1",
					Port:      8443,
					Transport: "tcp",
					State:     "listening",
				},
				Selection: core.AuditSelection{
					Status:          core.AuditSelectionStatusSelected,
					SelectedScanner: "tls",
					Reason:          "tls hint on tcp/8443",
				},
				TLSResult: &core.TargetResult{
					Host:           "127.0.0.1",
					Port:           8443,
					Reachable:      true,
					ScannedAt:      time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
					Classification: "manual_review_required",
					Findings: []core.Finding{
						{
							Code:     "incomplete-certificate-observation",
							Severity: core.SeverityMedium,
							Summary:  "The TLS service was reachable, but the certificate evidence is incomplete.",
						},
					},
				},
			},
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindLocal,
					Host:      "127.0.0.1",
					Port:      9443,
					Transport: "tcp",
					State:     "listening",
				},
				Selection: core.AuditSelection{
					Status:          core.AuditSelectionStatusSelected,
					SelectedScanner: "tls",
					Reason:          "tls hint on tcp/9443",
				},
				TLSResult: &core.TargetResult{
					Host:           "127.0.0.1",
					Port:           9443,
					Reachable:      true,
					ScannedAt:      time.Date(2026, time.April, 22, 1, 0, 0, 0, time.UTC),
					Classification: "manual_review_required",
					Findings: []core.Finding{
						{
							Code:     "incomplete-certificate-observation",
							Severity: core.SeverityMedium,
							Summary:  "The TLS service was reachable, but the certificate evidence is incomplete.",
						},
					},
				},
			},
		},
	}

	first, err := BuildAuditReport(source, ProfileMigrationReadiness, time.Date(2026, time.April, 23, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}
	second, err := BuildAuditReport(source, ProfileMigrationReadiness, time.Date(2026, time.April, 23, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildAuditReport() second error = %v", err)
	}

	if !slices.EqualFunc(first.Items, second.Items, func(left Item, right Item) bool {
		return left.Rank == right.Rank &&
			left.Code == right.Code &&
			left.TargetIdentity == right.TargetIdentity &&
			left.Severity == right.Severity
	}) {
		t.Fatal("BuildAuditReport() produced non-deterministic item ordering")
	}

	if got, want := first.Items[0].TargetIdentity, "local|127.0.0.1|8443|tcp"; got != want {
		t.Fatalf("first.Items[0].TargetIdentity = %q, want %q", got, want)
	}
	if got, want := first.Items[1].TargetIdentity, "local|127.0.0.1|9443|tcp"; got != want {
		t.Fatalf("first.Items[1].TargetIdentity = %q, want %q", got, want)
	}
}

func TestReportJSONIncludesWorkflowSections(t *testing.T) {
	t.Parallel()

	report := Report{
		ReportMetadata:    core.NewReportMetadata(core.ReportKindPrioritization, core.ReportScopeKindRemote, "remote audit from inventory file examples/inventory.yaml"),
		GeneratedAt:       time.Date(2026, time.April, 24, 3, 0, 0, 0, time.UTC),
		Profile:           ProfileMigrationReadiness,
		SourceReportKind:  core.ReportKindAudit,
		SourceGeneratedAt: time.Date(2026, time.April, 24, 2, 30, 0, 0, time.UTC),
		WorkflowView: &core.WorkflowContext{
			GroupBy: core.WorkflowGroupByEnvironment,
			Filters: []core.WorkflowFilter{
				{
					Field:  core.WorkflowFilterFieldOwner,
					Values: []string{"payments"},
				},
			},
		},
		Summary: Summary{
			TotalItems: 1,
		},
		GroupedSummaries: []core.GroupedSummary{
			{
				GroupBy: core.WorkflowGroupByEnvironment,
				Groups: []core.GroupedSummaryGroup{
					{
						Key:        "prod",
						TotalItems: 1,
						SeverityBreakdown: map[string]int{
							"high": 1,
						},
						CodeBreakdown: map[string]int{
							"classical-certificate-identity": 1,
						},
					},
				},
			},
		},
		WorkflowFindings: []core.WorkflowFinding{
			{
				Severity:       core.SeverityMedium,
				Code:           "missing-environment",
				Summary:        "The imported endpoint is missing environment metadata.",
				TargetIdentity: "remote|api.example.com|443|tcp",
			},
		},
		Items: []Item{
			{
				Rank:           1,
				Severity:       core.SeverityHigh,
				Code:           "classical-certificate-identity",
				Summary:        "The observed certificate identity remains classical.",
				TargetIdentity: "remote|api.example.com|443|tcp",
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)
	wantSubstrings := []string{
		`"workflow_view":{"group_by":"environment","filters":[{"field":"owner","values":["payments"]}]}`,
		`"grouped_summaries":[{"group_by":"environment","groups":[{"key":"prod","total_items":1`,
		`"workflow_findings":[{"severity":"medium","code":"missing-environment","summary":"The imported endpoint is missing environment metadata.","target_identity":"remote|api.example.com|443|tcp"}]`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}
