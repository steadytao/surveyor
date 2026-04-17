package diff

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

func TestBuildTLSReportIdentical(t *testing.T) {
	t.Parallel()

	report := core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 20, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
		Results: []core.TargetResult{
			{
				Host:                   "example.com",
				Port:                   443,
				Reachable:              true,
				ScannedAt:              time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
				TLSVersion:             "TLS 1.2",
				CipherSuite:            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "rsa",
				LeafSignatureAlgorithm: "sha256-rsa",
				Classification:         "modern_tls_classical_identity",
			},
		},
	}

	diffReport, err := BuildTLSReport(report, report, time.Date(2026, time.April, 21, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildTLSReport() error = %v", err)
	}

	if got, want := diffReport.ReportKind, core.ReportKindDiff; got != want {
		t.Fatalf("diffReport.ReportKind = %q, want %q", got, want)
	}
	if got, want := diffReport.ScopeKind, core.ReportScopeKindExplicit; got != want {
		t.Fatalf("diffReport.ScopeKind = %q, want %q", got, want)
	}
	if diffReport.Summary.ScopeChanged {
		t.Fatal("diffReport.Summary.ScopeChanged = true, want false")
	}
	if got, want := diffReport.Summary.UnchangedEntities, 1; got != want {
		t.Fatalf("diffReport.Summary.UnchangedEntities = %d, want %d", got, want)
	}
	if len(diffReport.Changes) != 0 {
		t.Fatalf("len(diffReport.Changes) = %d, want 0", len(diffReport.Changes))
	}
}

func TestBuildTLSReportDetectsAddedRemovedAndChanged(t *testing.T) {
	t.Parallel()

	baselineReport := core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 20, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
		Results: []core.TargetResult{
			{
				Host:                   "example.com",
				Port:                   443,
				Reachable:              true,
				ScannedAt:              time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
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
			{
				Host:                   "old.example.com",
				Port:                   443,
				Reachable:              true,
				ScannedAt:              time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
				TLSVersion:             "TLS 1.2",
				CipherSuite:            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "rsa",
				LeafSignatureAlgorithm: "sha256-rsa",
				Classification:         "modern_tls_classical_identity",
			},
		},
	}

	currentReport := core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS targets from config"),
		GeneratedAt:    time.Date(2026, time.April, 21, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindExplicit,
			InputKind: core.ReportInputKindConfig,
		},
		Results: []core.TargetResult{
			{
				Host:                   "example.com",
				Port:                   443,
				Reachable:              true,
				ScannedAt:              time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
				TLSVersion:             "TLS 1.3",
				CipherSuite:            "TLS_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "rsa",
				LeafSignatureAlgorithm: "sha256-rsa",
				Classification:         "modern_tls_classical_identity",
				Findings: []core.Finding{
					{Code: "classical-certificate-identity", Severity: core.SeverityMedium, Summary: "classical"},
				},
			},
			{
				Host:           "new.example.com",
				Port:           443,
				Reachable:      false,
				ScannedAt:      time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
				Classification: "unreachable",
				Errors:         []string{"dial timeout"},
			},
		},
	}

	diffReport, err := BuildTLSReport(baselineReport, currentReport, time.Date(2026, time.April, 22, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildTLSReport() error = %v", err)
	}

	if got, want := diffReport.Summary.TotalBaselineEntities, 2; got != want {
		t.Fatalf("diffReport.Summary.TotalBaselineEntities = %d, want %d", got, want)
	}
	if got, want := diffReport.Summary.TotalCurrentEntities, 2; got != want {
		t.Fatalf("diffReport.Summary.TotalCurrentEntities = %d, want %d", got, want)
	}
	if got, want := diffReport.Summary.AddedEntities, 1; got != want {
		t.Fatalf("diffReport.Summary.AddedEntities = %d, want %d", got, want)
	}
	if got, want := diffReport.Summary.RemovedEntities, 1; got != want {
		t.Fatalf("diffReport.Summary.RemovedEntities = %d, want %d", got, want)
	}
	if got, want := diffReport.Summary.ChangedEntities, 1; got != want {
		t.Fatalf("diffReport.Summary.ChangedEntities = %d, want %d", got, want)
	}

	gotCodes := make([]string, 0, len(diffReport.Changes))
	for _, change := range diffReport.Changes {
		gotCodes = append(gotCodes, change.Code)
	}
	wantCodes := []string{
		"classification_changed",
		"cipher_suite_changed",
		"findings_changed",
		"tls_version_changed",
		"warnings_changed",
		"new_endpoint",
		"removed_endpoint",
	}
	slices.Sort(gotCodes)
	slices.Sort(wantCodes)
	if !slices.Equal(gotCodes, wantCodes) {
		t.Fatalf("diffReport change codes = %v, want %v", gotCodes, wantCodes)
	}

	var tlsVersionChange Change
	found := false
	for _, change := range diffReport.Changes {
		if change.Code == "tls_version_changed" {
			tlsVersionChange = change
			found = true
			break
		}
	}
	if !found {
		t.Fatal("tls_version_changed change not found")
	}
	if got, want := tlsVersionChange.Direction, ChangeDirectionImproved; got != want {
		t.Fatalf("tlsVersionChange.Direction = %q, want %q", got, want)
	}
}

func TestBuildAuditReportDetectsRemoteChangeAndScopeDifference(t *testing.T) {
	t.Parallel()

	baselineReport := core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 20, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.0.0/30",
			Ports:     []int{443},
		},
		Execution: &core.ReportExecution{
			Profile:        "cautious",
			MaxHosts:       256,
			MaxConcurrency: 8,
			Timeout:        "3s",
		},
		Results: []core.AuditResult{
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
				TLSResult: &core.TargetResult{
					Host:                   "10.0.0.10",
					Port:                   443,
					Reachable:              true,
					ScannedAt:              time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
					TLSVersion:             "TLS 1.2",
					CipherSuite:            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					LeafKeyAlgorithm:       "rsa",
					LeafSignatureAlgorithm: "sha256-rsa",
					Classification:         "modern_tls_classical_identity",
					Findings: []core.Finding{
						{Code: "classical-certificate-identity", Severity: core.SeverityMedium, Summary: "classical"},
					},
				},
			},
		},
	}

	currentReport := core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit within CIDR 10.0.1.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 21, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind: core.ReportScopeKindRemote,
			InputKind: core.ReportInputKindCIDR,
			CIDR:      "10.0.1.0/30",
			Ports:     []int{443},
		},
		Execution: &core.ReportExecution{
			Profile:        "cautious",
			MaxHosts:       256,
			MaxConcurrency: 8,
			Timeout:        "3s",
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
		},
	}

	diffReport, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 22, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}

	if !diffReport.Summary.ScopeChanged {
		t.Fatal("diffReport.Summary.ScopeChanged = false, want true")
	}
	if got, want := diffReport.Summary.ChangedEntities, 1; got != want {
		t.Fatalf("diffReport.Summary.ChangedEntities = %d, want %d", got, want)
	}

	gotCodes := []string{}
	for _, change := range diffReport.Changes {
		gotCodes = append(gotCodes, change.Code)
	}
	wantCodes := []string{
		"errors_changed",
		"hint_changed",
		"reachability_changed",
		"selection_changed",
	}
	slices.Sort(gotCodes)
	slices.Sort(wantCodes)
	if !slices.Equal(gotCodes, wantCodes) {
		t.Fatalf("diffReport change codes = %v, want %v", gotCodes, wantCodes)
	}
}

func TestBuildAuditReportIsDeterministic(t *testing.T) {
	t.Parallel()

	baselineReport := core.AuditReport{
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
					Host:      "10.0.0.20",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
				},
				Selection: core.AuditSelection{Status: core.AuditSelectionStatusSelected, SelectedScanner: "tls", Reason: "tls hint on tcp/443"},
				TLSResult: &core.TargetResult{
					Host:           "10.0.0.20",
					Port:           443,
					Reachable:      true,
					ScannedAt:      time.Date(2026, time.April, 20, 1, 0, 0, 0, time.UTC),
					TLSVersion:     "TLS 1.2",
					Classification: "legacy_tls_exposure",
				},
			},
		},
	}

	currentReport := core.AuditReport{
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
					Host:      "10.0.0.20",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
				},
				Selection: core.AuditSelection{Status: core.AuditSelectionStatusSelected, SelectedScanner: "tls", Reason: "tls hint on tcp/443"},
				TLSResult: &core.TargetResult{
					Host:           "10.0.0.20",
					Port:           443,
					Reachable:      true,
					ScannedAt:      time.Date(2026, time.April, 21, 1, 0, 0, 0, time.UTC),
					TLSVersion:     "TLS 1.3",
					Classification: "modern_tls_classical_identity",
				},
			},
		},
	}

	first, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 22, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}
	second, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 22, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildAuditReport() second error = %v", err)
	}

	if !slices.EqualFunc(first.Changes, second.Changes, func(left Change, right Change) bool {
		return left.IdentityKey == right.IdentityKey &&
			left.Code == right.Code &&
			left.Direction == right.Direction &&
			left.Severity == right.Severity
	}) {
		t.Fatal("BuildAuditReport() produced non-deterministic change ordering")
	}
}

func TestReportJSONIncludesWorkflowSections(t *testing.T) {
	t.Parallel()

	report := Report{
		ReportMetadata:      core.NewReportMetadata(core.ReportKindDiff, core.ReportScopeKindRemote, "diff of audit reports"),
		GeneratedAt:         time.Date(2026, time.April, 24, 2, 0, 0, 0, time.UTC),
		BaselineReportKind:  core.ReportKindAudit,
		CurrentReportKind:   core.ReportKindAudit,
		BaselineGeneratedAt: time.Date(2026, time.April, 23, 2, 0, 0, 0, time.UTC),
		CurrentGeneratedAt:  time.Date(2026, time.April, 24, 2, 0, 0, 0, time.UTC),
		WorkflowView: &core.WorkflowContext{
			GroupBy: core.WorkflowGroupByOwner,
			Filters: []core.WorkflowFilter{
				{
					Field:  core.WorkflowFilterFieldEnvironment,
					Values: []string{"prod"},
				},
			},
		},
		Summary: Summary{
			TotalBaselineEntities: 1,
			TotalCurrentEntities:  1,
			ChangedEntities:       1,
		},
		GroupedSummaries: []core.GroupedSummary{
			{
				GroupBy: core.WorkflowGroupByOwner,
				Groups: []core.GroupedSummaryGroup{
					{
						Key:        "payments",
						TotalItems: 1,
						DirectionBreakdown: map[string]int{
							"worsened": 1,
						},
						ChangeBreakdown: map[string]int{
							"classification_changed": 1,
						},
					},
				},
			},
		},
		WorkflowFindings: []core.WorkflowFinding{
			{
				Severity:       core.SeverityLow,
				Code:           "missing-owner",
				Summary:        "The imported endpoint is missing owner metadata.",
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
		`"workflow_view":{"group_by":"owner","filters":[{"field":"environment","values":["prod"]}]}`,
		`"grouped_summaries":[{"group_by":"owner","groups":[{"key":"payments","total_items":1`,
		`"workflow_findings":[{"severity":"low","code":"missing-owner","summary":"The imported endpoint is missing owner metadata.","target_identity":"remote|api.example.com|443|tcp"}]`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}
