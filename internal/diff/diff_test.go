// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

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

	diffReport, err := BuildTLSReport(report, report, time.Date(2026, time.April, 21, 2, 0, 0, 0, time.UTC), nil)
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

	diffReport, err := BuildTLSReport(baselineReport, currentReport, time.Date(2026, time.April, 22, 2, 0, 0, 0, time.UTC), nil)
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

	diffReport, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 22, 2, 0, 0, 0, time.UTC), nil)
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

	first, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 22, 2, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}
	second, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 22, 2, 0, 0, 0, time.UTC), nil)
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

func TestBuildAuditReportAddsGroupedSummariesForInventoryMetadata(t *testing.T) {
	t.Parallel()

	baselineReport := core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file examples/inventory.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 24, 1, 0, 0, 0, time.UTC),
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
					Inventory: &core.InventoryAnnotation{
						Owner:       "payments",
						Environment: "prod",
						Provenance: []core.InventoryProvenance{
							{
								SourceKind:   core.InventorySourceKindInventoryFile,
								SourceFormat: core.InventorySourceFormatYAML,
								SourceName:   "examples/inventory.yaml",
								SourceRecord: "entries[0]",
							},
						},
					},
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
					ScannedAt:      time.Date(2026, time.April, 24, 1, 0, 0, 0, time.UTC),
					Classification: "modern_tls_classical_identity",
				},
			},
		},
	}

	currentReport := core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file examples/inventory.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 24, 2, 0, 0, 0, time.UTC),
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
					Inventory: &core.InventoryAnnotation{
						Owner:       "payments",
						Environment: "prod",
						Provenance: []core.InventoryProvenance{
							{
								SourceKind:   core.InventorySourceKindInventoryFile,
								SourceFormat: core.InventorySourceFormatYAML,
								SourceName:   "examples/inventory.yaml",
								SourceRecord: "entries[0]",
							},
						},
					},
				},
				Selection: core.AuditSelection{
					Status: core.AuditSelectionStatusSkipped,
					Reason: "endpoint did not respond during remote discovery",
				},
			},
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "admin.example.com",
					Port:      8443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Owner:       "platform",
						Environment: "dev",
						Provenance: []core.InventoryProvenance{
							{
								SourceKind:   core.InventorySourceKindInventoryFile,
								SourceFormat: core.InventorySourceFormatCSV,
								SourceName:   "exports/cmdb.csv",
								SourceRecord: "line 2",
							},
						},
					},
				},
				Selection: core.AuditSelection{
					Status:          core.AuditSelectionStatusSelected,
					SelectedScanner: "tls",
					Reason:          "tls hint on tcp/8443",
				},
			},
		},
	}

	report, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 24, 3, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}

	if got, want := len(report.GroupedSummaries), 3; got != want {
		t.Fatalf("len(report.GroupedSummaries) = %d, want %d", got, want)
	}

	ownerSummary := report.GroupedSummaries[0]
	if got, want := ownerSummary.GroupBy, core.WorkflowGroupByOwner; got != want {
		t.Fatalf("ownerSummary.GroupBy = %q, want %q", got, want)
	}
	if got, want := ownerSummary.Groups[0].Key, "payments"; got != want {
		t.Fatalf("ownerSummary.Groups[0].Key = %q, want %q", got, want)
	}
	if got, want := ownerSummary.Groups[0].TotalItems, 1; got != want {
		t.Fatalf("ownerSummary.Groups[0].TotalItems = %d, want %d", got, want)
	}
	if got, want := ownerSummary.Groups[1].Key, "platform"; got != want {
		t.Fatalf("ownerSummary.Groups[1].Key = %q, want %q", got, want)
	}
	if got, want := ownerSummary.Groups[1].TotalItems, 1; got != want {
		t.Fatalf("ownerSummary.Groups[1].TotalItems = %d, want %d", got, want)
	}

	environmentSummary := report.GroupedSummaries[1]
	if got, want := environmentSummary.GroupBy, core.WorkflowGroupByEnvironment; got != want {
		t.Fatalf("environmentSummary.GroupBy = %q, want %q", got, want)
	}
	if got, want := environmentSummary.Groups[0].Key, "dev"; got != want {
		t.Fatalf("environmentSummary.Groups[0].Key = %q, want %q", got, want)
	}
	if got, want := environmentSummary.Groups[1].Key, "prod"; got != want {
		t.Fatalf("environmentSummary.Groups[1].Key = %q, want %q", got, want)
	}

	sourceSummary := report.GroupedSummaries[2]
	if got, want := sourceSummary.GroupBy, core.WorkflowGroupBySource; got != want {
		t.Fatalf("sourceSummary.GroupBy = %q, want %q", got, want)
	}
	if got, want := sourceSummary.Groups[0].Key, "examples/inventory.yaml"; got != want {
		t.Fatalf("sourceSummary.Groups[0].Key = %q, want %q", got, want)
	}
	if got, want := sourceSummary.Groups[1].Key, "exports/cmdb.csv"; got != want {
		t.Fatalf("sourceSummary.Groups[1].Key = %q, want %q", got, want)
	}
}

func TestBuildAuditReportAppliesWorkflowView(t *testing.T) {
	t.Parallel()

	baselineReport := core.AuditReport{
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
				Selection: core.AuditSelection{
					Status:          core.AuditSelectionStatusSelected,
					SelectedScanner: "tls",
					Reason:          "tls hint on tcp/443",
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

	currentReport := core.AuditReport{
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
				Selection: core.AuditSelection{
					Status: core.AuditSelectionStatusSkipped,
					Reason: "endpoint did not respond during remote discovery",
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
					},
				},
				Selection: core.AuditSelection{
					Status: core.AuditSelectionStatusSkipped,
					Reason: "endpoint did not respond during remote discovery",
				},
			},
		},
	}

	report, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 25, 3, 0, 0, 0, time.UTC), &core.WorkflowContext{
		GroupBy: core.WorkflowGroupByOwner,
		Filters: []core.WorkflowFilter{
			{
				Field:  core.WorkflowFilterFieldEnvironment,
				Values: []string{"prod"},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}

	if report.WorkflowView == nil {
		t.Fatal("report.WorkflowView = nil, want populated workflow view")
	}
	if got, want := len(report.Changes), 1; got != want {
		t.Fatalf("len(report.Changes) = %d, want %d", got, want)
	}
	if got, want := report.Changes[0].IdentityKey, "remote|prod.example.com|443|tcp"; got != want {
		t.Fatalf("report.Changes[0].IdentityKey = %q, want %q", got, want)
	}
	if got, want := len(report.GroupedSummaries), 1; got != want {
		t.Fatalf("len(report.GroupedSummaries) = %d, want %d", got, want)
	}
	if got, want := report.GroupedSummaries[0].GroupBy, core.WorkflowGroupByOwner; got != want {
		t.Fatalf("report.GroupedSummaries[0].GroupBy = %q, want %q", got, want)
	}
	if got, want := report.GroupedSummaries[0].Groups[0].Key, "payments"; got != want {
		t.Fatalf("report.GroupedSummaries[0].Groups[0].Key = %q, want %q", got, want)
	}
	if got, want := report.Summary.TotalBaselineEntities, 1; got != want {
		t.Fatalf("report.Summary.TotalBaselineEntities = %d, want %d", got, want)
	}
	if got, want := report.Summary.TotalCurrentEntities, 1; got != want {
		t.Fatalf("report.Summary.TotalCurrentEntities = %d, want %d", got, want)
	}
}

func TestBuildAuditReportWorkflowFilterIncludesMetadataTransitions(t *testing.T) {
	t.Parallel()

	baselineReport := core.AuditReport{
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
					Host:      "api.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Owner:       "payments",
						Environment: "prod",
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

	currentReport := core.AuditReport{
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
					Host:      "api.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Owner:       "platform",
						Environment: "prod",
					},
				},
				Selection: core.AuditSelection{
					Status: core.AuditSelectionStatusSkipped,
					Reason: "endpoint did not respond during remote discovery",
				},
			},
		},
	}

	report, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 25, 3, 0, 0, 0, time.UTC), &core.WorkflowContext{
		GroupBy: core.WorkflowGroupByOwner,
		Filters: []core.WorkflowFilter{
			{
				Field:  core.WorkflowFilterFieldOwner,
				Values: []string{"payments"},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}

	if got, want := len(report.Changes), 1; got != want {
		t.Fatalf("len(report.Changes) = %d, want %d", got, want)
	}
	if got, want := report.Changes[0].IdentityKey, "remote|api.example.com|443|tcp"; got != want {
		t.Fatalf("report.Changes[0].IdentityKey = %q, want %q", got, want)
	}
	if got, want := len(report.GroupedSummaries), 1; got != want {
		t.Fatalf("len(report.GroupedSummaries) = %d, want %d", got, want)
	}
	if got, want := report.GroupedSummaries[0].Groups[0].Key, "payments"; got != want {
		t.Fatalf("report.GroupedSummaries[0].Groups[0].Key = %q, want %q", got, want)
	}
	if got, want := report.GroupedSummaries[0].Groups[1].Key, "platform"; got != want {
		t.Fatalf("report.GroupedSummaries[0].Groups[1].Key = %q, want %q", got, want)
	}
}

func TestBuildAuditReportSourceGroupingIncludesMetadataTransitions(t *testing.T) {
	t.Parallel()

	baselineReport := core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file baseline.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 25, 1, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind:     core.ReportScopeKindRemote,
			InputKind:     core.ReportInputKindInventoryFile,
			InventoryFile: "baseline.yaml",
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "api.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Provenance: []core.InventoryProvenance{
							{
								SourceKind:   core.InventorySourceKindInventoryFile,
								SourceFormat: core.InventorySourceFormatYAML,
								SourceName:   "baseline.yaml",
								SourceRecord: "entries[0]",
							},
						},
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

	currentReport := core.AuditReport{
		ReportMetadata: core.NewReportMetadata(core.ReportKindAudit, core.ReportScopeKindRemote, "remote audit from inventory file current.yaml"),
		GeneratedAt:    time.Date(2026, time.April, 25, 2, 0, 0, 0, time.UTC),
		Scope: &core.ReportScope{
			ScopeKind:     core.ReportScopeKindRemote,
			InputKind:     core.ReportInputKindInventoryFile,
			InventoryFile: "current.yaml",
		},
		Results: []core.AuditResult{
			{
				DiscoveredEndpoint: core.DiscoveredEndpoint{
					ScopeKind: core.EndpointScopeKindRemote,
					Host:      "api.example.com",
					Port:      443,
					Transport: "tcp",
					State:     "responsive",
					Inventory: &core.InventoryAnnotation{
						Provenance: []core.InventoryProvenance{
							{
								SourceKind:   core.InventorySourceKindInventoryFile,
								SourceFormat: core.InventorySourceFormatYAML,
								SourceName:   "current.yaml",
								SourceRecord: "entries[0]",
							},
						},
					},
				},
				Selection: core.AuditSelection{
					Status: core.AuditSelectionStatusSkipped,
					Reason: "endpoint did not respond during remote discovery",
				},
			},
		},
	}

	report, err := BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 25, 3, 0, 0, 0, time.UTC), &core.WorkflowContext{
		GroupBy: core.WorkflowGroupBySource,
	})
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}

	if got, want := len(report.GroupedSummaries), 1; got != want {
		t.Fatalf("len(report.GroupedSummaries) = %d, want %d", got, want)
	}
	if got, want := report.GroupedSummaries[0].Groups[0].Key, "baseline.yaml"; got != want {
		t.Fatalf("report.GroupedSummaries[0].Groups[0].Key = %q, want %q", got, want)
	}
	if got, want := report.GroupedSummaries[0].Groups[1].Key, "current.yaml"; got != want {
		t.Fatalf("report.GroupedSummaries[0].Groups[1].Key = %q, want %q", got, want)
	}
}

func TestBuildTLSReportRejectsWorkflowView(t *testing.T) {
	t.Parallel()

	source := core.Report{
		ReportMetadata: core.NewReportMetadata(core.ReportKindTLSScan, core.ReportScopeKindExplicit, "explicit TLS scan"),
		GeneratedAt:    time.Date(2026, time.April, 25, 1, 0, 0, 0, time.UTC),
	}

	_, err := BuildTLSReport(source, source, time.Date(2026, time.April, 25, 2, 0, 0, 0, time.UTC), &core.WorkflowContext{
		GroupBy: core.WorkflowGroupByOwner,
	})
	if err == nil {
		t.Fatal("BuildTLSReport() error = nil, want workflow-view rejection")
	}
	if !strings.Contains(err.Error(), "supported only for audit input") {
		t.Fatalf("BuildTLSReport() error = %v, want workflow-view rejection", err)
	}
}
