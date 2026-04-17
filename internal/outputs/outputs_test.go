package outputs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/core"
	diffreport "github.com/steadytao/surveyor/internal/diff"
	prioritizereport "github.com/steadytao/surveyor/internal/prioritize"
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

func TestBuildDiscoveryReportClonesNestedEvidence(t *testing.T) {
	t.Parallel()

	input := []core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "10.0.0.10",
			Port:      443,
			Transport: "tcp",
			State:     "responsive",
			Hints: []core.DiscoveryHint{
				{
					Protocol:   "tls",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=443"},
				},
			},
		},
	}

	report := BuildDiscoveryReport(input, time.Date(2026, time.April, 18, 1, 0, 0, 0, time.UTC))

	input[0].Hints[0].Evidence[0] = "mutated"

	if got, want := report.Results[0].Hints[0].Evidence[0], "transport=tcp"; got != want {
		t.Fatalf("report.Results[0].Hints[0].Evidence[0] = %q, want %q", got, want)
	}
}

func TestBuildDiscoveryReportClonesInventoryAnnotation(t *testing.T) {
	t.Parallel()

	input := []core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "api.example.com",
			Port:      443,
			Transport: "tcp",
			State:     "responsive",
			Inventory: &core.InventoryAnnotation{
				Ports:       []int{443, 8443},
				Name:        "Payments API",
				Owner:       "payments",
				Environment: "prod",
				Tags:        []string{"external", "critical"},
				Notes:       "Internet-facing service",
				Provenance: []core.InventoryProvenance{
					{
						SourceKind:   core.InventorySourceKindInventoryFile,
						SourceFormat: core.InventorySourceFormatYAML,
						SourceName:   "ingress.yaml",
						SourceRecord: "documents[0]",
						Adapter:      core.InventoryAdapterKubernetesIngressV1,
						SourceObject: "Ingress/default/payments-api",
					},
				},
				AdapterWarnings: []core.InventoryAdapterWarning{
					{
						Code:     "controller-specific-behaviour",
						Summary:  "The ingress controller may affect effective exposure and TLS handling.",
						Evidence: []string{"adapter=kubernetes-ingress-v1", "source_name=ingress.yaml", "source_object=Ingress/default/payments-api"},
					},
				},
			},
		},
	}

	report := BuildDiscoveryReport(input, time.Date(2026, time.April, 18, 1, 5, 0, 0, time.UTC))

	input[0].Inventory.Ports[0] = 9443
	input[0].Inventory.Tags[0] = "internal"
	input[0].Inventory.Provenance[0].SourceRecord = "line 99"
	input[0].Inventory.Provenance[0].SourceObject = "mutated"
	input[0].Inventory.AdapterWarnings[0].Evidence[0] = "mutated"

	if got, want := report.Results[0].Inventory.Ports[0], 443; got != want {
		t.Fatalf("report.Results[0].Inventory.Ports[0] = %d, want %d", got, want)
	}
	if got, want := report.Results[0].Inventory.Tags[0], "external"; got != want {
		t.Fatalf("report.Results[0].Inventory.Tags[0] = %q, want %q", got, want)
	}
	if got, want := report.Results[0].Inventory.Provenance[0].SourceRecord, "documents[0]"; got != want {
		t.Fatalf("report.Results[0].Inventory.Provenance[0].SourceRecord = %q, want %q", got, want)
	}
	if got, want := report.Results[0].Inventory.Provenance[0].SourceObject, "Ingress/default/payments-api"; got != want {
		t.Fatalf("report.Results[0].Inventory.Provenance[0].SourceObject = %q, want %q", got, want)
	}
	if got, want := report.Results[0].Inventory.AdapterWarnings[0].Evidence[0], "adapter=kubernetes-ingress-v1"; got != want {
		t.Fatalf("report.Results[0].Inventory.AdapterWarnings[0].Evidence[0] = %q, want %q", got, want)
	}
}

func TestBuildDiscoveryReportInventoryScopeDescription(t *testing.T) {
	t.Parallel()

	report := BuildDiscoveryReportWithMetadata(nil, time.Date(2026, time.April, 21, 4, 0, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/inventory.csv",
		Ports:         []int{443, 8443},
	}, nil)

	if got, want := report.ScopeDescription, "remote discovery from inventory file examples/inventory.csv over ports 443,8443"; got != want {
		t.Fatalf("report.ScopeDescription = %q, want %q", got, want)
	}
}

func TestBuildAuditReportInventoryScopeDescription(t *testing.T) {
	t.Parallel()

	report := BuildAuditReportWithMetadata(nil, time.Date(2026, time.April, 21, 4, 5, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/inventory.yaml",
	}, nil)

	if got, want := report.ScopeDescription, "remote audit from inventory file examples/inventory.yaml"; got != want {
		t.Fatalf("report.ScopeDescription = %q, want %q", got, want)
	}
}

func TestBuildAuditReportInventoryAdapterScopeDescription(t *testing.T) {
	t.Parallel()

	report := BuildAuditReportWithMetadata(nil, time.Date(2026, time.April, 21, 4, 10, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/caddy.json",
		Adapter:       core.InventoryAdapterCaddy,
	}, nil)

	if got, want := report.ScopeDescription, "remote audit from inventory file examples/caddy.json via caddy adapter"; got != want {
		t.Fatalf("report.ScopeDescription = %q, want %q", got, want)
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

func TestMarshalRemoteDiscoveryJSON(t *testing.T) {
	t.Parallel()

	report := sampleRemoteDiscoveryReport()

	data, err := MarshalDiscoveryJSON(report)
	if err != nil {
		t.Fatalf("MarshalDiscoveryJSON() error = %v", err)
	}

	want := readGoldenFile(t, "discovery-remote.golden.json")
	if string(data) != want {
		t.Fatalf("remote discovery json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalInventoryDiscoveryJSON(t *testing.T) {
	t.Parallel()

	report := sampleInventoryDiscoveryReport()

	data, err := MarshalDiscoveryJSON(report)
	if err != nil {
		t.Fatalf("MarshalDiscoveryJSON() error = %v", err)
	}

	want := readGoldenFile(t, "discovery-inventory.golden.json")
	if string(data) != want {
		t.Fatalf("inventory discovery json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalCaddyDiscoveryJSON(t *testing.T) {
	t.Parallel()

	report := sampleCaddyDiscoveryReport()

	data, err := MarshalDiscoveryJSON(report)
	if err != nil {
		t.Fatalf("MarshalDiscoveryJSON() error = %v", err)
	}

	want := readGoldenFile(t, "discovery-caddy.golden.json")
	if string(data) != want {
		t.Fatalf("caddy discovery json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
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

func TestMarshalRemoteAuditJSON(t *testing.T) {
	t.Parallel()

	report := sampleRemoteAuditReport()

	data, err := MarshalAuditJSON(report)
	if err != nil {
		t.Fatalf("MarshalAuditJSON() error = %v", err)
	}

	want := readGoldenFile(t, "audit-remote.golden.json")
	if string(data) != want {
		t.Fatalf("remote audit json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalInventoryAuditJSON(t *testing.T) {
	t.Parallel()

	report := sampleInventoryAuditReport()

	data, err := MarshalAuditJSON(report)
	if err != nil {
		t.Fatalf("MarshalAuditJSON() error = %v", err)
	}

	want := readGoldenFile(t, "audit-inventory.golden.json")
	if string(data) != want {
		t.Fatalf("inventory audit json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalKubernetesAuditJSON(t *testing.T) {
	t.Parallel()

	report := sampleKubernetesAuditReport()

	data, err := MarshalAuditJSON(report)
	if err != nil {
		t.Fatalf("MarshalAuditJSON() error = %v", err)
	}

	want := readGoldenFile(t, "audit-kubernetes.golden.json")
	if string(data) != want {
		t.Fatalf("kubernetes audit json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalDiffJSON(t *testing.T) {
	t.Parallel()

	report := sampleDiffReport(t)

	data, err := MarshalDiffJSON(report)
	if err != nil {
		t.Fatalf("MarshalDiffJSON() error = %v", err)
	}

	want := readGoldenFile(t, "diff.golden.json")
	if string(data) != want {
		t.Fatalf("diff json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalWorkflowDiffJSON(t *testing.T) {
	t.Parallel()

	report := sampleWorkflowDiffReport(t)

	data, err := MarshalDiffJSON(report)
	if err != nil {
		t.Fatalf("MarshalDiffJSON() error = %v", err)
	}

	want := readGoldenFile(t, "diff-workflow.golden.json")
	if string(data) != want {
		t.Fatalf("workflow diff json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalPrioritizationJSON(t *testing.T) {
	t.Parallel()

	report := samplePrioritizationReport(t)

	data, err := MarshalPrioritizationJSON(report)
	if err != nil {
		t.Fatalf("MarshalPrioritizationJSON() error = %v", err)
	}

	want := readGoldenFile(t, "priorities.golden.json")
	if string(data) != want {
		t.Fatalf("prioritization json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
	}
}

func TestMarshalWorkflowPrioritizationJSON(t *testing.T) {
	t.Parallel()

	report := sampleWorkflowPrioritizationReport(t)

	data, err := MarshalPrioritizationJSON(report)
	if err != nil {
		t.Fatalf("MarshalPrioritizationJSON() error = %v", err)
	}

	want := readGoldenFile(t, "priorities-workflow.golden.json")
	if string(data) != want {
		t.Fatalf("workflow prioritization json output mismatch\nwant:\n%s\ngot:\n%s", want, string(data))
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

func TestRenderMarkdownUsesNamedTargetHeadingWithEndpoint(t *testing.T) {
	t.Parallel()

	report := BuildReport([]core.TargetResult{
		{
			Name:      "ipv6-site",
			Host:      "2001:db8::1",
			Port:      443,
			ScannedAt: time.Date(2026, time.April, 14, 1, 0, 0, 0, time.UTC),
		},
	}, time.Date(2026, time.April, 14, 1, 30, 0, 0, time.UTC))

	markdown := RenderMarkdown(report)
	if !strings.Contains(markdown, "### ipv6-site ([2001:db8::1]:443)") {
		t.Fatalf("markdown = %q, want bracketed IPv6 target heading", markdown)
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

func TestRenderRemoteDiscoveryMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleRemoteDiscoveryReport()

	markdown := RenderDiscoveryMarkdown(report)
	want := readGoldenFile(t, "discovery-remote.golden.md")
	if markdown != want {
		t.Fatalf("remote discovery markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderInventoryDiscoveryMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleInventoryDiscoveryReport()

	markdown := RenderDiscoveryMarkdown(report)
	want := readGoldenFile(t, "discovery-inventory.golden.md")
	if markdown != want {
		t.Fatalf("inventory discovery markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderCaddyDiscoveryMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleCaddyDiscoveryReport()

	markdown := RenderDiscoveryMarkdown(report)
	want := readGoldenFile(t, "discovery-caddy.golden.md")
	if markdown != want {
		t.Fatalf("caddy discovery markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderDiscoveryMarkdownUsesBracketedIPv6Heading(t *testing.T) {
	t.Parallel()

	report := BuildDiscoveryReport([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "2001:db8::1",
			Port:      8443,
			Transport: "tcp",
			State:     "responsive",
		},
	}, time.Date(2026, time.April, 23, 1, 15, 0, 0, time.UTC))

	markdown := RenderDiscoveryMarkdown(report)
	if !strings.Contains(markdown, "### [2001:db8::1]:8443/tcp") {
		t.Fatalf("markdown = %q, want bracketed IPv6 discovery heading", markdown)
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

func TestRenderRemoteAuditMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleRemoteAuditReport()

	markdown := RenderAuditMarkdown(report)
	want := readGoldenFile(t, "audit-remote.golden.md")
	if markdown != want {
		t.Fatalf("remote audit markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderInventoryAuditMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleInventoryAuditReport()

	markdown := RenderAuditMarkdown(report)
	want := readGoldenFile(t, "audit-inventory.golden.md")
	if markdown != want {
		t.Fatalf("inventory audit markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderKubernetesAuditMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleKubernetesAuditReport()

	markdown := RenderAuditMarkdown(report)
	want := readGoldenFile(t, "audit-kubernetes.golden.md")
	if markdown != want {
		t.Fatalf("kubernetes audit markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderInventoryAuditMarkdownShowsAdapter(t *testing.T) {
	t.Parallel()

	report := sampleInventoryAuditReport()
	report.Scope.Adapter = core.InventoryAdapterCaddy

	markdown := RenderAuditMarkdown(report)
	if !strings.Contains(markdown, "Inventory file: examples/inventory.yaml") {
		t.Fatalf("markdown = %q, want inventory file line", markdown)
	}
	if !strings.Contains(markdown, "Adapter: caddy") {
		t.Fatalf("markdown = %q, want adapter line", markdown)
	}
}

func TestRenderDiffMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleDiffReport(t)

	markdown := RenderDiffMarkdown(report)
	want := readGoldenFile(t, "diff.golden.md")
	if markdown != want {
		t.Fatalf("diff markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderWorkflowDiffMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleWorkflowDiffReport(t)

	markdown := RenderDiffMarkdown(report)
	want := readGoldenFile(t, "diff-workflow.golden.md")
	if markdown != want {
		t.Fatalf("workflow diff markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderPrioritizationMarkdown(t *testing.T) {
	t.Parallel()

	report := samplePrioritizationReport(t)

	markdown := RenderPrioritizationMarkdown(report)
	want := readGoldenFile(t, "priorities.golden.md")
	if markdown != want {
		t.Fatalf("prioritization markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
	}
}

func TestRenderWorkflowPrioritizationMarkdown(t *testing.T) {
	t.Parallel()

	report := sampleWorkflowPrioritizationReport(t)

	markdown := RenderPrioritizationMarkdown(report)
	want := readGoldenFile(t, "priorities-workflow.golden.md")
	if markdown != want {
		t.Fatalf("workflow prioritization markdown output mismatch\nwant:\n%s\ngot:\n%s", want, markdown)
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
	return BuildReportWithMetadata([]core.TargetResult{
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
	}, time.Date(2026, time.April, 14, 1, 30, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind: core.ReportScopeKindExplicit,
		InputKind: core.ReportInputKindConfig,
	})
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
		ScopeKind: core.ReportScopeKindLocal,
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
		ScopeKind: core.ReportScopeKindLocal,
	}, nil)
}

func sampleRemoteDiscoveryReport() core.DiscoveryReport {
	return BuildDiscoveryReportWithMetadata([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "example.com",
			Port:      443,
			Transport: "tcp",
			State:     "responsive",
			Hints: []core.DiscoveryHint{
				{
					Protocol:   "tls",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=443"},
				},
			},
		},
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "10.0.0.10",
			Port:      443,
			Transport: "tcp",
			State:     "candidate",
			Errors:    []string{"connection refused"},
		},
	}, time.Date(2026, time.April, 20, 1, 15, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:   core.ReportScopeKindRemote,
		InputKind:   core.ReportInputKindTargetsFile,
		TargetsFile: "examples/approved-hosts.txt",
		Ports:       []int{443},
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})
}

func sampleRemoteAuditReport() core.AuditReport {
	return BuildAuditReportWithMetadata([]core.AuditResult{
		{
			DiscoveredEndpoint: core.DiscoveredEndpoint{
				ScopeKind: core.EndpointScopeKindRemote,
				Host:      "example.com",
				Port:      443,
				Transport: "tcp",
				State:     "responsive",
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
				Host:                   "example.com",
				Port:                   443,
				ScannedAt:              time.Date(2026, time.April, 20, 1, 20, 0, 0, time.UTC),
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
	}, time.Date(2026, time.April, 20, 1, 30, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:   core.ReportScopeKindRemote,
		InputKind:   core.ReportInputKindTargetsFile,
		TargetsFile: "examples/approved-hosts.txt",
		Ports:       []int{443},
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})
}

func sampleInventoryDiscoveryReport() core.DiscoveryReport {
	return BuildDiscoveryReportWithMetadata([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "api.example.com",
			Port:      443,
			Transport: "tcp",
			State:     "responsive",
			Inventory: &core.InventoryAnnotation{
				Ports:       []int{443, 8443},
				Name:        "Payments API",
				Owner:       "payments",
				Environment: "prod",
				Tags:        []string{"critical", "external"},
				Notes:       "Internet-facing service",
				Provenance: []core.InventoryProvenance{
					{
						SourceKind:   core.InventorySourceKindInventoryFile,
						SourceFormat: core.InventorySourceFormatYAML,
						SourceName:   "examples/inventory.yaml",
						SourceRecord: "entries[0]",
					},
				},
			},
			Hints: []core.DiscoveryHint{
				{
					Protocol:   "tls",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=443"},
				},
			},
		},
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "10.0.0.10",
			Port:      8443,
			Transport: "tcp",
			State:     "candidate",
			Inventory: &core.InventoryAnnotation{
				Ports:       []int{8443},
				Name:        "Admin Console",
				Owner:       "platform",
				Environment: "prod",
				Tags:        []string{"internal"},
				Provenance: []core.InventoryProvenance{
					{
						SourceKind:   core.InventorySourceKindInventoryFile,
						SourceFormat: core.InventorySourceFormatYAML,
						SourceName:   "examples/inventory.yaml",
						SourceRecord: "entries[1]",
					},
				},
			},
			Errors: []string{"connection refused"},
		},
	}, time.Date(2026, time.April, 23, 1, 15, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/inventory.yaml",
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})
}

func sampleInventoryAuditReport() core.AuditReport {
	return BuildAuditReportWithMetadata([]core.AuditResult{
		{
			DiscoveredEndpoint: core.DiscoveredEndpoint{
				ScopeKind: core.EndpointScopeKindRemote,
				Host:      "api.example.com",
				Port:      443,
				Transport: "tcp",
				State:     "responsive",
				Inventory: &core.InventoryAnnotation{
					Ports:       []int{443, 8443},
					Name:        "Payments API",
					Owner:       "payments",
					Environment: "prod",
					Tags:        []string{"critical", "external"},
					Notes:       "Internet-facing service",
					Provenance: []core.InventoryProvenance{
						{
							SourceKind:   core.InventorySourceKindInventoryFile,
							SourceFormat: core.InventorySourceFormatYAML,
							SourceName:   "examples/inventory.yaml",
							SourceRecord: "entries[0]",
						},
					},
				},
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
				Host:                   "api.example.com",
				Port:                   443,
				ScannedAt:              time.Date(2026, time.April, 23, 1, 20, 0, 0, time.UTC),
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
				ScopeKind: core.EndpointScopeKindRemote,
				Host:      "10.0.0.10",
				Port:      8443,
				Transport: "tcp",
				State:     "candidate",
				Inventory: &core.InventoryAnnotation{
					Ports:       []int{8443},
					Name:        "Admin Console",
					Owner:       "platform",
					Environment: "prod",
					Tags:        []string{"internal"},
					Provenance: []core.InventoryProvenance{
						{
							SourceKind:   core.InventorySourceKindInventoryFile,
							SourceFormat: core.InventorySourceFormatYAML,
							SourceName:   "examples/inventory.yaml",
							SourceRecord: "entries[1]",
						},
					},
				},
				Errors: []string{"connection refused"},
			},
			Selection: core.AuditSelection{
				Status: core.AuditSelectionStatusSkipped,
				Reason: "endpoint did not respond during remote discovery",
			},
		},
	}, time.Date(2026, time.April, 23, 1, 30, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/inventory.yaml",
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})
}

func sampleCaddyDiscoveryReport() core.DiscoveryReport {
	return BuildDiscoveryReportWithMetadata([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "api.example.com",
			Port:      443,
			Transport: "tcp",
			State:     "responsive",
			Inventory: &core.InventoryAnnotation{
				Ports: []int{443, 444},
				Provenance: []core.InventoryProvenance{
					{
						SourceKind:   core.InventorySourceKindInventoryFile,
						SourceFormat: core.InventorySourceFormatJSON,
						SourceName:   "examples/caddy.json",
						SourceRecord: "apps.http.servers.edge.routes[0]",
						Adapter:      core.InventoryAdapterCaddy,
						SourceObject: "server edge @id site-api",
					},
				},
				AdapterWarnings: []core.InventoryAdapterWarning{
					{
						Code:    "non-tcp-listener-ignored",
						Summary: "Caddy listener does not use TCP and cannot be mapped into Surveyor remote scope.",
						Evidence: []string{
							"adapter=caddy",
							"source_name=examples/caddy.json",
							"source_object=server edge",
							"listener=udp/:443",
						},
					},
					{
						Code:    "non-concrete-host-ignored",
						Summary: "Caddy route contains a wildcard or placeholder host that Surveyor cannot map to a concrete remote target.",
						Evidence: []string{
							"adapter=caddy",
							"source_name=examples/caddy.json",
							"source_object=server edge @id wildcard-route",
							"host=*.example.com",
						},
					},
				},
			},
			Hints: []core.DiscoveryHint{
				{
					Protocol:   "tls",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=443"},
				},
			},
		},
	}, time.Date(2026, time.April, 26, 1, 15, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/caddy.json",
		Adapter:       core.InventoryAdapterCaddy,
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})
}

func sampleKubernetesAuditReport() core.AuditReport {
	return BuildAuditReportWithMetadata([]core.AuditResult{
		{
			DiscoveredEndpoint: core.DiscoveredEndpoint{
				ScopeKind: core.EndpointScopeKindRemote,
				Host:      "api.example.com",
				Port:      443,
				Transport: "tcp",
				State:     "responsive",
				Inventory: &core.InventoryAnnotation{
					Ports: []int{80, 443},
					Provenance: []core.InventoryProvenance{
						{
							SourceKind:   core.InventorySourceKindInventoryFile,
							SourceFormat: core.InventorySourceFormatYAML,
							SourceName:   "examples/ingress.yaml",
							SourceRecord: "documents[0].spec.tls[0].hosts[0]",
							Adapter:      core.InventoryAdapterKubernetesIngressV1,
							SourceObject: "Ingress/payments/payments-api",
						},
						{
							SourceKind:   core.InventorySourceKindInventoryFile,
							SourceFormat: core.InventorySourceFormatYAML,
							SourceName:   "examples/ingress.yaml",
							SourceRecord: "documents[0].spec.rules[0]",
							Adapter:      core.InventoryAdapterKubernetesIngressV1,
							SourceObject: "Ingress/payments/payments-api",
						},
					},
					AdapterWarnings: []core.InventoryAdapterWarning{
						{
							Code:    "ingress-controller-required",
							Summary: "Ingress effective exposure and TLS behaviour depend on the ingress controller; the manifest alone does not prove live external exposure.",
							Evidence: []string{
								"adapter=kubernetes-ingress-v1",
								"source_name=examples/ingress.yaml",
								"source_object=Ingress/payments/payments-api",
								"source_record=documents[0]",
							},
						},
						{
							Code:    "ingress-class-unspecified",
							Summary: "The Ingress manifest omits ingressClassName, so controller selection depends on cluster defaults or controller-specific behaviour.",
							Evidence: []string{
								"adapter=kubernetes-ingress-v1",
								"source_name=examples/ingress.yaml",
								"source_object=Ingress/payments/payments-api",
								"source_record=documents[0].spec",
							},
						},
					},
				},
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
				Host:                   "api.example.com",
				Port:                   443,
				ScannedAt:              time.Date(2026, time.April, 26, 1, 20, 0, 0, time.UTC),
				Reachable:              true,
				TLSVersion:             "TLS 1.3",
				CipherSuite:            "TLS_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "ecdsa",
				LeafKeySize:            256,
				LeafSignatureAlgorithm: "ecdsa-with-SHA256",
				Classification:         "modern_tls_ready",
			},
		},
	}, time.Date(2026, time.April, 26, 1, 30, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/ingress.yaml",
		Adapter:       core.InventoryAdapterKubernetesIngressV1,
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})
}

func sampleDiffReport(t *testing.T) diffreport.Report {
	t.Helper()

	baselineReport := BuildAuditReportWithMetadata([]core.AuditResult{
		{
			DiscoveredEndpoint: core.DiscoveredEndpoint{
				ScopeKind: core.EndpointScopeKindRemote,
				Host:      "example.com",
				Port:      443,
				Transport: "tcp",
				State:     "responsive",
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
				Host:                   "example.com",
				Port:                   443,
				ScannedAt:              time.Date(2026, time.April, 20, 1, 20, 0, 0, time.UTC),
				Reachable:              true,
				TLSVersion:             "TLS 1.2",
				CipherSuite:            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "rsa",
				LeafKeySize:            2048,
				LeafSignatureAlgorithm: "sha256-rsa",
				Classification:         "legacy_tls_exposure",
				Findings: []core.Finding{
					{
						Code:     "legacy-tls-version",
						Severity: core.SeverityHigh,
						Summary:  "The service negotiated a legacy TLS version.",
					},
					{
						Code:     "classical-certificate-identity",
						Severity: core.SeverityMedium,
						Summary:  "The observed certificate identity remains classical.",
					},
				},
				Warnings: []string{"baseline-warning"},
			},
		},
	}, time.Date(2026, time.April, 20, 2, 0, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind: core.ReportScopeKindRemote,
		InputKind: core.ReportInputKindCIDR,
		CIDR:      "10.0.0.0/30",
		Ports:     []int{443},
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})

	currentReport := BuildAuditReportWithMetadata([]core.AuditResult{
		{
			DiscoveredEndpoint: core.DiscoveredEndpoint{
				ScopeKind: core.EndpointScopeKindRemote,
				Host:      "example.com",
				Port:      443,
				Transport: "tcp",
				State:     "responsive",
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
				Host:                   "example.com",
				Port:                   443,
				ScannedAt:              time.Date(2026, time.April, 21, 1, 20, 0, 0, time.UTC),
				Reachable:              true,
				TLSVersion:             "TLS 1.3",
				CipherSuite:            "TLS_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "rsa",
				LeafKeySize:            2048,
				LeafSignatureAlgorithm: "sha256-rsa",
				Classification:         "modern_tls_classical_identity",
				Findings: []core.Finding{
					{
						Code:     "classical-certificate-identity",
						Severity: core.SeverityMedium,
						Summary:  "The observed certificate identity remains classical.",
					},
				},
			},
		},
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
	}, time.Date(2026, time.April, 21, 2, 0, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind: core.ReportScopeKindRemote,
		InputKind: core.ReportInputKindCIDR,
		CIDR:      "10.0.1.0/30",
		Ports:     []int{443},
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})

	report, err := diffreport.BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 22, 2, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}

	return report
}

func samplePrioritizationReport(t *testing.T) prioritizereport.Report {
	t.Helper()

	source := BuildAuditReportWithMetadata([]core.AuditResult{
		{
			DiscoveredEndpoint: core.DiscoveredEndpoint{
				ScopeKind: core.EndpointScopeKindRemote,
				Host:      "example.com",
				Port:      443,
				Transport: "tcp",
				State:     "responsive",
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
				Host:                   "example.com",
				Port:                   443,
				ScannedAt:              time.Date(2026, time.April, 20, 1, 20, 0, 0, time.UTC),
				Reachable:              true,
				TLSVersion:             "TLS 1.3",
				CipherSuite:            "TLS_AES_128_GCM_SHA256",
				LeafKeyAlgorithm:       "rsa",
				LeafKeySize:            2048,
				LeafSignatureAlgorithm: "sha256-rsa",
				Classification:         "modern_tls_classical_identity",
				Findings: []core.Finding{
					{
						Code:           "classical-certificate-identity",
						Severity:       core.SeverityMedium,
						Summary:        "The observed certificate identity remains classical.",
						Evidence:       []string{"leaf_key_algorithm=rsa"},
						Recommendation: "Inventory certificate replacement and related PKI dependencies as part of migration planning.",
					},
				},
				Warnings: []string{"certificate metadata incomplete"},
			},
		},
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
	}, time.Date(2026, time.April, 20, 1, 30, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:   core.ReportScopeKindRemote,
		InputKind:   core.ReportInputKindTargetsFile,
		TargetsFile: "examples/approved-hosts.txt",
		Ports:       []int{443},
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})

	report, err := prioritizereport.BuildAuditReport(
		source,
		prioritizereport.ProfileMigrationReadiness,
		time.Date(2026, time.April, 22, 3, 0, 0, 0, time.UTC),
		nil,
	)
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}

	return report
}

func sampleWorkflowDiffReport(t *testing.T) diffreport.Report {
	t.Helper()

	baselineReport := BuildAuditReportWithMetadata([]core.AuditResult{
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
				Reason:          "tls hint on tcp/443",
			},
		},
	}, time.Date(2026, time.April, 25, 1, 0, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/inventory.yaml",
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})

	currentReport := BuildAuditReportWithMetadata([]core.AuditResult{
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
				Host:      "dev.example.com",
				Port:      443,
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
				Status: core.AuditSelectionStatusSkipped,
				Reason: "endpoint did not respond during remote discovery",
			},
		},
	}, time.Date(2026, time.April, 25, 2, 0, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/inventory.yaml",
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})

	report, err := diffreport.BuildAuditReport(baselineReport, currentReport, time.Date(2026, time.April, 25, 3, 0, 0, 0, time.UTC), &core.WorkflowContext{
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

	return report
}

func sampleWorkflowPrioritizationReport(t *testing.T) prioritizereport.Report {
	t.Helper()

	source := BuildAuditReportWithMetadata([]core.AuditResult{
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
			Selection: core.AuditSelection{
				Status:          core.AuditSelectionStatusSelected,
				SelectedScanner: "tls",
				Reason:          "tls hint on tcp/443",
			},
			TLSResult: &core.TargetResult{
				Host:           "prod.example.com",
				Port:           443,
				ScannedAt:      time.Date(2026, time.April, 25, 1, 20, 0, 0, time.UTC),
				Reachable:      true,
				Classification: "legacy_tls_exposure",
				Findings: []core.Finding{
					{
						Code:           "legacy-tls-version",
						Severity:       core.SeverityHigh,
						Summary:        "Legacy TLS remains enabled.",
						Evidence:       []string{"tls_version=TLS 1.0"},
						Recommendation: "Upgrade the endpoint to a modern TLS baseline.",
					},
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
				Reason:          "tls hint on tcp/443",
			},
			TLSResult: &core.TargetResult{
				Host:           "dev.example.com",
				Port:           443,
				ScannedAt:      time.Date(2026, time.April, 25, 1, 21, 0, 0, time.UTC),
				Reachable:      true,
				Classification: "modern_tls_classical_identity",
				Findings: []core.Finding{
					{
						Code:           "classical-certificate-identity",
						Severity:       core.SeverityMedium,
						Summary:        "The observed certificate identity remains classical.",
						Evidence:       []string{"leaf_key_algorithm=rsa"},
						Recommendation: "Inventory certificate replacement and related PKI dependencies.",
					},
				},
			},
		},
	}, time.Date(2026, time.April, 25, 1, 30, 0, 0, time.UTC), &core.ReportScope{
		ScopeKind:     core.ReportScopeKindRemote,
		InputKind:     core.ReportInputKindInventoryFile,
		InventoryFile: "examples/inventory.yaml",
	}, &core.ReportExecution{
		Profile:        "cautious",
		MaxHosts:       256,
		MaxConcurrency: 8,
		Timeout:        "3s",
	})

	report, err := prioritizereport.BuildAuditReport(
		source,
		prioritizereport.ProfileMigrationReadiness,
		time.Date(2026, time.April, 25, 3, 0, 0, 0, time.UTC),
		&core.WorkflowContext{
			GroupBy: core.WorkflowGroupByOwner,
			Filters: []core.WorkflowFilter{
				{
					Field:  core.WorkflowFilterFieldTag,
					Values: []string{"external"},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("BuildAuditReport() error = %v", err)
	}

	return report
}
