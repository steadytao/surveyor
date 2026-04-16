package core

import "time"

// AuditSelectionStatus records whether audit chose to scan or skip an endpoint.
type AuditSelectionStatus string

const (
	AuditSelectionStatusSelected AuditSelectionStatus = "selected"
	AuditSelectionStatusSkipped  AuditSelectionStatus = "skipped"
)

// AuditSelection records the explicit scanner decision for one discovered endpoint.
type AuditSelection struct {
	Status          AuditSelectionStatus `json:"status"`
	SelectedScanner string               `json:"selected_scanner,omitempty"`
	Reason          string               `json:"reason,omitempty"`
}

// AuditResult combines discovered facts, the selection decision and any verified scan result.
type AuditResult struct {
	DiscoveredEndpoint DiscoveredEndpoint `json:"discovered_endpoint"`
	Selection          AuditSelection     `json:"selection"`
	TLSResult          *TargetResult      `json:"tls_result,omitempty"`
}

// AuditSummary contains aggregate counts derived from audit results.
type AuditSummary struct {
	TotalEndpoints                  int            `json:"total_endpoints"`
	TLSCandidates                   int            `json:"tls_candidates"`
	ScannedEndpoints                int            `json:"scanned_endpoints"`
	SkippedEndpoints                int            `json:"skipped_endpoints"`
	SelectionBreakdown              map[string]int `json:"selection_breakdown,omitempty"`
	VerifiedClassificationBreakdown map[string]int `json:"verified_classification_breakdown,omitempty"`
}

// AuditReport is the top-level canonical audit report.
type AuditReport struct {
	ReportMetadata
	GeneratedAt time.Time        `json:"generated_at"`
	Scope       *ReportScope     `json:"scope,omitempty"`
	Execution   *ReportExecution `json:"execution,omitempty"`
	Results     []AuditResult    `json:"results"`
	Summary     AuditSummary     `json:"summary"`
}
