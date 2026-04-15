package core

import "time"

type AuditSelectionStatus string

const (
	AuditSelectionStatusSelected AuditSelectionStatus = "selected"
	AuditSelectionStatusSkipped  AuditSelectionStatus = "skipped"
)

type AuditSelection struct {
	Status          AuditSelectionStatus `json:"status"`
	SelectedScanner string               `json:"selected_scanner,omitempty"`
	Reason          string               `json:"reason,omitempty"`
}

type AuditResult struct {
	DiscoveredEndpoint DiscoveredEndpoint `json:"discovered_endpoint"`
	Selection          AuditSelection     `json:"selection"`
	TLSResult          *TargetResult      `json:"tls_result,omitempty"`
}

type AuditSummary struct {
	TotalEndpoints                  int            `json:"total_endpoints"`
	TLSCandidates                   int            `json:"tls_candidates"`
	ScannedEndpoints                int            `json:"scanned_endpoints"`
	SkippedEndpoints                int            `json:"skipped_endpoints"`
	SelectionBreakdown              map[string]int `json:"selection_breakdown,omitempty"`
	VerifiedClassificationBreakdown map[string]int `json:"verified_classification_breakdown,omitempty"`
}

type AuditReport struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Results     []AuditResult `json:"results"`
	Summary     AuditSummary  `json:"summary"`
}
