package diff

import (
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

// ChangeDirection records the conservative direction Surveyor can defend for a
// reported change.
type ChangeDirection string

const (
	ChangeDirectionWorsened      ChangeDirection = "worsened"
	ChangeDirectionImproved      ChangeDirection = "improved"
	ChangeDirectionChanged       ChangeDirection = "changed"
	ChangeDirectionInformational ChangeDirection = "informational"
)

// Summary records the top-level aggregate counts for a diff report.
type Summary struct {
	TotalBaselineEntities int            `json:"total_baseline_entities"`
	TotalCurrentEntities  int            `json:"total_current_entities"`
	AddedEntities         int            `json:"added_entities"`
	RemovedEntities       int            `json:"removed_entities"`
	ChangedEntities       int            `json:"changed_entities"`
	UnchangedEntities     int            `json:"unchanged_entities"`
	ScopeChanged          bool           `json:"scope_changed"`
	ChangeBreakdown       map[string]int `json:"change_breakdown,omitempty"`
	DirectionBreakdown    map[string]int `json:"direction_breakdown,omitempty"`
}

// IssueValues records warning or error values from both the discovery and TLS
// layers without falling back to unordered maps.
type IssueValues struct {
	DiscoveredEndpoint []string `json:"discovered_endpoint,omitempty"`
	TLSResult          []string `json:"tls_result,omitempty"`
}

// Change records one stable semantic difference between a baseline entity and a
// current entity.
type Change struct {
	IdentityKey    string          `json:"identity_key"`
	Code           string          `json:"code"`
	Direction      ChangeDirection `json:"direction"`
	Severity       core.Severity   `json:"severity"`
	Summary        string          `json:"summary"`
	BaselineValue  any             `json:"baseline_value,omitempty"`
	CurrentValue   any             `json:"current_value,omitempty"`
	Evidence       []string        `json:"evidence,omitempty"`
	Recommendation string          `json:"recommendation,omitempty"`
}

// Report is the canonical diff report assembled from two compatible Surveyor
// reports.
type Report struct {
	core.ReportMetadata
	GeneratedAt              time.Time         `json:"generated_at"`
	BaselineReportKind       core.ReportKind   `json:"baseline_report_kind"`
	CurrentReportKind        core.ReportKind   `json:"current_report_kind"`
	BaselineGeneratedAt      time.Time         `json:"baseline_generated_at"`
	CurrentGeneratedAt       time.Time         `json:"current_generated_at"`
	BaselineScopeDescription string            `json:"baseline_scope_description,omitempty"`
	CurrentScopeDescription  string            `json:"current_scope_description,omitempty"`
	BaselineScope            *core.ReportScope `json:"baseline_scope,omitempty"`
	CurrentScope             *core.ReportScope `json:"current_scope,omitempty"`
	Summary                  Summary           `json:"summary"`
	Changes                  []Change          `json:"changes"`
}
