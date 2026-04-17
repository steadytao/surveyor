package prioritize

import (
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

// Profile records the prioritization profile applied to the source report.
type Profile string

const (
	ProfileMigrationReadiness Profile = "migration-readiness"
	ProfileChangeRisk         Profile = "change-risk"
)

// Summary records aggregate counts for a prioritization report.
type Summary struct {
	TotalItems        int            `json:"total_items"`
	SeverityBreakdown map[string]int `json:"severity_breakdown,omitempty"`
	CodeBreakdown     map[string]int `json:"code_breakdown,omitempty"`
}

// Item records one ranked prioritization outcome derived from a current report.
type Item struct {
	Rank           int           `json:"rank"`
	Severity       core.Severity `json:"severity"`
	Code           string        `json:"code"`
	Summary        string        `json:"summary"`
	TargetIdentity string        `json:"target_identity"`
	Reason         string        `json:"reason,omitempty"`
	Evidence       []string      `json:"evidence,omitempty"`
	Recommendation string        `json:"recommendation,omitempty"`
}

// Report is the canonical prioritization report over a current Surveyor report.
type Report struct {
	core.ReportMetadata
	GeneratedAt       time.Time              `json:"generated_at"`
	Profile           Profile                `json:"profile"`
	SourceReportKind  core.ReportKind        `json:"source_report_kind"`
	SourceGeneratedAt time.Time              `json:"source_generated_at"`
	Scope             *core.ReportScope      `json:"scope,omitempty"`
	WorkflowView      *core.WorkflowContext  `json:"workflow_view,omitempty"`
	Summary           Summary                `json:"summary"`
	GroupedSummaries  []core.GroupedSummary  `json:"grouped_summaries,omitempty"`
	WorkflowFindings  []core.WorkflowFinding `json:"workflow_findings,omitempty"`
	Items             []Item                 `json:"items"`
}
