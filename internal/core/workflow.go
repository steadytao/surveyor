package core

// WorkflowGroupBy records a supported organisational grouping dimension for
// analysis output.
type WorkflowGroupBy string

const (
	WorkflowGroupByOwner       WorkflowGroupBy = "owner"
	WorkflowGroupByEnvironment WorkflowGroupBy = "environment"
	WorkflowGroupBySource      WorkflowGroupBy = "source"
)

// WorkflowFilterField records a supported metadata field used to narrow
// analysis output.
type WorkflowFilterField string

const (
	WorkflowFilterFieldOwner       WorkflowFilterField = "owner"
	WorkflowFilterFieldEnvironment WorkflowFilterField = "environment"
	WorkflowFilterFieldTag         WorkflowFilterField = "tag"
	WorkflowFilterFieldSource      WorkflowFilterField = "source"
)

// WorkflowFilter records one explicit metadata filter applied to an analysis
// view.
type WorkflowFilter struct {
	Field  WorkflowFilterField `json:"field"`
	Values []string            `json:"values"`
}

// WorkflowContext records the grouping and filtering view applied to a diff or
// prioritization report.
type WorkflowContext struct {
	GroupBy WorkflowGroupBy  `json:"group_by,omitempty"`
	Filters []WorkflowFilter `json:"filters,omitempty"`
}

// GroupedSummary records one grouped aggregate section derived from canonical
// diff or prioritization items.
type GroupedSummary struct {
	GroupBy WorkflowGroupBy       `json:"group_by"`
	Groups  []GroupedSummaryGroup `json:"groups,omitempty"`
}

// GroupedSummaryGroup records one named group within a grouped summary.
type GroupedSummaryGroup struct {
	Key                string         `json:"key"`
	TotalItems         int            `json:"total_items"`
	SeverityBreakdown  map[string]int `json:"severity_breakdown,omitempty"`
	CodeBreakdown      map[string]int `json:"code_breakdown,omitempty"`
	DirectionBreakdown map[string]int `json:"direction_breakdown,omitempty"`
	ChangeBreakdown    map[string]int `json:"change_breakdown,omitempty"`
}

// WorkflowFinding records one metadata-quality or workflow-oriented finding
// derived from current report context rather than scanner evidence alone.
type WorkflowFinding struct {
	Severity       Severity `json:"severity"`
	Code           string   `json:"code"`
	Summary        string   `json:"summary"`
	TargetIdentity string   `json:"target_identity,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}
