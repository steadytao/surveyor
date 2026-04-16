package outputs

import (
	"sort"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

// BuildAuditReport assembles the canonical audit report and its summary.
func BuildAuditReport(results []core.AuditResult, generatedAt time.Time) core.AuditReport {
	return BuildAuditReportWithMetadata(results, generatedAt, nil, nil)
}

// BuildAuditReportWithMetadata assembles the canonical audit report, including
// any declared report scope and execution settings.
func BuildAuditReportWithMetadata(results []core.AuditResult, generatedAt time.Time, scope *core.ReportScope, execution *core.ReportExecution) core.AuditReport {
	// Copy the slice so report assembly does not retain caller-owned backing
	// storage. Rendering should be a pure step over stable audit results.
	reportResults := make([]core.AuditResult, 0, len(results))
	for _, result := range results {
		reportResults = append(reportResults, core.CloneAuditResult(result))
	}

	return core.AuditReport{
		ReportMetadata: buildAuditReportMetadata(scope),
		GeneratedAt:    generatedAt.UTC(),
		Scope:          cloneReportScope(scope),
		Execution:      cloneReportExecution(execution),
		Results:        reportResults,
		Summary:        buildAuditSummary(reportResults),
	}
}

func buildAuditSummary(results []core.AuditResult) core.AuditSummary {
	summary := core.AuditSummary{
		TotalEndpoints:                  len(results),
		SelectionBreakdown:              map[string]int{},
		VerifiedClassificationBreakdown: map[string]int{},
	}

	for _, result := range results {
		switch result.Selection.Status {
		case core.AuditSelectionStatusSelected:
			if result.Selection.SelectedScanner != "" {
				summary.SelectionBreakdown[result.Selection.SelectedScanner] += 1
			}
			if result.Selection.SelectedScanner == "tls" {
				summary.TLSCandidates += 1
			}
			// Only verified scanner output contributes to the scanned and
			// classification summaries. Hints and selection decisions alone do not.
			if result.TLSResult != nil {
				summary.ScannedEndpoints += 1
				if result.TLSResult.Classification != "" {
					summary.VerifiedClassificationBreakdown[result.TLSResult.Classification] += 1
				}
			}
		case core.AuditSelectionStatusSkipped:
			summary.SkippedEndpoints += 1
		}
	}

	if len(summary.SelectionBreakdown) == 0 {
		summary.SelectionBreakdown = nil
	}
	if len(summary.VerifiedClassificationBreakdown) == 0 {
		summary.VerifiedClassificationBreakdown = nil
	}

	return summary
}

func sortedSelectionKeys(summary core.AuditSummary) []string {
	if len(summary.SelectionBreakdown) == 0 {
		return nil
	}

	keys := make([]string, 0, len(summary.SelectionBreakdown))
	for key := range summary.SelectionBreakdown {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	return keys
}

func sortedVerifiedClassificationKeys(summary core.AuditSummary) []string {
	if len(summary.VerifiedClassificationBreakdown) == 0 {
		return nil
	}

	keys := make([]string, 0, len(summary.VerifiedClassificationBreakdown))
	for key := range summary.VerifiedClassificationBreakdown {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	return keys
}
