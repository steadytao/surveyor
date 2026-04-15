package outputs

import (
	"sort"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

func BuildAuditReport(results []core.AuditResult, generatedAt time.Time) core.AuditReport {
	reportResults := append([]core.AuditResult(nil), results...)

	return core.AuditReport{
		GeneratedAt: generatedAt.UTC(),
		Results:     reportResults,
		Summary:     buildAuditSummary(reportResults),
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
