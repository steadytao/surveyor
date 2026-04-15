package outputs

import (
	"sort"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

// BuildReport assembles the canonical TLS inventory report and its summary.
func BuildReport(results []core.TargetResult, generatedAt time.Time) core.Report {
	// Copy the slice so report assembly does not retain caller-owned backing
	// storage. Rendering should be a pure step over stable result data.
	reportResults := make([]core.TargetResult, 0, len(results))
	for _, result := range results {
		reportResults = append(reportResults, core.CloneTargetResult(result))
	}

	report := core.Report{
		GeneratedAt: generatedAt.UTC(),
		Results:     reportResults,
		Summary:     buildSummary(reportResults),
	}

	return report
}

func buildSummary(results []core.TargetResult) core.Summary {
	summary := core.Summary{
		TotalTargets:            len(results),
		ClassificationBreakdown: map[string]int{},
	}

	for _, result := range results {
		if result.Reachable {
			summary.ReachableTargets += 1
		} else {
			summary.UnreachableTargets += 1
		}

		if result.Classification != "" {
			summary.ClassificationBreakdown[result.Classification] += 1
		}
	}

	if len(summary.ClassificationBreakdown) == 0 {
		summary.ClassificationBreakdown = nil
	}

	return summary
}

func sortedClassificationKeys(summary core.Summary) []string {
	if len(summary.ClassificationBreakdown) == 0 {
		return nil
	}

	// Stable ordering keeps Markdown deterministic and makes test fixtures and
	// future diffs easier to reason about.
	keys := make([]string, 0, len(summary.ClassificationBreakdown))
	for key := range summary.ClassificationBreakdown {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	return keys
}
