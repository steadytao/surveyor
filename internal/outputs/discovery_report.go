package outputs

import (
	"sort"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

// BuildDiscoveryReport assembles the canonical discovery report and its summary.
func BuildDiscoveryReport(results []core.DiscoveredEndpoint, generatedAt time.Time) core.DiscoveryReport {
	return BuildDiscoveryReportWithMetadata(results, generatedAt, nil, nil)
}

// BuildDiscoveryReportWithMetadata assembles the canonical discovery report,
// including any declared report scope and execution settings.
func BuildDiscoveryReportWithMetadata(results []core.DiscoveredEndpoint, generatedAt time.Time, scope *core.ReportScope, execution *core.ReportExecution) core.DiscoveryReport {
	// Copy the slice so report assembly does not retain caller-owned backing
	// storage. Discovery rendering should be a pure step over stable result data.
	reportResults := append([]core.DiscoveredEndpoint(nil), results...)

	return core.DiscoveryReport{
		GeneratedAt: generatedAt.UTC(),
		Scope:       cloneReportScope(scope),
		Execution:   cloneReportExecution(execution),
		Results:     reportResults,
		Summary:     buildDiscoverySummary(reportResults),
	}
}

func cloneReportScope(scope *core.ReportScope) *core.ReportScope {
	if scope == nil {
		return nil
	}

	clone := *scope
	clone.Ports = append([]int(nil), scope.Ports...)
	return &clone
}

func cloneReportExecution(execution *core.ReportExecution) *core.ReportExecution {
	if execution == nil {
		return nil
	}

	clone := *execution
	return &clone
}

func buildDiscoverySummary(results []core.DiscoveredEndpoint) core.DiscoverySummary {
	summary := core.DiscoverySummary{
		TotalEndpoints: len(results),
		HintBreakdown:  map[string]int{},
	}

	for _, result := range results {
		switch result.Transport {
		case "tcp":
			summary.TCPEndpoints += 1
		case "udp":
			summary.UDPEndpoints += 1
		}

		seenProtocols := make(map[string]struct{}, len(result.Hints))
		for _, hint := range result.Hints {
			if hint.Protocol == "" {
				continue
			}
			if _, ok := seenProtocols[hint.Protocol]; ok {
				continue
			}

			seenProtocols[hint.Protocol] = struct{}{}
			summary.HintBreakdown[hint.Protocol] += 1
		}
	}

	if len(summary.HintBreakdown) == 0 {
		summary.HintBreakdown = nil
	}

	return summary
}

func sortedHintKeys(summary core.DiscoverySummary) []string {
	if len(summary.HintBreakdown) == 0 {
		return nil
	}

	keys := make([]string, 0, len(summary.HintBreakdown))
	for key := range summary.HintBreakdown {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	return keys
}
