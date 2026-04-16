package outputs

import (
	"fmt"
	"sort"
	"strings"
	"time"

	prioritizereport "github.com/steadytao/surveyor/internal/prioritize"
)

// RenderPrioritizationMarkdown renders the human-readable prioritisation report
// from the canonical prioritization model.
func RenderPrioritizationMarkdown(report prioritizereport.Report) string {
	var builder strings.Builder

	builder.WriteString("# Surveyor Prioritisation Report\n\n")
	builder.WriteString(fmt.Sprintf("- Generated: %s\n", report.GeneratedAt.UTC().Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("- Profile: %s\n", report.Profile))
	builder.WriteString(fmt.Sprintf("- Source report kind: %s\n", report.SourceReportKind))
	builder.WriteString(fmt.Sprintf("- Source generated: %s\n", report.SourceGeneratedAt.UTC().Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("- Total items: %d\n\n", report.Summary.TotalItems))

	if report.Scope != nil {
		builder.WriteString("## Scope\n\n")
		builder.WriteString(fmt.Sprintf("- Scope kind: %s\n", report.Scope.ScopeKind))
		if report.Scope.InputKind != "" {
			builder.WriteString(fmt.Sprintf("- Input kind: %s\n", report.Scope.InputKind))
		}
		if report.Scope.CIDR != "" {
			builder.WriteString(fmt.Sprintf("- CIDR: %s\n", report.Scope.CIDR))
		}
		if report.Scope.TargetsFile != "" {
			builder.WriteString(fmt.Sprintf("- Targets file: %s\n", report.Scope.TargetsFile))
		}
		if len(report.Scope.Ports) > 0 {
			builder.WriteString(fmt.Sprintf("- Ports: %s\n", renderPortsList(report.Scope.Ports)))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Severity summary\n\n")
	severityKeys := sortedPrioritizationMapKeys(report.Summary.SeverityBreakdown)
	if len(severityKeys) == 0 {
		builder.WriteString("- No prioritised severities recorded\n\n")
	} else {
		for _, key := range severityKeys {
			builder.WriteString(fmt.Sprintf("- %s: %d\n", key, report.Summary.SeverityBreakdown[key]))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Code summary\n\n")
	codeKeys := sortedPrioritizationMapKeys(report.Summary.CodeBreakdown)
	if len(codeKeys) == 0 {
		builder.WriteString("- No prioritised codes recorded\n\n")
	} else {
		for _, key := range codeKeys {
			builder.WriteString(fmt.Sprintf("- %s: %d\n", key, report.Summary.CodeBreakdown[key]))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Priorities\n\n")
	if len(report.Items) == 0 {
		builder.WriteString("No prioritised items were recorded.\n")
		return builder.String()
	}

	for index, item := range report.Items {
		if index > 0 {
			builder.WriteString("\n")
		}

		builder.WriteString(fmt.Sprintf("### %d. %s\n\n", item.Rank, item.TargetIdentity))
		builder.WriteString(fmt.Sprintf("- Code: %s\n", item.Code))
		builder.WriteString(fmt.Sprintf("- Severity: %s\n", item.Severity))
		builder.WriteString(fmt.Sprintf("- Summary: %s\n", item.Summary))
		if item.Reason != "" {
			builder.WriteString(fmt.Sprintf("- Reason: %s\n", item.Reason))
		}
		if item.Recommendation != "" {
			builder.WriteString(fmt.Sprintf("- Recommendation: %s\n", item.Recommendation))
		}
		if len(item.Evidence) > 0 {
			builder.WriteString("\n#### Evidence\n\n")
			for _, evidence := range item.Evidence {
				builder.WriteString(fmt.Sprintf("- %s\n", evidence))
			}
		}
	}

	return builder.String()
}

func sortedPrioritizationMapKeys(values map[string]int) []string {
	if len(values) == 0 {
		return nil
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
