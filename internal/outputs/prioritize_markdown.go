// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

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

	renderReportScopeSection(&builder, report.Scope)
	renderWorkflowView(&builder, report.WorkflowView)

	severityKeys := sortedPrioritizationMapKeys(report.Summary.SeverityBreakdown)
	codeKeys := sortedPrioritizationMapKeys(report.Summary.CodeBreakdown)
	renderBreakdownSection(&builder, "## Severity summary", "- No prioritised severities recorded", severityKeys, func(key string) int {
		return report.Summary.SeverityBreakdown[key]
	})
	renderBreakdownSection(&builder, "## Code summary", "- No prioritised codes recorded", codeKeys, func(key string) int {
		return report.Summary.CodeBreakdown[key]
	})

	renderGroupedSummaries(&builder, report.GroupedSummaries)
	renderWorkflowFindings(&builder, report.WorkflowFindings)

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
