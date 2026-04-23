// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package outputs

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	diffreport "github.com/steadytao/surveyor/internal/diff"
)

// RenderDiffMarkdown renders the human-readable diff report from the canonical
// diff model.
func RenderDiffMarkdown(report diffreport.Report) string {
	var builder strings.Builder

	builder.WriteString("# Surveyor Diff Report\n\n")
	builder.WriteString(fmt.Sprintf("- Generated: %s\n", report.GeneratedAt.UTC().Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("- Baseline report kind: %s\n", report.BaselineReportKind))
	builder.WriteString(fmt.Sprintf("- Current report kind: %s\n", report.CurrentReportKind))
	builder.WriteString(fmt.Sprintf("- Total baseline entities: %d\n", report.Summary.TotalBaselineEntities))
	builder.WriteString(fmt.Sprintf("- Total current entities: %d\n", report.Summary.TotalCurrentEntities))
	builder.WriteString(fmt.Sprintf("- Added entities: %d\n", report.Summary.AddedEntities))
	builder.WriteString(fmt.Sprintf("- Removed entities: %d\n", report.Summary.RemovedEntities))
	builder.WriteString(fmt.Sprintf("- Changed entities: %d\n", report.Summary.ChangedEntities))
	builder.WriteString(fmt.Sprintf("- Unchanged entities: %d\n", report.Summary.UnchangedEntities))
	builder.WriteString(fmt.Sprintf("- Scope changed: %t\n\n", report.Summary.ScopeChanged))

	builder.WriteString("## Comparison\n\n")
	builder.WriteString(fmt.Sprintf("- Baseline generated: %s\n", report.BaselineGeneratedAt.UTC().Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("- Current generated: %s\n", report.CurrentGeneratedAt.UTC().Format(time.RFC3339)))
	if report.BaselineScopeDescription != "" {
		builder.WriteString(fmt.Sprintf("- Baseline scope: %s\n", report.BaselineScopeDescription))
	}
	if report.CurrentScopeDescription != "" {
		builder.WriteString(fmt.Sprintf("- Current scope: %s\n", report.CurrentScopeDescription))
	}
	builder.WriteString("\n")

	renderWorkflowView(&builder, report.WorkflowView)

	builder.WriteString("## Change Summary\n\n")
	changeKeys := sortedDiffMapKeys(report.Summary.ChangeBreakdown)
	if len(changeKeys) == 0 {
		builder.WriteString("- No changes recorded\n\n")
	} else {
		for _, key := range changeKeys {
			builder.WriteString(fmt.Sprintf("- %s: %d\n", key, report.Summary.ChangeBreakdown[key]))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Direction Summary\n\n")
	directionKeys := sortedDiffMapKeys(report.Summary.DirectionBreakdown)
	if len(directionKeys) == 0 {
		builder.WriteString("- No change directions recorded\n\n")
	} else {
		for _, key := range directionKeys {
			builder.WriteString(fmt.Sprintf("- %s: %d\n", key, report.Summary.DirectionBreakdown[key]))
		}
		builder.WriteString("\n")
	}

	renderGroupedSummaries(&builder, report.GroupedSummaries)
	renderWorkflowFindings(&builder, report.WorkflowFindings)

	builder.WriteString("## Changes\n\n")
	if len(report.Changes) == 0 {
		builder.WriteString("No changes were recorded.\n")
		return builder.String()
	}

	for index, change := range report.Changes {
		if index > 0 {
			builder.WriteString("\n")
		}

		builder.WriteString(fmt.Sprintf("### %s\n\n", change.IdentityKey))
		builder.WriteString(fmt.Sprintf("- Code: %s\n", change.Code))
		builder.WriteString(fmt.Sprintf("- Direction: %s\n", change.Direction))
		builder.WriteString(fmt.Sprintf("- Severity: %s\n", change.Severity))
		builder.WriteString(fmt.Sprintf("- Summary: %s\n", change.Summary))

		if change.BaselineValue != nil {
			builder.WriteString("- Baseline value:\n")
			builder.WriteString(renderMarkdownJSONBlock(change.BaselineValue))
		}
		if change.CurrentValue != nil {
			builder.WriteString("- Current value:\n")
			builder.WriteString(renderMarkdownJSONBlock(change.CurrentValue))
		}
		if len(change.Evidence) > 0 {
			builder.WriteString("\n#### Evidence\n\n")
			for _, evidence := range change.Evidence {
				builder.WriteString(fmt.Sprintf("- %s\n", evidence))
			}
		}
		if change.Recommendation != "" {
			builder.WriteString(fmt.Sprintf("\n- Recommendation: %s\n", change.Recommendation))
		}
	}

	return builder.String()
}

func renderMarkdownJSONBlock(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "  unable to render value\n"
	}

	return "\n```json\n" + string(data) + "\n```\n"
}

func sortedDiffMapKeys(values map[string]int) []string {
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
