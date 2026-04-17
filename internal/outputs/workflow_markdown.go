package outputs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/steadytao/surveyor/internal/core"
)

func renderWorkflowView(builder *strings.Builder, view *core.WorkflowContext) {
	if view == nil {
		return
	}

	builder.WriteString("## Workflow View\n\n")
	if view.GroupBy != "" {
		builder.WriteString(fmt.Sprintf("- Group by: %s\n", view.GroupBy))
	}
	for _, filter := range view.Filters {
		builder.WriteString(fmt.Sprintf("- Filter %s: %s\n", filter.Field, strings.Join(filter.Values, ", ")))
	}
	builder.WriteString("\n")
}

func renderGroupedSummaries(builder *strings.Builder, summaries []core.GroupedSummary) {
	if len(summaries) == 0 {
		return
	}

	builder.WriteString("## Grouped Summaries\n\n")
	for summaryIndex, summary := range summaries {
		if summaryIndex > 0 {
			builder.WriteString("\n")
		}

		builder.WriteString(fmt.Sprintf("### By %s\n\n", summary.GroupBy))
		if len(summary.Groups) == 0 {
			builder.WriteString("- No grouped items recorded\n")
			continue
		}

		for groupIndex, group := range summary.Groups {
			if groupIndex > 0 {
				builder.WriteString("\n")
			}

			builder.WriteString(fmt.Sprintf("#### %s\n\n", group.Key))
			builder.WriteString(fmt.Sprintf("- Total items: %d\n", group.TotalItems))
			if breakdown := formatWorkflowBreakdown(group.SeverityBreakdown); breakdown != "" {
				builder.WriteString(fmt.Sprintf("- Severity breakdown: %s\n", breakdown))
			}
			if breakdown := formatWorkflowBreakdown(group.CodeBreakdown); breakdown != "" {
				builder.WriteString(fmt.Sprintf("- Code breakdown: %s\n", breakdown))
			}
			if breakdown := formatWorkflowBreakdown(group.DirectionBreakdown); breakdown != "" {
				builder.WriteString(fmt.Sprintf("- Direction breakdown: %s\n", breakdown))
			}
			if breakdown := formatWorkflowBreakdown(group.ChangeBreakdown); breakdown != "" {
				builder.WriteString(fmt.Sprintf("- Change breakdown: %s\n", breakdown))
			}
		}
	}

	builder.WriteString("\n")
}

func renderWorkflowFindings(builder *strings.Builder, findings []core.WorkflowFinding) {
	if len(findings) == 0 {
		return
	}

	builder.WriteString("## Workflow Findings\n\n")
	for index, finding := range findings {
		if index > 0 {
			builder.WriteString("\n")
		}

		heading := finding.Code
		if finding.TargetIdentity != "" {
			heading += " (" + finding.TargetIdentity + ")"
		}

		builder.WriteString(fmt.Sprintf("### %s\n\n", heading))
		builder.WriteString(fmt.Sprintf("- Severity: %s\n", finding.Severity))
		builder.WriteString(fmt.Sprintf("- Summary: %s\n", finding.Summary))
		if finding.Reason != "" {
			builder.WriteString(fmt.Sprintf("- Reason: %s\n", finding.Reason))
		}
		if finding.Recommendation != "" {
			builder.WriteString(fmt.Sprintf("- Recommendation: %s\n", finding.Recommendation))
		}
		if len(finding.Evidence) > 0 {
			builder.WriteString("\n#### Evidence\n\n")
			for _, evidence := range finding.Evidence {
				builder.WriteString(fmt.Sprintf("- %s\n", evidence))
			}
		}
	}

	builder.WriteString("\n")
}

func formatWorkflowBreakdown(values map[string]int) string {
	if len(values) == 0 {
		return ""
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, values[key]))
	}

	return strings.Join(parts, ", ")
}
