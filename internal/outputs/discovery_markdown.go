package outputs

import (
	"fmt"
	"strings"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

// RenderDiscoveryMarkdown renders the human-readable discovery report from the
// canonical discovery model.
func RenderDiscoveryMarkdown(report core.DiscoveryReport) string {
	var builder strings.Builder

	builder.WriteString("# Surveyor Discovery Report\n\n")
	builder.WriteString(fmt.Sprintf("- Generated: %s\n", report.GeneratedAt.UTC().Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("- Total endpoints: %d\n", report.Summary.TotalEndpoints))
	builder.WriteString(fmt.Sprintf("- TCP endpoints: %d\n", report.Summary.TCPEndpoints))
	builder.WriteString(fmt.Sprintf("- UDP endpoints: %d\n\n", report.Summary.UDPEndpoints))

	builder.WriteString("## Hint summary\n\n")
	hintKeys := sortedHintKeys(report.Summary)
	if len(hintKeys) == 0 {
		builder.WriteString("- No hints recorded\n\n")
	} else {
		for _, key := range hintKeys {
			builder.WriteString(fmt.Sprintf("- %s: %d\n", key, report.Summary.HintBreakdown[key]))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Endpoints\n\n")
	if len(report.Results) == 0 {
		builder.WriteString("No endpoints were included in this report.\n")
		return builder.String()
	}

	for index, result := range report.Results {
		if index > 0 {
			builder.WriteString("\n")
		}

		builder.WriteString(fmt.Sprintf("### %s\n\n", discoveryEndpointHeading(result)))
		builder.WriteString(fmt.Sprintf("- Address: %s\n", result.Address))
		builder.WriteString(fmt.Sprintf("- Port: %d\n", result.Port))
		builder.WriteString(fmt.Sprintf("- Transport: %s\n", result.Transport))
		builder.WriteString(fmt.Sprintf("- State: %s\n", result.State))

		if result.PID > 0 {
			builder.WriteString(fmt.Sprintf("- PID: %d\n", result.PID))
		}
		if result.ProcessName != "" {
			builder.WriteString(fmt.Sprintf("- Process name: %s\n", result.ProcessName))
		}
		if result.Executable != "" {
			builder.WriteString(fmt.Sprintf("- Executable: %s\n", result.Executable))
		}

		if len(result.Hints) > 0 {
			builder.WriteString("\n#### Hints\n\n")
			for _, hint := range result.Hints {
				builder.WriteString(fmt.Sprintf("- %s (%s)\n", hint.Protocol, defaultString(hint.Confidence, "unknown")))
				for _, evidence := range hint.Evidence {
					builder.WriteString(fmt.Sprintf("  - evidence: %s\n", evidence))
				}
			}
		}

		if len(result.Warnings) > 0 {
			builder.WriteString("\n#### Warnings\n\n")
			for _, warning := range result.Warnings {
				builder.WriteString(fmt.Sprintf("- %s\n", warning))
			}
		}

		if len(result.Errors) > 0 {
			builder.WriteString("\n#### Errors\n\n")
			for _, errText := range result.Errors {
				builder.WriteString(fmt.Sprintf("- %s\n", errText))
			}
		}
	}

	return builder.String()
}

func discoveryEndpointHeading(result core.DiscoveredEndpoint) string {
	return fmt.Sprintf("%s:%d/%s", result.Address, result.Port, result.Transport)
}
