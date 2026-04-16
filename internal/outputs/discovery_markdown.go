package outputs

import (
	"fmt"
	"net"
	"strconv"
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
		renderInventoryFileScope(&builder, report.Scope)
		renderScopePorts(&builder, report.Scope)
		builder.WriteString("\n")
	}

	if report.Execution != nil {
		builder.WriteString("## Execution\n\n")
		if report.Execution.Profile != "" {
			builder.WriteString(fmt.Sprintf("- Profile: %s\n", report.Execution.Profile))
		}
		if report.Execution.MaxHosts > 0 {
			builder.WriteString(fmt.Sprintf("- Max hosts: %d\n", report.Execution.MaxHosts))
		}
		if report.Execution.MaxConcurrency > 0 {
			builder.WriteString(fmt.Sprintf("- Max concurrency: %d\n", report.Execution.MaxConcurrency))
		}
		if report.Execution.Timeout != "" {
			builder.WriteString(fmt.Sprintf("- Timeout per attempt: %s\n", report.Execution.Timeout))
		}
		builder.WriteString("\n")
	}

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
		builder.WriteString(fmt.Sprintf("- Scope kind: %s\n", result.ScopeKind))
		builder.WriteString(fmt.Sprintf("- Host: %s\n", result.Host))
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
		renderInventoryAnnotation(&builder, result.Inventory)

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
	return net.JoinHostPort(result.Host, strconv.Itoa(result.Port)) + "/" + result.Transport
}

func renderPortsList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}

	return strings.Join(values, ",")
}
