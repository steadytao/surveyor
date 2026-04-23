// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

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

	hintKeys := sortedHintKeys(report.Summary)
	renderReportScopeSection(&builder, report.Scope)
	renderReportExecutionSection(&builder, report.Execution)
	renderBreakdownSection(&builder, "## Hint summary", "- No hints recorded", hintKeys, func(key string) int {
		return report.Summary.HintBreakdown[key]
	})

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
		renderDiscoveredEndpointFields(&builder, result)
		renderHintsSection(&builder, result.Hints)
		renderStringListSection(&builder, "Warnings", result.Warnings)
		renderStringListSection(&builder, "Errors", result.Errors)
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
