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

// RenderAuditMarkdown renders the human-readable audit report from the
// canonical audit model.
func RenderAuditMarkdown(report core.AuditReport) string {
	var builder strings.Builder

	builder.WriteString("# Surveyor Audit Report\n\n")
	builder.WriteString(fmt.Sprintf("- Generated: %s\n", report.GeneratedAt.UTC().Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("- Total endpoints: %d\n", report.Summary.TotalEndpoints))
	builder.WriteString(fmt.Sprintf("- TLS candidates: %d\n", report.Summary.TLSCandidates))
	builder.WriteString(fmt.Sprintf("- Scanned endpoints: %d\n", report.Summary.ScannedEndpoints))
	builder.WriteString(fmt.Sprintf("- Skipped endpoints: %d\n\n", report.Summary.SkippedEndpoints))

	selectionKeys := sortedSelectionKeys(report.Summary)
	classificationKeys := sortedVerifiedClassificationKeys(report.Summary)
	renderReportScopeSection(&builder, report.Scope)
	renderReportExecutionSection(&builder, report.Execution)
	renderBreakdownSection(&builder, "## Selection summary", "- No scanners selected", selectionKeys, func(key string) int {
		return report.Summary.SelectionBreakdown[key]
	})
	renderBreakdownSection(&builder, "## Verified classification summary", "- No verified scan results recorded", classificationKeys, func(key string) int {
		return report.Summary.VerifiedClassificationBreakdown[key]
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

		builder.WriteString(fmt.Sprintf("### %s\n\n", auditEndpointHeading(result.DiscoveredEndpoint)))
		renderDiscoveredEndpointFields(&builder, result.DiscoveredEndpoint)
		renderHintsSection(&builder, result.DiscoveredEndpoint.Hints)

		builder.WriteString("\n#### Selection\n\n")
		builder.WriteString(fmt.Sprintf("- Status: %s\n", result.Selection.Status))
		if result.Selection.SelectedScanner != "" {
			builder.WriteString(fmt.Sprintf("- Selected scanner: %s\n", result.Selection.SelectedScanner))
		}
		if result.Selection.Reason != "" {
			builder.WriteString(fmt.Sprintf("- Reason: %s\n", result.Selection.Reason))
		}

		renderStringListSection(&builder, "Warnings", result.DiscoveredEndpoint.Warnings)
		renderStringListSection(&builder, "Errors", result.DiscoveredEndpoint.Errors)
		renderVerifiedTLSResult(&builder, result.TLSResult)
	}

	return builder.String()
}

func auditEndpointHeading(endpoint core.DiscoveredEndpoint) string {
	return net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)) + "/" + endpoint.Transport
}
