package outputs

import (
	"fmt"
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
		if len(report.Scope.Ports) > 0 {
			builder.WriteString(fmt.Sprintf("- Ports: %s\n", renderPortsList(report.Scope.Ports)))
		}
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

	builder.WriteString("## Selection summary\n\n")
	selectionKeys := sortedSelectionKeys(report.Summary)
	if len(selectionKeys) == 0 {
		builder.WriteString("- No scanners selected\n\n")
	} else {
		for _, key := range selectionKeys {
			builder.WriteString(fmt.Sprintf("- %s: %d\n", key, report.Summary.SelectionBreakdown[key]))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Verified classification summary\n\n")
	classificationKeys := sortedVerifiedClassificationKeys(report.Summary)
	if len(classificationKeys) == 0 {
		builder.WriteString("- No verified scan results recorded\n\n")
	} else {
		for _, key := range classificationKeys {
			builder.WriteString(fmt.Sprintf("- %s: %d\n", key, report.Summary.VerifiedClassificationBreakdown[key]))
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

		builder.WriteString(fmt.Sprintf("### %s\n\n", auditEndpointHeading(result.DiscoveredEndpoint)))
		builder.WriteString(fmt.Sprintf("- Scope kind: %s\n", result.DiscoveredEndpoint.ScopeKind))
		builder.WriteString(fmt.Sprintf("- Host: %s\n", result.DiscoveredEndpoint.Host))
		builder.WriteString(fmt.Sprintf("- Port: %d\n", result.DiscoveredEndpoint.Port))
		builder.WriteString(fmt.Sprintf("- Transport: %s\n", result.DiscoveredEndpoint.Transport))
		builder.WriteString(fmt.Sprintf("- State: %s\n", result.DiscoveredEndpoint.State))

		if result.DiscoveredEndpoint.PID > 0 {
			builder.WriteString(fmt.Sprintf("- PID: %d\n", result.DiscoveredEndpoint.PID))
		}
		if result.DiscoveredEndpoint.ProcessName != "" {
			builder.WriteString(fmt.Sprintf("- Process name: %s\n", result.DiscoveredEndpoint.ProcessName))
		}
		if result.DiscoveredEndpoint.Executable != "" {
			builder.WriteString(fmt.Sprintf("- Executable: %s\n", result.DiscoveredEndpoint.Executable))
		}
		renderInventoryAnnotation(&builder, result.DiscoveredEndpoint.Inventory)

		if len(result.DiscoveredEndpoint.Hints) > 0 {
			builder.WriteString("\n#### Hints\n\n")
			for _, hint := range result.DiscoveredEndpoint.Hints {
				builder.WriteString(fmt.Sprintf("- %s (%s)\n", hint.Protocol, defaultString(hint.Confidence, "unknown")))
				for _, evidence := range hint.Evidence {
					builder.WriteString(fmt.Sprintf("  - evidence: %s\n", evidence))
				}
			}
		}

		builder.WriteString("\n#### Selection\n\n")
		builder.WriteString(fmt.Sprintf("- Status: %s\n", result.Selection.Status))
		if result.Selection.SelectedScanner != "" {
			builder.WriteString(fmt.Sprintf("- Selected scanner: %s\n", result.Selection.SelectedScanner))
		}
		if result.Selection.Reason != "" {
			builder.WriteString(fmt.Sprintf("- Reason: %s\n", result.Selection.Reason))
		}

		if len(result.DiscoveredEndpoint.Warnings) > 0 {
			builder.WriteString("\n#### Warnings\n\n")
			for _, warning := range result.DiscoveredEndpoint.Warnings {
				builder.WriteString(fmt.Sprintf("- %s\n", warning))
			}
		}

		if len(result.DiscoveredEndpoint.Errors) > 0 {
			builder.WriteString("\n#### Errors\n\n")
			for _, errText := range result.DiscoveredEndpoint.Errors {
				builder.WriteString(fmt.Sprintf("- %s\n", errText))
			}
		}

		if result.TLSResult != nil {
			builder.WriteString("\n#### Verified TLS Result\n\n")
			builder.WriteString(fmt.Sprintf("- Classification: %s\n", result.TLSResult.Classification))
			builder.WriteString(fmt.Sprintf("- Reachable: %t\n", result.TLSResult.Reachable))
			if result.TLSResult.TLSVersion != "" {
				builder.WriteString(fmt.Sprintf("- TLS version: %s\n", result.TLSResult.TLSVersion))
			}
			if result.TLSResult.CipherSuite != "" {
				builder.WriteString(fmt.Sprintf("- Cipher suite: %s\n", result.TLSResult.CipherSuite))
			}
			if result.TLSResult.LeafKeyAlgorithm != "" {
				builder.WriteString(fmt.Sprintf("- Leaf key algorithm: %s\n", result.TLSResult.LeafKeyAlgorithm))
			}
			if result.TLSResult.LeafKeySize > 0 {
				builder.WriteString(fmt.Sprintf("- Leaf key size: %d\n", result.TLSResult.LeafKeySize))
			}
			if result.TLSResult.LeafSignatureAlgorithm != "" {
				builder.WriteString(fmt.Sprintf("- Leaf signature algorithm: %s\n", result.TLSResult.LeafSignatureAlgorithm))
			}
		}
	}

	return builder.String()
}

func auditEndpointHeading(endpoint core.DiscoveredEndpoint) string {
	return fmt.Sprintf("%s:%d/%s", endpoint.Host, endpoint.Port, endpoint.Transport)
}
