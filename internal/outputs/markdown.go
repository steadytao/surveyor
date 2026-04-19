package outputs

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

// RenderMarkdown renders the human-readable TLS inventory report from the
// canonical report model.
func RenderMarkdown(report core.Report) string {
	var builder strings.Builder

	builder.WriteString("# Surveyor TLS Inventory Report\n\n")
	builder.WriteString(fmt.Sprintf("- Generated: %s\n", report.GeneratedAt.UTC().Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("- Total targets: %d\n", report.Summary.TotalTargets))
	builder.WriteString(fmt.Sprintf("- Reachable targets: %d\n", report.Summary.ReachableTargets))
	builder.WriteString(fmt.Sprintf("- Unreachable targets: %d\n\n", report.Summary.UnreachableTargets))

	classificationKeys := sortedClassificationKeys(report.Summary)
	renderBreakdownSection(&builder, "## Classification summary", "- No classifications recorded", classificationKeys, func(key string) int {
		return report.Summary.ClassificationBreakdown[key]
	})

	builder.WriteString("## Targets\n\n")
	if len(report.Results) == 0 {
		builder.WriteString("No targets were included in this report.\n")
		return builder.String()
	}

	for index, result := range report.Results {
		if index > 0 {
			builder.WriteString("\n")
		}

		builder.WriteString(fmt.Sprintf("### %s\n\n", targetHeading(result)))
		builder.WriteString(fmt.Sprintf("- Host: %s\n", result.Host))
		builder.WriteString(fmt.Sprintf("- Port: %d\n", result.Port))
		builder.WriteString(fmt.Sprintf("- Scanned at: %s\n", result.ScannedAt.UTC().Format(time.RFC3339)))
		builder.WriteString(fmt.Sprintf("- Reachable: %t\n", result.Reachable))
		builder.WriteString(fmt.Sprintf("- Classification: %s\n", defaultString(result.Classification, "unclassified")))

		if result.Address != "" {
			builder.WriteString(fmt.Sprintf("- Address: %s\n", result.Address))
		}
		if result.TLSVersion != "" {
			builder.WriteString(fmt.Sprintf("- TLS version: %s\n", result.TLSVersion))
		}
		if result.CipherSuite != "" {
			builder.WriteString(fmt.Sprintf("- Cipher suite: %s\n", result.CipherSuite))
		}
		if result.LeafKeyAlgorithm != "" {
			builder.WriteString(fmt.Sprintf("- Leaf key algorithm: %s\n", result.LeafKeyAlgorithm))
		}
		if result.LeafKeySize > 0 {
			builder.WriteString(fmt.Sprintf("- Leaf key size: %d\n", result.LeafKeySize))
		}
		if result.LeafSignatureAlgorithm != "" {
			builder.WriteString(fmt.Sprintf("- Leaf signature algorithm: %s\n", result.LeafSignatureAlgorithm))
		}

		// Markdown is intentionally derived from the canonical result model.
		// If a fact matters here, it should already exist in JSON.
		renderTargetFindingsSection(&builder, result.Findings)
		renderStringListSection(&builder, "Warnings", result.Warnings)
		renderStringListSection(&builder, "Errors", result.Errors)
	}

	return builder.String()
}

func targetHeading(result core.TargetResult) string {
	endpoint := net.JoinHostPort(result.Host, strconv.Itoa(result.Port))
	if result.Name != "" {
		return result.Name + " (" + endpoint + ")"
	}

	return endpoint
}

func defaultString(value string, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}
