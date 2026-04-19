package outputs

import (
	"fmt"
	"strings"

	"github.com/steadytao/surveyor/internal/core"
)

func renderReportScopeSection(builder *strings.Builder, scope *core.ReportScope) {
	if scope == nil {
		return
	}

	builder.WriteString("## Scope\n\n")
	builder.WriteString(fmt.Sprintf("- Scope kind: %s\n", scope.ScopeKind))
	if scope.InputKind != "" {
		builder.WriteString(fmt.Sprintf("- Input kind: %s\n", scope.InputKind))
	}
	if scope.CIDR != "" {
		builder.WriteString(fmt.Sprintf("- CIDR: %s\n", scope.CIDR))
	}
	if scope.TargetsFile != "" {
		builder.WriteString(fmt.Sprintf("- Targets file: %s\n", scope.TargetsFile))
	}
	renderInventoryFileScope(builder, scope)
	renderScopePorts(builder, scope)
	builder.WriteString("\n")
}

func renderReportExecutionSection(builder *strings.Builder, execution *core.ReportExecution) {
	if execution == nil {
		return
	}

	builder.WriteString("## Execution\n\n")
	if execution.Profile != "" {
		builder.WriteString(fmt.Sprintf("- Profile: %s\n", execution.Profile))
	}
	if execution.MaxHosts > 0 {
		builder.WriteString(fmt.Sprintf("- Max hosts: %d\n", execution.MaxHosts))
	}
	if execution.MaxAttempts > 0 {
		builder.WriteString(fmt.Sprintf("- Max attempts: %d\n", execution.MaxAttempts))
	}
	if execution.AttemptCount > 0 {
		builder.WriteString(fmt.Sprintf("- Attempt count: %d\n", execution.AttemptCount))
	}
	if execution.MaxConcurrency > 0 {
		builder.WriteString(fmt.Sprintf("- Max concurrency: %d\n", execution.MaxConcurrency))
	}
	if execution.Timeout != "" {
		builder.WriteString(fmt.Sprintf("- Timeout per attempt: %s\n", execution.Timeout))
	}
	builder.WriteString("\n")
}

func renderBreakdownSection(
	builder *strings.Builder,
	heading string,
	emptyText string,
	keys []string,
	value func(string) int,
) {
	builder.WriteString(heading)
	builder.WriteString("\n\n")
	if len(keys) == 0 {
		builder.WriteString(emptyText)
		builder.WriteString("\n\n")
		return
	}

	for _, key := range keys {
		builder.WriteString(fmt.Sprintf("- %s: %d\n", key, value(key)))
	}
	builder.WriteString("\n")
}

func renderStringListSection(builder *strings.Builder, heading string, values []string) {
	if len(values) == 0 {
		return
	}

	builder.WriteString("\n#### ")
	builder.WriteString(heading)
	builder.WriteString("\n\n")
	for _, value := range values {
		builder.WriteString(fmt.Sprintf("- %s\n", value))
	}
}

func renderHintsSection(builder *strings.Builder, hints []core.DiscoveryHint) {
	if len(hints) == 0 {
		return
	}

	builder.WriteString("\n#### Hints\n\n")
	for _, hint := range hints {
		builder.WriteString(fmt.Sprintf("- %s (%s)\n", hint.Protocol, defaultString(hint.Confidence, "unknown")))
		for _, evidence := range hint.Evidence {
			builder.WriteString(fmt.Sprintf("  - evidence: %s\n", evidence))
		}
	}
}

func renderTargetFindingsSection(builder *strings.Builder, findings []core.Finding) {
	if len(findings) == 0 {
		return
	}

	builder.WriteString("\n#### Findings\n\n")
	for _, finding := range findings {
		builder.WriteString(fmt.Sprintf("- %s (%s): %s\n", finding.Code, finding.Severity, finding.Summary))
		for _, evidence := range finding.Evidence {
			builder.WriteString(fmt.Sprintf("  - evidence: %s\n", evidence))
		}
		if finding.Recommendation != "" {
			builder.WriteString(fmt.Sprintf("  - recommendation: %s\n", finding.Recommendation))
		}
	}
}

func renderDiscoveredEndpointFields(builder *strings.Builder, endpoint core.DiscoveredEndpoint) {
	builder.WriteString(fmt.Sprintf("- Scope kind: %s\n", endpoint.ScopeKind))
	builder.WriteString(fmt.Sprintf("- Host: %s\n", endpoint.Host))
	builder.WriteString(fmt.Sprintf("- Port: %d\n", endpoint.Port))
	builder.WriteString(fmt.Sprintf("- Transport: %s\n", endpoint.Transport))
	builder.WriteString(fmt.Sprintf("- State: %s\n", endpoint.State))

	if endpoint.PID > 0 {
		builder.WriteString(fmt.Sprintf("- PID: %d\n", endpoint.PID))
	}
	if endpoint.ProcessName != "" {
		builder.WriteString(fmt.Sprintf("- Process name: %s\n", endpoint.ProcessName))
	}
	if endpoint.Executable != "" {
		builder.WriteString(fmt.Sprintf("- Executable: %s\n", endpoint.Executable))
	}
	renderInventoryAnnotation(builder, endpoint.Inventory)
}

func renderVerifiedTLSResult(builder *strings.Builder, result *core.TargetResult) {
	if result == nil {
		return
	}

	builder.WriteString("\n#### Verified TLS Result\n\n")
	builder.WriteString(fmt.Sprintf("- Classification: %s\n", result.Classification))
	builder.WriteString(fmt.Sprintf("- Reachable: %t\n", result.Reachable))
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
}
