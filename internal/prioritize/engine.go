package prioritize

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/steadytao/surveyor/internal/baseline"
	"github.com/steadytao/surveyor/internal/core"
)

type rankedItem struct {
	Item
	score int
}

// ParseProfile validates the requested prioritization profile.
func ParseProfile(raw string) (Profile, error) {
	profileText := strings.ToLower(strings.TrimSpace(raw))
	if profileText == "" {
		return ProfileMigrationReadiness, nil
	}

	profile := Profile(profileText)
	switch profile {
	case ProfileMigrationReadiness, ProfileChangeRisk:
		return profile, nil
	default:
		return "", fmt.Errorf("invalid --profile %q: must be one of migration-readiness or change-risk", raw)
	}
}

// BuildTLSReport assembles the canonical prioritization report for a current
// TLS report.
func BuildTLSReport(source core.Report, profile Profile, generatedAt time.Time) (Report, error) {
	if err := validateSourceProfile(profile); err != nil {
		return Report{}, err
	}

	rankedItems := make([]rankedItem, 0, len(source.Results))
	for _, result := range source.Results {
		rankedItems = append(rankedItems, prioritizeTLSResult(result, profile)...)
	}

	return buildReport(
		core.NewReportMetadata(core.ReportKindPrioritization, source.ScopeKind, source.ScopeDescription),
		profile,
		source.ReportKind,
		source.GeneratedAt,
		source.Scope,
		rankedItems,
		generatedAt,
	), nil
}

// BuildAuditReport assembles the canonical prioritization report for a current
// audit report.
func BuildAuditReport(source core.AuditReport, profile Profile, generatedAt time.Time) (Report, error) {
	if err := validateSourceProfile(profile); err != nil {
		return Report{}, err
	}

	rankedItems := make([]rankedItem, 0, len(source.Results))
	for _, result := range source.Results {
		rankedItems = append(rankedItems, prioritizeAuditResult(result, profile)...)
	}

	return buildReport(
		core.NewReportMetadata(core.ReportKindPrioritization, source.ScopeKind, source.ScopeDescription),
		profile,
		source.ReportKind,
		source.GeneratedAt,
		source.Scope,
		rankedItems,
		generatedAt,
	), nil
}

func validateSourceProfile(profile Profile) error {
	switch profile {
	case ProfileMigrationReadiness, ProfileChangeRisk:
		return nil
	default:
		return fmt.Errorf("unsupported prioritization profile %q", profile)
	}
}

func buildReport(metadata core.ReportMetadata, profile Profile, sourceReportKind core.ReportKind, sourceGeneratedAt time.Time, scope *core.ReportScope, rankedItems []rankedItem, generatedAt time.Time) Report {
	sortRankedItems(rankedItems)

	items := make([]Item, 0, len(rankedItems))
	for index, ranked := range rankedItems {
		item := ranked.Item
		item.Rank = index + 1
		item.Evidence = cloneStrings(item.Evidence)
		items = append(items, item)
	}

	return Report{
		ReportMetadata:    metadata,
		GeneratedAt:       generatedAt.UTC(),
		Profile:           profile,
		SourceReportKind:  sourceReportKind,
		SourceGeneratedAt: sourceGeneratedAt.UTC(),
		Scope:             cloneReportScope(scope),
		Summary:           buildSummary(items),
		Items:             items,
	}
}

func buildSummary(items []Item) Summary {
	summary := Summary{
		TotalItems:        len(items),
		SeverityBreakdown: map[string]int{},
		CodeBreakdown:     map[string]int{},
	}

	for _, item := range items {
		summary.SeverityBreakdown[string(item.Severity)] += 1
		summary.CodeBreakdown[item.Code] += 1
	}

	if len(summary.SeverityBreakdown) == 0 {
		summary.SeverityBreakdown = nil
	}
	if len(summary.CodeBreakdown) == 0 {
		summary.CodeBreakdown = nil
	}

	return summary
}

func prioritizeTLSResult(result core.TargetResult, profile Profile) []rankedItem {
	targetIdentity := baseline.TargetResultIdentityKey(result)
	items := make([]rankedItem, 0, len(result.Findings)+2)

	for _, finding := range result.Findings {
		items = append(items, rankedFindingItem(targetIdentity, finding, profile))
	}

	if len(result.Errors) > 0 && !hasFindingCode(result.Findings, "target-unreachable") {
		items = append(items, rankedSyntheticItem(
			targetIdentity,
			core.SeverityMedium,
			"endpoint-errors",
			"The endpoint emitted errors during TLS collection.",
			errorsReason(profile),
			result.Errors,
			"Review the errors and confirm the endpoint before using this result for migration planning.",
			syntheticScore(profile, "endpoint-errors", core.SeverityMedium),
		))
	}

	if len(result.Warnings) > 0 {
		items = append(items, rankedSyntheticItem(
			targetIdentity,
			core.SeverityLow,
			"endpoint-warnings",
			"The endpoint emitted warnings during TLS collection.",
			warningsReason(profile),
			result.Warnings,
			"Review the warnings before treating this result as complete.",
			syntheticScore(profile, "endpoint-warnings", core.SeverityLow),
		))
	}

	return items
}

func prioritizeAuditResult(result core.AuditResult, profile Profile) []rankedItem {
	targetIdentity := baseline.AuditResultIdentityKey(result)
	items := make([]rankedItem, 0, len(result.DiscoveredEndpoint.Hints)+3)

	if result.TLSResult != nil {
		for _, ranked := range prioritizeTLSResult(*result.TLSResult, profile) {
			ranked.TargetIdentity = targetIdentity
			items = append(items, ranked)
		}
	}

	if result.Selection.Status == core.AuditSelectionStatusSkipped && result.Selection.Reason != "" {
		severity := core.SeverityLow
		if strings.Contains(strings.ToLower(result.Selection.Reason), "did not respond") {
			severity = core.SeverityMedium
		}
		evidence := cloneStrings(result.DiscoveredEndpoint.Errors)
		if len(evidence) == 0 {
			evidence = []string{result.Selection.Reason}
		}

		items = append(items, rankedSyntheticItem(
			targetIdentity,
			severity,
			"audit-selection-skipped",
			"The endpoint was not scanned during audit.",
			result.Selection.Reason,
			evidence,
			auditSelectionRecommendation(result.Selection.Reason),
			syntheticScore(profile, "audit-selection-skipped", severity),
		))
	} else if len(result.DiscoveredEndpoint.Errors) > 0 {
		items = append(items, rankedSyntheticItem(
			targetIdentity,
			core.SeverityMedium,
			"endpoint-errors",
			"The endpoint emitted errors during audit discovery.",
			errorsReason(profile),
			result.DiscoveredEndpoint.Errors,
			"Review the discovery errors and confirm the endpoint state before relying on this audit result.",
			syntheticScore(profile, "endpoint-errors", core.SeverityMedium),
		))
	}

	if len(result.DiscoveredEndpoint.Warnings) > 0 {
		items = append(items, rankedSyntheticItem(
			targetIdentity,
			core.SeverityLow,
			"endpoint-warnings",
			"The endpoint emitted warnings during audit discovery.",
			warningsReason(profile),
			result.DiscoveredEndpoint.Warnings,
			"Review the discovery warnings before treating this audit result as complete.",
			syntheticScore(profile, "endpoint-warnings", core.SeverityLow),
		))
	}

	return items
}

func rankedFindingItem(targetIdentity string, finding core.Finding, profile Profile) rankedItem {
	return rankedItem{
		Item: Item{
			Severity:       finding.Severity,
			Code:           finding.Code,
			Summary:        finding.Summary,
			TargetIdentity: targetIdentity,
			Reason:         findingReason(profile, finding.Code),
			Evidence:       cloneStrings(finding.Evidence),
			Recommendation: finding.Recommendation,
		},
		score: findingScore(profile, finding),
	}
}

func rankedSyntheticItem(targetIdentity string, severity core.Severity, code string, summary string, reason string, evidence []string, recommendation string, score int) rankedItem {
	return rankedItem{
		Item: Item{
			Severity:       severity,
			Code:           code,
			Summary:        summary,
			TargetIdentity: targetIdentity,
			Reason:         reason,
			Evidence:       cloneStrings(evidence),
			Recommendation: recommendation,
		},
		score: score,
	}
}

func findingScore(profile Profile, finding core.Finding) int {
	return severityBaseScore(finding.Severity) + profileFindingBonus(profile, finding.Code)
}

func syntheticScore(profile Profile, code string, severity core.Severity) int {
	return severityBaseScore(severity) + profileSyntheticBonus(profile, code)
}

func severityBaseScore(severity core.Severity) int {
	switch severity {
	case core.SeverityCritical:
		return 500
	case core.SeverityHigh:
		return 400
	case core.SeverityMedium:
		return 300
	case core.SeverityLow:
		return 200
	case core.SeverityInfo:
		return 100
	default:
		return 0
	}
}

func profileFindingBonus(profile Profile, code string) int {
	switch profile {
	case ProfileMigrationReadiness:
		switch code {
		case "legacy-tls-version":
			return 90
		case "classical-certificate-identity":
			return 80
		case "incomplete-certificate-observation", "unsupported-certificate-identity":
			return 75
		case "target-unreachable":
			return 40
		default:
			return 20
		}
	case ProfileChangeRisk:
		switch code {
		case "target-unreachable":
			return 90
		case "legacy-tls-version":
			return 70
		case "incomplete-certificate-observation":
			return 60
		case "classical-certificate-identity":
			return 30
		default:
			return 20
		}
	default:
		return 0
	}
}

func profileSyntheticBonus(profile Profile, code string) int {
	switch profile {
	case ProfileMigrationReadiness:
		switch code {
		case "audit-selection-skipped":
			return 50
		case "endpoint-errors":
			return 35
		case "endpoint-warnings":
			return 20
		default:
			return 10
		}
	case ProfileChangeRisk:
		switch code {
		case "endpoint-errors":
			return 80
		case "audit-selection-skipped":
			return 70
		case "endpoint-warnings":
			return 45
		default:
			return 10
		}
	default:
		return 0
	}
}

func findingReason(profile Profile, code string) string {
	switch profile {
	case ProfileMigrationReadiness:
		switch code {
		case "legacy-tls-version":
			return "Legacy TLS exposure should be addressed before treating transport posture as migration-ready."
		case "classical-certificate-identity":
			return "Classical certificate identity is a direct migration dependency."
		case "incomplete-certificate-observation", "unsupported-certificate-identity":
			return "Incomplete or unsupported certificate evidence blocks confident migration planning."
		case "target-unreachable":
			return "Unreachable endpoints need review before they can be treated as assessed."
		}
	case ProfileChangeRisk:
		switch code {
		case "target-unreachable":
			return "Lost reachability is an operational change that needs investigation."
		case "legacy-tls-version":
			return "Legacy transport posture remains an active risk to monitor."
		case "incomplete-certificate-observation":
			return "Incomplete evidence makes current transport state less trustworthy."
		}
	}

	return "Surveyor derived this item from current report evidence."
}

func warningsReason(profile Profile) string {
	switch profile {
	case ProfileChangeRisk:
		return "Collection warnings can indicate unstable or incomplete current state."
	default:
		return "Warnings reduce confidence in the current result and should be reviewed."
	}
}

func errorsReason(profile Profile) string {
	switch profile {
	case ProfileChangeRisk:
		return "Collection errors may indicate degraded operational state."
	default:
		return "Errors reduce confidence in the current result and may block migration planning."
	}
}

func auditSelectionRecommendation(reason string) string {
	if strings.Contains(strings.ToLower(reason), "did not respond") {
		return "Confirm the endpoint, network path and whether a TLS service is still expected at this address."
	}

	return "Review why the endpoint was skipped before treating it as covered by the audit."
}

func hasFindingCode(findings []core.Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}

	return false
}

func sortRankedItems(items []rankedItem) {
	slices.SortFunc(items, func(left rankedItem, right rankedItem) int {
		if comparison := cmp.Compare(right.score, left.score); comparison != 0 {
			return comparison
		}
		if comparison := cmp.Compare(severityRank(right.Severity), severityRank(left.Severity)); comparison != 0 {
			return comparison
		}
		if comparison := cmp.Compare(left.TargetIdentity, right.TargetIdentity); comparison != 0 {
			return comparison
		}
		if comparison := cmp.Compare(left.Code, right.Code); comparison != 0 {
			return comparison
		}
		return cmp.Compare(left.Summary, right.Summary)
	})
}

func severityRank(severity core.Severity) int {
	switch severity {
	case core.SeverityCritical:
		return 5
	case core.SeverityHigh:
		return 4
	case core.SeverityMedium:
		return 3
	case core.SeverityLow:
		return 2
	case core.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	return append([]string(nil), values...)
}

func cloneReportScope(scope *core.ReportScope) *core.ReportScope {
	if scope == nil {
		return nil
	}

	cloned := *scope
	cloned.Ports = append([]int(nil), scope.Ports...)
	return &cloned
}
