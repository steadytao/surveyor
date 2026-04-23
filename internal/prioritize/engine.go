// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

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

type rankingContext struct {
	targetIdentity string
	scope          *core.ReportScope
	inventory      *core.InventoryAnnotation
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
func BuildTLSReport(source core.Report, profile Profile, generatedAt time.Time, workflowView *core.WorkflowContext) (Report, error) {
	if err := validateSourceProfile(profile); err != nil {
		return Report{}, err
	}
	if hasWorkflowView(workflowView) {
		return Report{}, fmt.Errorf("workflow grouping and filtering are supported only for audit input")
	}

	rankedItems := make([]rankedItem, 0, len(source.Results))
	for _, result := range source.Results {
		rankedItems = append(rankedItems, prioritizeTLSResult(result, profile, rankingContext{
			targetIdentity: baseline.TargetResultIdentityKey(result),
			scope:          source.Scope,
		})...)
	}

	return buildReport(
		core.NewReportMetadata(core.ReportKindPrioritization, source.ScopeKind, source.ScopeDescription),
		profile,
		source.ReportKind,
		source.GeneratedAt,
		source.Scope,
		nil,
		rankedItems,
		nil,
		nil,
		generatedAt,
	), nil
}

// BuildAuditReport assembles the canonical prioritization report for a current
// audit report.
func BuildAuditReport(source core.AuditReport, profile Profile, generatedAt time.Time, workflowView *core.WorkflowContext) (Report, error) {
	if err := validateSourceProfile(profile); err != nil {
		return Report{}, err
	}

	inventoryByIdentity := make(map[string]*core.InventoryAnnotation, len(source.Results))
	rankedItems := make([]rankedItem, 0, len(source.Results))
	workflowFindings := make([]core.WorkflowFinding, 0)
	for _, result := range source.Results {
		targetIdentity := baseline.AuditResultIdentityKey(result)
		inventoryByIdentity[targetIdentity] = result.DiscoveredEndpoint.Inventory
		context := rankingContext{
			targetIdentity: targetIdentity,
			scope:          source.Scope,
			inventory:      result.DiscoveredEndpoint.Inventory,
		}
		rankedItems = append(rankedItems, prioritizeAuditResult(result, profile, context)...)
		workflowFindings = append(workflowFindings, workflowFindingsForAuditResult(result, source.Scope)...)
	}

	filteredItems := filterRankedItems(rankedItems, inventoryByIdentity, workflowView)
	filteredWorkflowFindings := filterWorkflowFindings(workflowFindings, inventoryByIdentity, workflowView)
	groupedSummaries := buildAuditGroupedSummaries(filteredItems, inventoryByIdentity, workflowView)

	return buildReport(
		core.NewReportMetadata(core.ReportKindPrioritization, source.ScopeKind, source.ScopeDescription),
		profile,
		source.ReportKind,
		source.GeneratedAt,
		source.Scope,
		workflowView,
		filteredItems,
		groupedSummaries,
		filteredWorkflowFindings,
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

func buildReport(metadata core.ReportMetadata, profile Profile, sourceReportKind core.ReportKind, sourceGeneratedAt time.Time, scope *core.ReportScope, workflowView *core.WorkflowContext, rankedItems []rankedItem, groupedSummaries []core.GroupedSummary, workflowFindings []core.WorkflowFinding, generatedAt time.Time) Report {
	sortRankedItems(rankedItems)
	sortWorkflowFindings(workflowFindings)

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
		WorkflowView:      core.CloneWorkflowContext(workflowView),
		Summary:           buildSummary(items),
		GroupedSummaries:  core.CloneGroupedSummaries(groupedSummaries),
		WorkflowFindings:  core.CloneWorkflowFindings(workflowFindings),
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

func prioritizeTLSResult(result core.TargetResult, profile Profile, context rankingContext) []rankedItem {
	items := make([]rankedItem, 0, len(result.Findings)+2)

	for _, finding := range result.Findings {
		items = append(items, rankedFindingItem(finding, profile, context))
	}

	if len(result.Errors) > 0 && !hasFindingCode(result.Findings, "target-unreachable") {
		items = append(items, rankedSyntheticItem(
			context.targetIdentity,
			core.SeverityMedium,
			"endpoint-errors",
			"The endpoint emitted errors during TLS collection.",
			errorsReason(profile, context.inventory),
			result.Errors,
			"Review the errors and confirm the endpoint before using this result for migration planning.",
			syntheticScore(profile, "endpoint-errors", core.SeverityMedium, context.inventory),
		))
	}

	if len(result.Warnings) > 0 {
		items = append(items, rankedSyntheticItem(
			context.targetIdentity,
			core.SeverityLow,
			"endpoint-warnings",
			"The endpoint emitted warnings during TLS collection.",
			warningsReason(profile, context.inventory),
			result.Warnings,
			"Review the warnings before treating this result as complete.",
			syntheticScore(profile, "endpoint-warnings", core.SeverityLow, context.inventory),
		))
	}

	return items
}

func prioritizeAuditResult(result core.AuditResult, profile Profile, context rankingContext) []rankedItem {
	items := make([]rankedItem, 0, len(result.DiscoveredEndpoint.Hints)+3)

	if result.TLSResult != nil {
		items = append(items, prioritizeTLSResult(*result.TLSResult, profile, context)...)
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
			context.targetIdentity,
			severity,
			"audit-selection-skipped",
			"The endpoint was not scanned during audit.",
			selectionReason(profile, result.Selection.Reason, context.inventory),
			evidence,
			auditSelectionRecommendation(result.Selection.Reason),
			syntheticScore(profile, "audit-selection-skipped", severity, context.inventory),
		))
	} else if len(result.DiscoveredEndpoint.Errors) > 0 {
		items = append(items, rankedSyntheticItem(
			context.targetIdentity,
			core.SeverityMedium,
			"endpoint-errors",
			"The endpoint emitted errors during audit discovery.",
			errorsReason(profile, context.inventory),
			result.DiscoveredEndpoint.Errors,
			"Review the discovery errors and confirm the endpoint state before relying on this audit result.",
			syntheticScore(profile, "endpoint-errors", core.SeverityMedium, context.inventory),
		))
	}

	if len(result.DiscoveredEndpoint.Warnings) > 0 {
		items = append(items, rankedSyntheticItem(
			context.targetIdentity,
			core.SeverityLow,
			"endpoint-warnings",
			"The endpoint emitted warnings during audit discovery.",
			warningsReason(profile, context.inventory),
			result.DiscoveredEndpoint.Warnings,
			"Review the discovery warnings before treating this audit result as complete.",
			syntheticScore(profile, "endpoint-warnings", core.SeverityLow, context.inventory),
		))
	}

	return items
}

func rankedFindingItem(finding core.Finding, profile Profile, context rankingContext) rankedItem {
	return rankedItem{
		Item: Item{
			Severity:       finding.Severity,
			Code:           finding.Code,
			Summary:        finding.Summary,
			TargetIdentity: context.targetIdentity,
			Reason:         findingReason(profile, finding.Code, context.inventory),
			Evidence:       cloneStrings(finding.Evidence),
			Recommendation: finding.Recommendation,
		},
		score: findingScore(profile, finding, context.inventory),
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

func findingScore(profile Profile, finding core.Finding, inventory *core.InventoryAnnotation) int {
	return severityBaseScore(finding.Severity) + profileFindingBonus(profile, finding.Code) + metadataScoreBonus(profile, inventory)
}

func syntheticScore(profile Profile, code string, severity core.Severity, inventory *core.InventoryAnnotation) int {
	return severityBaseScore(severity) + profileSyntheticBonus(profile, code) + metadataScoreBonus(profile, inventory)
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

func findingReason(profile Profile, code string, inventory *core.InventoryAnnotation) string {
	base := "Surveyor derived this item from current report evidence."
	switch profile {
	case ProfileMigrationReadiness:
		switch code {
		case "legacy-tls-version":
			base = "Legacy TLS exposure should be addressed before treating transport posture as migration-ready."
		case "classical-certificate-identity":
			base = "Classical certificate identity is a direct migration dependency."
		case "incomplete-certificate-observation", "unsupported-certificate-identity":
			base = "Incomplete or unsupported certificate evidence blocks confident migration planning."
		case "target-unreachable":
			base = "Unreachable endpoints need review before they can be treated as assessed."
		}
	case ProfileChangeRisk:
		switch code {
		case "target-unreachable":
			base = "Lost reachability is an operational change that needs investigation."
		case "legacy-tls-version":
			base = "Legacy transport posture remains an active risk to monitor."
		case "incomplete-certificate-observation":
			base = "Incomplete evidence makes current transport state less trustworthy."
		}
	}

	return base + metadataReasonSuffix(inventory)
}

func warningsReason(profile Profile, inventory *core.InventoryAnnotation) string {
	base := "Warnings reduce confidence in the current result and should be reviewed."
	switch profile {
	case ProfileChangeRisk:
		base = "Collection warnings can indicate unstable or incomplete current state."
	}

	return base + metadataReasonSuffix(inventory)
}

func errorsReason(profile Profile, inventory *core.InventoryAnnotation) string {
	base := "Errors reduce confidence in the current result and may block migration planning."
	switch profile {
	case ProfileChangeRisk:
		base = "Collection errors may indicate degraded operational state."
	}

	return base + metadataReasonSuffix(inventory)
}

func selectionReason(profile Profile, selectionReason string, inventory *core.InventoryAnnotation) string {
	base := selectionReason
	if profile == ProfileChangeRisk && strings.Contains(strings.ToLower(selectionReason), "did not respond") {
		base = "The endpoint did not respond during remote discovery and needs investigation."
	}

	return base + metadataReasonSuffix(inventory)
}

func auditSelectionRecommendation(reason string) string {
	if strings.Contains(strings.ToLower(reason), "did not respond") {
		return "Confirm the endpoint, network path and whether a TLS service is still expected at this address."
	}

	return "Review why the endpoint was skipped before treating it as covered by the audit."
}

func workflowFindingsForAuditResult(result core.AuditResult, scope *core.ReportScope) []core.WorkflowFinding {
	inventory := result.DiscoveredEndpoint.Inventory
	if inventory == nil {
		return nil
	}

	targetIdentity := baseline.AuditResultIdentityKey(result)
	findings := make([]core.WorkflowFinding, 0, 4)

	if strings.TrimSpace(inventory.Owner) == "" {
		findings = append(findings, core.WorkflowFinding{
			Severity:       metadataGapSeverity(inventory),
			Code:           "missing-owner",
			Summary:        "The imported endpoint is missing owner metadata.",
			TargetIdentity: targetIdentity,
			Reason:         "Owner metadata is needed for operational follow-up and grouped reporting.",
			Evidence:       inventoryEvidence(result, scope),
			Recommendation: "Add owner metadata to the imported inventory source.",
		})
	}

	if strings.TrimSpace(inventory.Environment) == "" {
		findings = append(findings, core.WorkflowFinding{
			Severity:       metadataGapSeverity(inventory),
			Code:           "missing-environment",
			Summary:        "The imported endpoint is missing environment metadata.",
			TargetIdentity: targetIdentity,
			Reason:         "Environment metadata is needed to prioritise production and non-production work differently.",
			Evidence:       inventoryEvidence(result, scope),
			Recommendation: "Add environment metadata to the imported inventory source.",
		})
	}

	if len(inventory.Provenance) == 0 {
		findings = append(findings, core.WorkflowFinding{
			Severity:       core.SeverityLow,
			Code:           "weak-provenance",
			Summary:        "The imported endpoint has no recorded source provenance.",
			TargetIdentity: targetIdentity,
			Reason:         "Without provenance, later review and source reconciliation become weaker.",
			Evidence:       inventoryEvidence(result, scope),
			Recommendation: "Preserve source file and record metadata when importing inventory.",
		})
	}

	if inventoryPortsOverridden(scope, inventory) {
		findings = append(findings, core.WorkflowFinding{
			Severity:       core.SeverityLow,
			Code:           "inventory-ports-overridden",
			Summary:        "Run-level ports override the imported inventory ports for this endpoint.",
			TargetIdentity: targetIdentity,
			Reason:         "The current run did not use the imported port set exactly as declared.",
			Evidence:       inventoryPortOverrideEvidence(scope, inventory),
			Recommendation: "Confirm whether the override was intentional before using this result for inventory hygiene decisions.",
		})
	}

	return findings
}

func hasWorkflowView(view *core.WorkflowContext) bool {
	return view != nil && (view.GroupBy != "" || len(view.Filters) > 0)
}

func filterRankedItems(items []rankedItem, inventoryByIdentity map[string]*core.InventoryAnnotation, workflowView *core.WorkflowContext) []rankedItem {
	if workflowView == nil || len(workflowView.Filters) == 0 {
		return append([]rankedItem(nil), items...)
	}

	filtered := make([]rankedItem, 0, len(items))
	for _, item := range items {
		if core.MatchesWorkflowFilters(inventoryByIdentity[item.TargetIdentity], workflowView.Filters) {
			filtered = append(filtered, item)
		}
	}

	return filtered
}

func filterWorkflowFindings(findings []core.WorkflowFinding, inventoryByIdentity map[string]*core.InventoryAnnotation, workflowView *core.WorkflowContext) []core.WorkflowFinding {
	if workflowView == nil || len(workflowView.Filters) == 0 {
		return append([]core.WorkflowFinding(nil), findings...)
	}

	filtered := make([]core.WorkflowFinding, 0, len(findings))
	for _, finding := range findings {
		if core.MatchesWorkflowFilters(inventoryByIdentity[finding.TargetIdentity], workflowView.Filters) {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func buildAuditGroupedSummaries(items []rankedItem, inventoryByIdentity map[string]*core.InventoryAnnotation, workflowView *core.WorkflowContext) []core.GroupedSummary {
	if workflowView == nil || workflowView.GroupBy == "" || len(items) == 0 {
		return nil
	}

	accumulators := map[string]*groupedSummaryAccumulator{}
	for _, item := range items {
		for _, key := range core.WorkflowGroupKeys(workflowView.GroupBy, inventoryByIdentity[item.TargetIdentity]) {
			accumulator := accumulators[key]
			if accumulator == nil {
				accumulator = &groupedSummaryAccumulator{
					severityBreakdown: map[string]int{},
					codeBreakdown:     map[string]int{},
				}
				accumulators[key] = accumulator
			}

			accumulator.totalItems += 1
			accumulator.severityBreakdown[string(item.Severity)] += 1
			accumulator.codeBreakdown[item.Code] += 1
		}
	}

	if len(accumulators) == 0 {
		return nil
	}

	keys := make([]string, 0, len(accumulators))
	for key := range accumulators {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	groups := make([]core.GroupedSummaryGroup, 0, len(keys))
	for _, key := range keys {
		accumulator := accumulators[key]
		groups = append(groups, core.GroupedSummaryGroup{
			Key:               key,
			TotalItems:        accumulator.totalItems,
			SeverityBreakdown: cloneStringIntMap(accumulator.severityBreakdown),
			CodeBreakdown:     cloneStringIntMap(accumulator.codeBreakdown),
		})
	}

	return []core.GroupedSummary{{
		GroupBy: workflowView.GroupBy,
		Groups:  groups,
	}}
}

func hasFindingCode(findings []core.Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}

	return false
}

type groupedSummaryAccumulator struct {
	totalItems        int
	severityBreakdown map[string]int
	codeBreakdown     map[string]int
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

func sortWorkflowFindings(findings []core.WorkflowFinding) {
	slices.SortFunc(findings, func(left core.WorkflowFinding, right core.WorkflowFinding) int {
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

func cloneStringIntMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}

	cloned := make(map[string]int, len(values))
	for key, value := range values {
		cloned[key] = value
	}

	return cloned
}

func cloneReportScope(scope *core.ReportScope) *core.ReportScope {
	if scope == nil {
		return nil
	}

	cloned := *scope
	cloned.Ports = append([]int(nil), scope.Ports...)
	return &cloned
}

func metadataScoreBonus(profile Profile, inventory *core.InventoryAnnotation) int {
	if inventory == nil {
		return 0
	}

	bonus := 0
	if isProductionEnvironment(inventory.Environment) {
		switch profile {
		case ProfileChangeRisk:
			bonus += 80
		default:
			bonus += 60
		}
	}
	if hasInventoryTag(inventory, "external") {
		switch profile {
		case ProfileChangeRisk:
			bonus += 60
		default:
			bonus += 40
		}
	}
	if hasInventoryTag(inventory, "critical") {
		switch profile {
		case ProfileChangeRisk:
			bonus += 40
		default:
			bonus += 50
		}
	}

	return bonus
}

func metadataReasonSuffix(inventory *core.InventoryAnnotation) string {
	if inventory == nil {
		return ""
	}

	parts := make([]string, 0, 3)
	if isProductionEnvironment(inventory.Environment) {
		parts = append(parts, "it is in the production environment")
	} else if environment := strings.TrimSpace(inventory.Environment); environment != "" {
		parts = append(parts, fmt.Sprintf("it is in the %s environment", environment))
	}
	if owner := strings.TrimSpace(inventory.Owner); owner != "" {
		parts = append(parts, fmt.Sprintf("it is owned by %s", owner))
	}
	if tags := displayTags(inventory.Tags); tags != "" {
		parts = append(parts, fmt.Sprintf("it is tagged %s", tags))
	}
	if len(parts) == 0 {
		return ""
	}

	return " In inventory context, " + strings.Join(parts, ", ") + "."
}

func metadataGapSeverity(inventory *core.InventoryAnnotation) core.Severity {
	if inventory == nil {
		return core.SeverityLow
	}
	if isProductionEnvironment(inventory.Environment) || hasInventoryTag(inventory, "external") || hasInventoryTag(inventory, "critical") {
		return core.SeverityMedium
	}

	return core.SeverityLow
}

func inventoryEvidence(result core.AuditResult, scope *core.ReportScope) []string {
	evidence := []string{
		"host=" + result.DiscoveredEndpoint.Host,
		fmt.Sprintf("port=%d", result.DiscoveredEndpoint.Port),
	}
	if scope != nil && scope.InventoryFile != "" {
		evidence = append(evidence, "inventory_file="+scope.InventoryFile)
	}
	return evidence
}

func inventoryPortsOverridden(scope *core.ReportScope, inventory *core.InventoryAnnotation) bool {
	if scope == nil || inventory == nil || scope.InputKind != core.ReportInputKindInventoryFile || len(scope.Ports) == 0 || len(inventory.Ports) == 0 {
		return false
	}

	if len(scope.Ports) != len(inventory.Ports) {
		return true
	}

	expected := append([]int(nil), scope.Ports...)
	actual := append([]int(nil), inventory.Ports...)
	slices.Sort(expected)
	slices.Sort(actual)
	for index := range expected {
		if expected[index] != actual[index] {
			return true
		}
	}

	return false
}

func inventoryPortOverrideEvidence(scope *core.ReportScope, inventory *core.InventoryAnnotation) []string {
	evidence := make([]string, 0, 2)
	if len(inventory.Ports) > 0 {
		evidence = append(evidence, "inventory_ports="+joinPorts(inventory.Ports))
	}
	if scope != nil && len(scope.Ports) > 0 {
		evidence = append(evidence, "effective_ports="+joinPorts(scope.Ports))
	}
	return evidence
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}

	return strings.Join(values, ",")
}

func hasInventoryTag(inventory *core.InventoryAnnotation, tag string) bool {
	for _, current := range inventory.Tags {
		if strings.EqualFold(strings.TrimSpace(current), tag) {
			return true
		}
	}

	return false
}

func displayTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}

	values := make([]string, 0, len(tags))
	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}
	if len(values) == 0 {
		return ""
	}

	return strings.Join(values, ", ")
}

func isProductionEnvironment(environment string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "prod", "production":
		return true
	default:
		return false
	}
}
