// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package diff

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/steadytao/surveyor/internal/baseline"
	"github.com/steadytao/surveyor/internal/core"
)

// BuildTLSReport assembles the canonical diff report for two compatible TLS
// inventory reports.
func BuildTLSReport(baselineReport core.Report, currentReport core.Report, generatedAt time.Time, workflowView *core.WorkflowContext) (Report, error) {
	comparison, err := baseline.ValidateCompatibility(
		tlsReportHeader(baselineReport),
		tlsReportHeader(currentReport),
	)
	if err != nil {
		return Report{}, err
	}
	if hasWorkflowView(workflowView) {
		return Report{}, fmt.Errorf("workflow grouping and filtering are supported only for audit input")
	}

	changes, changedEntities, unchangedEntities := compareTLSResults(baselineReport.Results, currentReport.Results)

	return buildReport(comparison, generatedAt, nil, changes, len(baselineReport.Results), len(currentReport.Results), changedEntities, unchangedEntities, nil), nil
}

// BuildAuditReport assembles the canonical diff report for two compatible audit
// reports.
func BuildAuditReport(baselineReport core.AuditReport, currentReport core.AuditReport, generatedAt time.Time, workflowView *core.WorkflowContext) (Report, error) {
	comparison, err := baseline.ValidateCompatibility(
		auditReportHeader(baselineReport),
		auditReportHeader(currentReport),
	)
	if err != nil {
		return Report{}, err
	}

	baselineByID := auditResultsByIdentity(baselineReport.Results)
	currentByID := auditResultsByIdentity(currentReport.Results)

	changes, changedEntities, unchangedEntities := compareAuditResults(baselineReport.Results, currentReport.Results)
	filteredChanges := changes
	totalBaseline := len(baselineReport.Results)
	totalCurrent := len(currentReport.Results)
	if workflowView != nil && len(workflowView.Filters) > 0 {
		includedKeys := filterAuditIdentityKeys(baselineByID, currentByID, workflowView)
		filteredChanges = filterChangesByIdentity(changes, includedKeys)
		totalBaseline, totalCurrent, changedEntities, unchangedEntities = auditViewCounts(baselineByID, currentByID, includedKeys, filteredChanges)
	}
	groupedSummaries := buildAuditGroupedSummaries(filteredChanges, baselineByID, currentByID, workflowView)

	return buildReport(comparison, generatedAt, workflowView, filteredChanges, totalBaseline, totalCurrent, changedEntities, unchangedEntities, groupedSummaries), nil
}

func buildReport(comparison baseline.Comparison, generatedAt time.Time, workflowView *core.WorkflowContext, changes []Change, totalBaseline int, totalCurrent int, changedEntities int, unchangedEntities int, groupedSummaries []core.GroupedSummary) Report {
	report := Report{
		ReportMetadata: core.NewReportMetadata(
			core.ReportKindDiff,
			comparison.Current.ScopeKind,
			describeDiffScope(comparison),
		),
		GeneratedAt:              generatedAt.UTC(),
		BaselineReportKind:       comparison.Baseline.ReportKind,
		CurrentReportKind:        comparison.Current.ReportKind,
		BaselineGeneratedAt:      comparison.Baseline.GeneratedAt.UTC(),
		CurrentGeneratedAt:       comparison.Current.GeneratedAt.UTC(),
		BaselineScopeDescription: comparison.Baseline.ScopeDescription,
		CurrentScopeDescription:  comparison.Current.ScopeDescription,
		BaselineScope:            cloneReportScope(comparison.Baseline.Scope),
		CurrentScope:             cloneReportScope(comparison.Current.Scope),
		WorkflowView:             core.CloneWorkflowContext(workflowView),
		Summary: buildSummary(
			totalBaseline,
			totalCurrent,
			changes,
			changedEntities,
			unchangedEntities,
			comparison.ScopeChanged,
		),
		GroupedSummaries: core.CloneGroupedSummaries(groupedSummaries),
		Changes:          cloneChanges(changes),
	}

	return report
}

func buildSummary(totalBaseline int, totalCurrent int, changes []Change, changedEntities int, unchangedEntities int, scopeChanged bool) Summary {
	summary := Summary{
		TotalBaselineEntities: totalBaseline,
		TotalCurrentEntities:  totalCurrent,
		ChangedEntities:       changedEntities,
		UnchangedEntities:     unchangedEntities,
		ScopeChanged:          scopeChanged,
		ChangeBreakdown:       map[string]int{},
		DirectionBreakdown:    map[string]int{},
	}

	for _, change := range changes {
		switch change.Code {
		case "new_endpoint":
			summary.AddedEntities += 1
		case "removed_endpoint":
			summary.RemovedEntities += 1
		}

		summary.ChangeBreakdown[change.Code] += 1
		summary.DirectionBreakdown[string(change.Direction)] += 1
	}

	if len(summary.ChangeBreakdown) == 0 {
		summary.ChangeBreakdown = nil
	}
	if len(summary.DirectionBreakdown) == 0 {
		summary.DirectionBreakdown = nil
	}

	return summary
}

func compareTLSResults(baselineResults []core.TargetResult, currentResults []core.TargetResult) ([]Change, int, int) {
	baselineByID := make(map[string]core.TargetResult, len(baselineResults))
	currentByID := make(map[string]core.TargetResult, len(currentResults))
	keys := make([]string, 0, len(baselineResults)+len(currentResults))
	seenKeys := map[string]struct{}{}

	for _, result := range baselineResults {
		key := baseline.TargetResultIdentityKey(result)
		baselineByID[key] = core.CloneTargetResult(result)
		if _, ok := seenKeys[key]; !ok {
			seenKeys[key] = struct{}{}
			keys = append(keys, key)
		}
	}

	for _, result := range currentResults {
		key := baseline.TargetResultIdentityKey(result)
		currentByID[key] = core.CloneTargetResult(result)
		if _, ok := seenKeys[key]; !ok {
			seenKeys[key] = struct{}{}
			keys = append(keys, key)
		}
	}

	sort.Strings(keys)

	changes := []Change{}
	changedEntities := 0
	unchangedEntities := 0

	for _, key := range keys {
		baselineResult, baselineOK := baselineByID[key]
		currentResult, currentOK := currentByID[key]

		switch {
		case !baselineOK:
			changes = append(changes, Change{
				IdentityKey:  key,
				Code:         "new_endpoint",
				Direction:    ChangeDirectionInformational,
				Severity:     core.SeverityInfo,
				Summary:      "A new TLS target appeared in the current report.",
				CurrentValue: core.CloneTargetResult(currentResult),
				Evidence: []string{
					"host=" + currentResult.Host,
					"port=" + strconv.Itoa(currentResult.Port),
				},
			})
			continue
		case !currentOK:
			changes = append(changes, Change{
				IdentityKey:   key,
				Code:          "removed_endpoint",
				Direction:     ChangeDirectionInformational,
				Severity:      core.SeverityInfo,
				Summary:       "A TLS target from the baseline report is missing in the current report.",
				BaselineValue: core.CloneTargetResult(baselineResult),
				Evidence: []string{
					"host=" + baselineResult.Host,
					"port=" + strconv.Itoa(baselineResult.Port),
				},
			})
			continue
		}

		entityChanges := []Change{}
		entityChanges = append(entityChanges, compareTLSReachability(key, baselineResult, currentResult)...)
		entityChanges = append(entityChanges, compareTLSStringField(key, "tls_version_changed", "The negotiated TLS version changed.", baselineResult.TLSVersion, currentResult.TLSVersion, tlsVersionDirection)...)
		entityChanges = append(entityChanges, compareTLSStringField(key, "cipher_suite_changed", "The negotiated cipher suite changed.", baselineResult.CipherSuite, currentResult.CipherSuite, unchangedDirection)...)
		entityChanges = append(entityChanges, compareTLSStringField(key, "classification_changed", "The TLS classification changed.", baselineResult.Classification, currentResult.Classification, classificationDirection)...)
		entityChanges = append(entityChanges, compareTLSStringField(key, "leaf_key_algorithm_changed", "The leaf certificate key algorithm changed.", baselineResult.LeafKeyAlgorithm, currentResult.LeafKeyAlgorithm, unchangedDirection)...)
		entityChanges = append(entityChanges, compareTLSStringField(key, "leaf_signature_algorithm_changed", "The leaf certificate signature algorithm changed.", baselineResult.LeafSignatureAlgorithm, currentResult.LeafSignatureAlgorithm, unchangedDirection)...)
		entityChanges = append(entityChanges, compareTLSCertificateChain(key, baselineResult.CertificateChain, currentResult.CertificateChain)...)
		entityChanges = append(entityChanges, compareTLSFindings(key, baselineResult.Findings, currentResult.Findings)...)
		entityChanges = append(entityChanges, compareTLSMessages(key, "warnings_changed", "The TLS warnings changed.", baselineResult.Warnings, currentResult.Warnings, warningDirection)...)
		entityChanges = append(entityChanges, compareTLSMessages(key, "errors_changed", "The TLS errors changed.", baselineResult.Errors, currentResult.Errors, errorDirection)...)

		if len(entityChanges) == 0 {
			unchangedEntities += 1
			continue
		}

		changedEntities += 1
		changes = append(changes, entityChanges...)
	}

	sortChanges(changes)
	return changes, changedEntities, unchangedEntities
}

func compareAuditResults(baselineResults []core.AuditResult, currentResults []core.AuditResult) ([]Change, int, int) {
	baselineByID := make(map[string]core.AuditResult, len(baselineResults))
	currentByID := make(map[string]core.AuditResult, len(currentResults))
	keys := make([]string, 0, len(baselineResults)+len(currentResults))
	seenKeys := map[string]struct{}{}

	for _, result := range baselineResults {
		key := baseline.AuditResultIdentityKey(result)
		baselineByID[key] = core.CloneAuditResult(result)
		if _, ok := seenKeys[key]; !ok {
			seenKeys[key] = struct{}{}
			keys = append(keys, key)
		}
	}

	for _, result := range currentResults {
		key := baseline.AuditResultIdentityKey(result)
		currentByID[key] = core.CloneAuditResult(result)
		if _, ok := seenKeys[key]; !ok {
			seenKeys[key] = struct{}{}
			keys = append(keys, key)
		}
	}

	sort.Strings(keys)

	changes := []Change{}
	changedEntities := 0
	unchangedEntities := 0

	for _, key := range keys {
		baselineResult, baselineOK := baselineByID[key]
		currentResult, currentOK := currentByID[key]

		switch {
		case !baselineOK:
			changes = append(changes, Change{
				IdentityKey:  key,
				Code:         "new_endpoint",
				Direction:    ChangeDirectionInformational,
				Severity:     core.SeverityInfo,
				Summary:      "A new audit endpoint appeared in the current report.",
				CurrentValue: core.CloneAuditResult(currentResult),
				Evidence:     auditIdentityEvidence(currentResult.DiscoveredEndpoint),
			})
			continue
		case !currentOK:
			changes = append(changes, Change{
				IdentityKey:   key,
				Code:          "removed_endpoint",
				Direction:     ChangeDirectionInformational,
				Severity:      core.SeverityInfo,
				Summary:       "An audit endpoint from the baseline report is missing in the current report.",
				BaselineValue: core.CloneAuditResult(baselineResult),
				Evidence:      auditIdentityEvidence(baselineResult.DiscoveredEndpoint),
			})
			continue
		}

		entityChanges := []Change{}
		entityChanges = append(entityChanges, compareAuditReachability(key, baselineResult.DiscoveredEndpoint, currentResult.DiscoveredEndpoint)...)
		entityChanges = append(entityChanges, compareAuditHints(key, baselineResult.DiscoveredEndpoint.Hints, currentResult.DiscoveredEndpoint.Hints)...)
		entityChanges = append(entityChanges, compareAuditSelection(key, baselineResult.Selection, currentResult.Selection)...)
		entityChanges = append(entityChanges, compareAuditIssues(key, "warnings_changed", "Audit warnings changed.", extractWarnings(baselineResult), extractWarnings(currentResult), warningDirection)...)
		entityChanges = append(entityChanges, compareAuditIssues(key, "errors_changed", "Audit errors changed.", extractErrors(baselineResult), extractErrors(currentResult), errorDirection)...)
		entityChanges = append(entityChanges, compareAuditTLSDetails(key, baselineResult.TLSResult, currentResult.TLSResult)...)

		if len(entityChanges) == 0 {
			unchangedEntities += 1
			continue
		}

		changedEntities += 1
		changes = append(changes, entityChanges...)
	}

	sortChanges(changes)
	return changes, changedEntities, unchangedEntities
}

func hasWorkflowView(view *core.WorkflowContext) bool {
	return view != nil && (view.GroupBy != "" || len(view.Filters) > 0)
}

func auditResultsByIdentity(results []core.AuditResult) map[string]core.AuditResult {
	index := make(map[string]core.AuditResult, len(results))
	for _, result := range results {
		index[baseline.AuditResultIdentityKey(result)] = core.CloneAuditResult(result)
	}

	return index
}

func filterAuditIdentityKeys(baselineByID map[string]core.AuditResult, currentByID map[string]core.AuditResult, workflowView *core.WorkflowContext) map[string]struct{} {
	keys := make(map[string]struct{}, len(baselineByID)+len(currentByID))
	for identityKey, result := range baselineByID {
		if _, ok := currentByID[identityKey]; ok {
			continue
		}
		if auditIdentityMatchesWorkflowView(nil, &result, workflowView) {
			keys[identityKey] = struct{}{}
		}
	}
	for identityKey, result := range currentByID {
		if baselineResult, ok := baselineByID[identityKey]; ok {
			if auditIdentityMatchesWorkflowView(&result, &baselineResult, workflowView) {
				keys[identityKey] = struct{}{}
			}
			continue
		}
		if auditIdentityMatchesWorkflowView(&result, nil, workflowView) {
			keys[identityKey] = struct{}{}
		}
	}

	return keys
}

func auditIdentityMatchesWorkflowView(currentResult *core.AuditResult, baselineResult *core.AuditResult, workflowView *core.WorkflowContext) bool {
	if workflowView == nil || len(workflowView.Filters) == 0 {
		return true
	}

	context := selectAuditGroupingContext(currentResult, baselineResult)
	return core.MatchesWorkflowFilters(context.currentInventory, workflowView.Filters) ||
		core.MatchesWorkflowFilters(context.baselineInventory, workflowView.Filters)
}

func filterChangesByIdentity(changes []Change, includedKeys map[string]struct{}) []Change {
	filtered := make([]Change, 0, len(changes))
	for _, change := range changes {
		if _, ok := includedKeys[change.IdentityKey]; ok {
			filtered = append(filtered, change)
		}
	}

	return filtered
}

func auditViewCounts(baselineByID map[string]core.AuditResult, currentByID map[string]core.AuditResult, includedKeys map[string]struct{}, filteredChanges []Change) (int, int, int, int) {
	changedKeys := map[string]struct{}{}
	for _, change := range filteredChanges {
		changedKeys[change.IdentityKey] = struct{}{}
	}

	totalBaseline := 0
	totalCurrent := 0
	changedEntities := 0
	unchangedEntities := 0
	for identityKey := range includedKeys {
		_, baselineOK := baselineByID[identityKey]
		_, currentOK := currentByID[identityKey]
		if baselineOK {
			totalBaseline += 1
		}
		if currentOK {
			totalCurrent += 1
		}
		if _, changed := changedKeys[identityKey]; changed {
			changedEntities += 1
			continue
		}
		unchangedEntities += 1
	}

	return totalBaseline, totalCurrent, changedEntities, unchangedEntities
}

func compareTLSReachability(key string, baselineResult core.TargetResult, currentResult core.TargetResult) []Change {
	if baselineResult.Reachable == currentResult.Reachable {
		return nil
	}

	direction := ChangeDirectionChanged
	severity := core.SeverityLow
	if !baselineResult.Reachable && currentResult.Reachable {
		direction = ChangeDirectionImproved
	} else if baselineResult.Reachable && !currentResult.Reachable {
		direction = ChangeDirectionWorsened
		severity = core.SeverityMedium
	}

	return []Change{{
		IdentityKey:   key,
		Code:          "reachability_changed",
		Direction:     direction,
		Severity:      severity,
		Summary:       "The TLS target reachability changed.",
		BaselineValue: baselineResult.Reachable,
		CurrentValue:  currentResult.Reachable,
	}}
}

type stringDirectionFunc func(string, string) (ChangeDirection, core.Severity)

func compareTLSStringField(key string, code string, summary string, baselineValue string, currentValue string, directionFunc stringDirectionFunc) []Change {
	if baselineValue == currentValue {
		return nil
	}

	direction, severity := directionFunc(baselineValue, currentValue)
	return []Change{{
		IdentityKey:   key,
		Code:          code,
		Direction:     direction,
		Severity:      severity,
		Summary:       summary,
		BaselineValue: baselineValue,
		CurrentValue:  currentValue,
	}}
}

func compareTLSCertificateChain(key string, baselineChain []core.CertificateRef, currentChain []core.CertificateRef) []Change {
	if sameCertificateChain(baselineChain, currentChain) {
		return nil
	}

	return []Change{{
		IdentityKey:   key,
		Code:          "certificate_chain_changed",
		Direction:     ChangeDirectionChanged,
		Severity:      core.SeverityLow,
		Summary:       "The presented certificate chain changed.",
		BaselineValue: cloneCertificateRefs(baselineChain),
		CurrentValue:  cloneCertificateRefs(currentChain),
	}}
}

func compareTLSFindings(key string, baselineFindings []core.Finding, currentFindings []core.Finding) []Change {
	if sameFindings(baselineFindings, currentFindings) {
		return nil
	}

	direction, severity := findingsDirection(baselineFindings, currentFindings)
	return []Change{{
		IdentityKey:   key,
		Code:          "findings_changed",
		Direction:     direction,
		Severity:      severity,
		Summary:       "The TLS findings changed.",
		BaselineValue: cloneFindings(baselineFindings),
		CurrentValue:  cloneFindings(currentFindings),
	}}
}

func compareTLSMessages(key string, code string, summary string, baselineMessages []string, currentMessages []string, directionFunc func([]string, []string) (ChangeDirection, core.Severity)) []Change {
	if sameStrings(baselineMessages, currentMessages) {
		return nil
	}

	direction, severity := directionFunc(baselineMessages, currentMessages)
	return []Change{{
		IdentityKey:   key,
		Code:          code,
		Direction:     direction,
		Severity:      severity,
		Summary:       summary,
		BaselineValue: cloneStrings(baselineMessages),
		CurrentValue:  cloneStrings(currentMessages),
	}}
}

func compareAuditReachability(key string, baselineEndpoint core.DiscoveredEndpoint, currentEndpoint core.DiscoveredEndpoint) []Change {
	if baselineEndpoint.ScopeKind != core.EndpointScopeKindRemote || currentEndpoint.ScopeKind != core.EndpointScopeKindRemote {
		return nil
	}
	if baselineEndpoint.State == currentEndpoint.State {
		return nil
	}

	baselineResponsive := baselineEndpoint.State == "responsive"
	currentResponsive := currentEndpoint.State == "responsive"
	direction := ChangeDirectionChanged
	severity := core.SeverityLow
	if !baselineResponsive && currentResponsive {
		direction = ChangeDirectionImproved
	} else if baselineResponsive && !currentResponsive {
		direction = ChangeDirectionWorsened
		severity = core.SeverityMedium
	}

	return []Change{{
		IdentityKey:   key,
		Code:          "reachability_changed",
		Direction:     direction,
		Severity:      severity,
		Summary:       "The remote endpoint responsiveness changed.",
		BaselineValue: baselineEndpoint.State,
		CurrentValue:  currentEndpoint.State,
	}}
}

func compareAuditHints(key string, baselineHints []core.DiscoveryHint, currentHints []core.DiscoveryHint) []Change {
	if sameHints(baselineHints, currentHints) {
		return nil
	}

	return []Change{{
		IdentityKey:   key,
		Code:          "hint_changed",
		Direction:     ChangeDirectionChanged,
		Severity:      core.SeverityInfo,
		Summary:       "The discovery hints changed.",
		BaselineValue: cloneHints(baselineHints),
		CurrentValue:  cloneHints(currentHints),
	}}
}

func compareAuditSelection(key string, baselineSelection core.AuditSelection, currentSelection core.AuditSelection) []Change {
	if baselineSelection == currentSelection {
		return nil
	}

	return []Change{{
		IdentityKey:   key,
		Code:          "selection_changed",
		Direction:     ChangeDirectionChanged,
		Severity:      core.SeverityLow,
		Summary:       "The audit selection decision changed.",
		BaselineValue: baselineSelection,
		CurrentValue:  currentSelection,
	}}
}

func compareAuditIssues(key string, code string, summary string, baselineValues IssueValues, currentValues IssueValues, directionFunc func([]string, []string) (ChangeDirection, core.Severity)) []Change {
	if sameIssueValues(baselineValues, currentValues) {
		return nil
	}

	direction, severity := directionFunc(flattenIssueValues(baselineValues), flattenIssueValues(currentValues))
	return []Change{{
		IdentityKey:   key,
		Code:          code,
		Direction:     direction,
		Severity:      severity,
		Summary:       summary,
		BaselineValue: cloneIssueValues(baselineValues),
		CurrentValue:  cloneIssueValues(currentValues),
	}}
}

func compareAuditTLSDetails(key string, baselineResult *core.TargetResult, currentResult *core.TargetResult) []Change {
	if baselineResult == nil || currentResult == nil {
		return nil
	}

	changes := []Change{}
	changes = append(changes, compareTLSReachability(key, *baselineResult, *currentResult)...)
	changes = append(changes, compareTLSStringField(key, "tls_version_changed", "The negotiated TLS version changed.", baselineResult.TLSVersion, currentResult.TLSVersion, tlsVersionDirection)...)
	changes = append(changes, compareTLSStringField(key, "cipher_suite_changed", "The negotiated cipher suite changed.", baselineResult.CipherSuite, currentResult.CipherSuite, unchangedDirection)...)
	changes = append(changes, compareTLSStringField(key, "classification_changed", "The verified TLS classification changed.", baselineResult.Classification, currentResult.Classification, classificationDirection)...)
	changes = append(changes, compareTLSStringField(key, "leaf_key_algorithm_changed", "The leaf certificate key algorithm changed.", baselineResult.LeafKeyAlgorithm, currentResult.LeafKeyAlgorithm, unchangedDirection)...)
	changes = append(changes, compareTLSStringField(key, "leaf_signature_algorithm_changed", "The leaf certificate signature algorithm changed.", baselineResult.LeafSignatureAlgorithm, currentResult.LeafSignatureAlgorithm, unchangedDirection)...)
	changes = append(changes, compareTLSCertificateChain(key, baselineResult.CertificateChain, currentResult.CertificateChain)...)
	changes = append(changes, compareTLSFindings(key, baselineResult.Findings, currentResult.Findings)...)
	return changes
}

func sameCertificateChain(left []core.CertificateRef, right []core.CertificateRef) bool {
	return slices.EqualFunc(normalizeCertificateChain(left), normalizeCertificateChain(right), func(left normalizedCertificateRef, right normalizedCertificateRef) bool {
		return left == right
	})
}

type normalizedCertificateRef struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	DNSNames           string
	PublicKeyAlgorithm string
	PublicKeySize      int
	SignatureAlgorithm string
	IsCA               bool
}

func normalizeCertificateChain(chain []core.CertificateRef) []normalizedCertificateRef {
	if len(chain) == 0 {
		return nil
	}

	normalized := make([]normalizedCertificateRef, 0, len(chain))
	for _, ref := range chain {
		dnsNames := append([]string(nil), ref.DNSNames...)
		sort.Strings(dnsNames)
		normalized = append(normalized, normalizedCertificateRef{
			Subject:            ref.Subject,
			Issuer:             ref.Issuer,
			SerialNumber:       ref.SerialNumber,
			NotBefore:          ref.NotBefore,
			NotAfter:           ref.NotAfter,
			DNSNames:           strings.Join(dnsNames, "\x00"),
			PublicKeyAlgorithm: ref.PublicKeyAlgorithm,
			PublicKeySize:      ref.PublicKeySize,
			SignatureAlgorithm: ref.SignatureAlgorithm,
			IsCA:               ref.IsCA,
		})
	}

	return normalized
}

func sameFindings(left []core.Finding, right []core.Finding) bool {
	return slices.Equal(normalizeFindings(left), normalizeFindings(right))
}

func normalizeFindings(findings []core.Finding) []string {
	if len(findings) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(findings))
	for _, finding := range findings {
		evidence := append([]string(nil), finding.Evidence...)
		sort.Strings(evidence)
		normalized = append(normalized, strings.Join([]string{
			finding.Code,
			string(finding.Severity),
			finding.Summary,
			finding.Recommendation,
			strings.Join(evidence, "\x00"),
		}, "|"))
	}

	sort.Strings(normalized)
	return normalized
}

func sameHints(left []core.DiscoveryHint, right []core.DiscoveryHint) bool {
	return slices.Equal(normalizeHints(left), normalizeHints(right))
}

func normalizeHints(hints []core.DiscoveryHint) []string {
	if len(hints) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(hints))
	for _, hint := range hints {
		evidence := append([]string(nil), hint.Evidence...)
		sort.Strings(evidence)
		normalized = append(normalized, strings.Join([]string{
			hint.Protocol,
			hint.Confidence,
			strings.Join(evidence, "\x00"),
		}, "|"))
	}

	sort.Strings(normalized)
	return normalized
}

func sameStrings(left []string, right []string) bool {
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func tlsVersionDirection(baselineValue string, currentValue string) (ChangeDirection, core.Severity) {
	baselineRank, baselineOK := tlsVersionRank(baselineValue)
	currentRank, currentOK := tlsVersionRank(currentValue)
	if baselineOK && currentOK {
		switch {
		case currentRank > baselineRank:
			return ChangeDirectionImproved, core.SeverityLow
		case currentRank < baselineRank:
			return ChangeDirectionWorsened, core.SeverityMedium
		}
	}

	return ChangeDirectionChanged, core.SeverityLow
}

func classificationDirection(baselineValue string, currentValue string) (ChangeDirection, core.Severity) {
	baselineRank, baselineOK := classificationRank(baselineValue)
	currentRank, currentOK := classificationRank(currentValue)
	if baselineOK && currentOK {
		switch {
		case currentRank > baselineRank:
			return ChangeDirectionImproved, core.SeverityLow
		case currentRank < baselineRank:
			return ChangeDirectionWorsened, core.SeverityMedium
		}
	}

	return ChangeDirectionChanged, core.SeverityLow
}

func unchangedDirection(_, _ string) (ChangeDirection, core.Severity) {
	return ChangeDirectionChanged, core.SeverityLow
}

func warningDirection(baselineValues []string, currentValues []string) (ChangeDirection, core.Severity) {
	return messageDirection(baselineValues, currentValues, core.SeverityLow)
}

func errorDirection(baselineValues []string, currentValues []string) (ChangeDirection, core.Severity) {
	return messageDirection(baselineValues, currentValues, core.SeverityMedium)
}

func messageDirection(baselineValues []string, currentValues []string, worsenedSeverity core.Severity) (ChangeDirection, core.Severity) {
	switch {
	case len(currentValues) > len(baselineValues):
		return ChangeDirectionWorsened, worsenedSeverity
	case len(currentValues) < len(baselineValues):
		return ChangeDirectionImproved, core.SeverityLow
	default:
		return ChangeDirectionChanged, core.SeverityLow
	}
}

func findingsDirection(baselineValues []core.Finding, currentValues []core.Finding) (ChangeDirection, core.Severity) {
	baselineSeverity := highestFindingSeverity(baselineValues)
	currentSeverity := highestFindingSeverity(currentValues)

	switch {
	case currentSeverity > baselineSeverity:
		return ChangeDirectionWorsened, currentSeverity
	case currentSeverity < baselineSeverity:
		return ChangeDirectionImproved, core.SeverityLow
	default:
		return ChangeDirectionChanged, currentSeverity
	}
}

func highestFindingSeverity(findings []core.Finding) core.Severity {
	highestRank := -1
	highestSeverity := core.SeverityInfo
	for _, finding := range findings {
		rank := severityRank(finding.Severity)
		if rank > highestRank {
			highestRank = rank
			highestSeverity = finding.Severity
		}
	}

	return highestSeverity
}

func tlsVersionRank(version string) (int, bool) {
	switch version {
	case "SSL 3.0":
		return 0, true
	case "TLS 1.0":
		return 1, true
	case "TLS 1.1":
		return 2, true
	case "TLS 1.2":
		return 3, true
	case "TLS 1.3":
		return 4, true
	default:
		return 0, false
	}
}

func classificationRank(classification string) (int, bool) {
	switch classification {
	case "legacy_tls_exposure":
		return 0, true
	case "manual_review_required":
		return 1, true
	case "classical_certificates":
		return 2, true
	case "modern_tls_classical_identity":
		return 2, true
	case "unreachable":
		return 1, true
	default:
		return 0, false
	}
}

func severityRank(severity core.Severity) int {
	switch severity {
	case core.SeverityInfo:
		return 0
	case core.SeverityLow:
		return 1
	case core.SeverityMedium:
		return 2
	case core.SeverityHigh:
		return 3
	case core.SeverityCritical:
		return 4
	default:
		return -1
	}
}

func auditIdentityEvidence(endpoint core.DiscoveredEndpoint) []string {
	return []string{
		"scope_kind=" + string(endpoint.ScopeKind),
		"host=" + endpoint.Host,
		"port=" + strconv.Itoa(endpoint.Port),
		"transport=" + endpoint.Transport,
	}
}

func extractWarnings(result core.AuditResult) IssueValues {
	values := IssueValues{
		DiscoveredEndpoint: cloneStrings(result.DiscoveredEndpoint.Warnings),
	}
	if result.TLSResult != nil {
		values.TLSResult = cloneStrings(result.TLSResult.Warnings)
	}
	return values
}

func extractErrors(result core.AuditResult) IssueValues {
	values := IssueValues{
		DiscoveredEndpoint: cloneStrings(result.DiscoveredEndpoint.Errors),
	}
	if result.TLSResult != nil {
		values.TLSResult = cloneStrings(result.TLSResult.Errors)
	}
	return values
}

func sameIssueValues(left IssueValues, right IssueValues) bool {
	return sameStrings(left.DiscoveredEndpoint, right.DiscoveredEndpoint) &&
		sameStrings(left.TLSResult, right.TLSResult)
}

func flattenIssueValues(values IssueValues) []string {
	flattened := append([]string(nil), values.DiscoveredEndpoint...)
	flattened = append(flattened, values.TLSResult...)
	return flattened
}

func cloneIssueValues(values IssueValues) IssueValues {
	return IssueValues{
		DiscoveredEndpoint: cloneStrings(values.DiscoveredEndpoint),
		TLSResult:          cloneStrings(values.TLSResult),
	}
}

func describeDiffScope(comparison baseline.Comparison) string {
	return "diff of " + string(comparison.Current.ReportKind) + " reports"
}

type auditGroupingDimensions struct {
	owner       bool
	environment bool
	source      bool
}

type auditGroupingContext struct {
	currentInventory  *core.InventoryAnnotation
	baselineInventory *core.InventoryAnnotation
}

type groupedSummaryAccumulator struct {
	totalItems         int
	severityBreakdown  map[string]int
	directionBreakdown map[string]int
	changeBreakdown    map[string]int
}

func buildAuditGroupedSummaries(changes []Change, baselineByID map[string]core.AuditResult, currentByID map[string]core.AuditResult, workflowView *core.WorkflowContext) []core.GroupedSummary {
	if len(changes) == 0 {
		return nil
	}

	dimensions := detectAuditGroupingDimensions(baselineByID, currentByID)
	if !dimensions.owner && !dimensions.environment && !dimensions.source {
		return nil
	}

	var summaries []core.GroupedSummary
	groupBys := requestedAuditGroupBys(workflowView, dimensions)
	for _, groupBy := range groupBys {
		summary := buildGroupedSummaryForAuditDimension(groupBy, changes, baselineByID, currentByID, dimensions)
		if len(summary.Groups) == 0 {
			continue
		}
		summaries = append(summaries, summary)
	}

	return summaries
}

func detectAuditGroupingDimensions(baselineByID map[string]core.AuditResult, currentByID map[string]core.AuditResult) auditGroupingDimensions {
	var dimensions auditGroupingDimensions

	for _, result := range baselineByID {
		updateAuditGroupingDimensions(&dimensions, result.DiscoveredEndpoint.Inventory)
	}
	for _, result := range currentByID {
		updateAuditGroupingDimensions(&dimensions, result.DiscoveredEndpoint.Inventory)
	}

	return dimensions
}

func updateAuditGroupingDimensions(dimensions *auditGroupingDimensions, inventory *core.InventoryAnnotation) {
	if inventory == nil {
		return
	}
	if strings.TrimSpace(inventory.Owner) != "" {
		dimensions.owner = true
	}
	if strings.TrimSpace(inventory.Environment) != "" {
		dimensions.environment = true
	}
	if len(inventory.Provenance) > 0 {
		dimensions.source = true
	}
}

func requestedAuditGroupBys(workflowView *core.WorkflowContext, dimensions auditGroupingDimensions) []core.WorkflowGroupBy {
	if workflowView != nil && workflowView.GroupBy != "" {
		switch workflowView.GroupBy {
		case core.WorkflowGroupByOwner:
			if dimensions.owner {
				return []core.WorkflowGroupBy{core.WorkflowGroupByOwner}
			}
		case core.WorkflowGroupByEnvironment:
			if dimensions.environment {
				return []core.WorkflowGroupBy{core.WorkflowGroupByEnvironment}
			}
		case core.WorkflowGroupBySource:
			if dimensions.source {
				return []core.WorkflowGroupBy{core.WorkflowGroupBySource}
			}
		default:
			return nil
		}

		return nil
	}

	groupBys := make([]core.WorkflowGroupBy, 0, 3)
	if dimensions.owner {
		groupBys = append(groupBys, core.WorkflowGroupByOwner)
	}
	if dimensions.environment {
		groupBys = append(groupBys, core.WorkflowGroupByEnvironment)
	}
	if dimensions.source {
		groupBys = append(groupBys, core.WorkflowGroupBySource)
	}

	return groupBys
}

func buildGroupedSummaryForAuditDimension(groupBy core.WorkflowGroupBy, changes []Change, baselineByID map[string]core.AuditResult, currentByID map[string]core.AuditResult, dimensions auditGroupingDimensions) core.GroupedSummary {
	accumulators := map[string]*groupedSummaryAccumulator{}

	for _, change := range changes {
		context := selectAuditGroupingContext(auditResultForIdentity(change.IdentityKey, currentByID), auditResultForIdentity(change.IdentityKey, baselineByID))
		keys := groupKeysForAuditDimension(groupBy, context, dimensions)
		for _, key := range keys {
			accumulator := accumulators[key]
			if accumulator == nil {
				accumulator = &groupedSummaryAccumulator{
					severityBreakdown:  map[string]int{},
					directionBreakdown: map[string]int{},
					changeBreakdown:    map[string]int{},
				}
				accumulators[key] = accumulator
			}

			accumulator.totalItems += 1
			accumulator.severityBreakdown[string(change.Severity)] += 1
			accumulator.directionBreakdown[string(change.Direction)] += 1
			accumulator.changeBreakdown[change.Code] += 1
		}
	}

	if len(accumulators) == 0 {
		return core.GroupedSummary{GroupBy: groupBy}
	}

	keys := make([]string, 0, len(accumulators))
	for key := range accumulators {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	groups := make([]core.GroupedSummaryGroup, 0, len(keys))
	for _, key := range keys {
		accumulator := accumulators[key]
		groups = append(groups, core.GroupedSummaryGroup{
			Key:                key,
			TotalItems:         accumulator.totalItems,
			SeverityBreakdown:  cloneStringIntMap(accumulator.severityBreakdown),
			DirectionBreakdown: cloneStringIntMap(accumulator.directionBreakdown),
			ChangeBreakdown:    cloneStringIntMap(accumulator.changeBreakdown),
		})
	}

	return core.GroupedSummary{
		GroupBy: groupBy,
		Groups:  groups,
	}
}

func auditResultForIdentity(identityKey string, resultsByID map[string]core.AuditResult) *core.AuditResult {
	result, ok := resultsByID[identityKey]
	if !ok {
		return nil
	}

	return &result
}

func selectAuditGroupingContext(currentResult *core.AuditResult, baselineResult *core.AuditResult) auditGroupingContext {
	context := auditGroupingContext{}
	if currentResult != nil {
		context.currentInventory = currentResult.DiscoveredEndpoint.Inventory
	}
	if baselineResult != nil {
		context.baselineInventory = baselineResult.DiscoveredEndpoint.Inventory
	}

	return context
}

func groupKeysForAuditDimension(groupBy core.WorkflowGroupBy, context auditGroupingContext, dimensions auditGroupingDimensions) []string {
	keys := []string{}
	seen := map[string]struct{}{}
	appendKeys := func(values []string) {
		for _, value := range values {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			keys = append(keys, value)
		}
	}

	switch groupBy {
	case core.WorkflowGroupByOwner:
		if !dimensions.owner {
			return nil
		}
		appendKeys(core.WorkflowGroupKeys(core.WorkflowGroupByOwner, context.baselineInventory))
		appendKeys(core.WorkflowGroupKeys(core.WorkflowGroupByOwner, context.currentInventory))
	case core.WorkflowGroupByEnvironment:
		if !dimensions.environment {
			return nil
		}
		appendKeys(core.WorkflowGroupKeys(core.WorkflowGroupByEnvironment, context.baselineInventory))
		appendKeys(core.WorkflowGroupKeys(core.WorkflowGroupByEnvironment, context.currentInventory))
	case core.WorkflowGroupBySource:
		if !dimensions.source {
			return nil
		}
		appendKeys(core.WorkflowGroupKeys(core.WorkflowGroupBySource, context.baselineInventory))
		appendKeys(core.WorkflowGroupKeys(core.WorkflowGroupBySource, context.currentInventory))
	default:
		return nil
	}

	if len(keys) == 0 {
		return nil
	}

	sort.Strings(keys)
	return keys
}

func tlsReportHeader(report core.Report) baseline.ReportHeader {
	return baseline.ReportHeader{
		ReportMetadata: report.ReportMetadata,
		GeneratedAt:    report.GeneratedAt,
		Scope:          cloneReportScope(report.Scope),
	}
}

func auditReportHeader(report core.AuditReport) baseline.ReportHeader {
	return baseline.ReportHeader{
		ReportMetadata: report.ReportMetadata,
		GeneratedAt:    report.GeneratedAt,
		Scope:          cloneReportScope(report.Scope),
	}
}

func cloneReportScope(scope *core.ReportScope) *core.ReportScope {
	if scope == nil {
		return nil
	}

	cloned := *scope
	cloned.Ports = append([]int(nil), scope.Ports...)
	return &cloned
}

func cloneChanges(changes []Change) []Change {
	if len(changes) == 0 {
		return nil
	}

	cloned := make([]Change, 0, len(changes))
	for _, change := range changes {
		changeClone := change
		changeClone.Evidence = cloneStrings(change.Evidence)
		cloned = append(cloned, changeClone)
	}
	return cloned
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneCertificateRefs(values []core.CertificateRef) []core.CertificateRef {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]core.CertificateRef, 0, len(values))
	for _, value := range values {
		valueClone := value
		valueClone.DNSNames = cloneStrings(value.DNSNames)
		cloned = append(cloned, valueClone)
	}
	return cloned
}

func cloneFindings(values []core.Finding) []core.Finding {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]core.Finding, 0, len(values))
	for _, value := range values {
		valueClone := value
		valueClone.Evidence = cloneStrings(value.Evidence)
		cloned = append(cloned, valueClone)
	}
	return cloned
}

func cloneHints(values []core.DiscoveryHint) []core.DiscoveryHint {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]core.DiscoveryHint, 0, len(values))
	for _, value := range values {
		valueClone := value
		valueClone.Evidence = cloneStrings(value.Evidence)
		cloned = append(cloned, valueClone)
	}
	return cloned
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

func sortChanges(changes []Change) {
	slices.SortFunc(changes, func(left Change, right Change) int {
		if comparison := cmp.Compare(left.IdentityKey, right.IdentityKey); comparison != 0 {
			return comparison
		}
		return cmp.Compare(left.Code, right.Code)
	})
}
