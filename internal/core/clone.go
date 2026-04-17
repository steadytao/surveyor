package core

// CloneTargetResult returns a deep copy of one target result so report
// assembly can treat the returned value as stable data.
func CloneTargetResult(result TargetResult) TargetResult {
	cloned := result
	cloned.CertificateChain = cloneCertificateRefs(result.CertificateChain)
	cloned.Findings = cloneFindings(result.Findings)
	cloned.Warnings = append([]string(nil), result.Warnings...)
	cloned.Errors = append([]string(nil), result.Errors...)
	return cloned
}

// CloneDiscoveredEndpoint returns a deep copy of one discovered endpoint.
func CloneDiscoveredEndpoint(endpoint DiscoveredEndpoint) DiscoveredEndpoint {
	cloned := endpoint
	cloned.Inventory = cloneInventoryAnnotation(endpoint.Inventory)
	cloned.Hints = cloneDiscoveryHints(endpoint.Hints)
	cloned.Warnings = append([]string(nil), endpoint.Warnings...)
	cloned.Errors = append([]string(nil), endpoint.Errors...)
	return cloned
}

// CloneAuditResult returns a deep copy of one audit result.
func CloneAuditResult(result AuditResult) AuditResult {
	cloned := result
	cloned.DiscoveredEndpoint = CloneDiscoveredEndpoint(result.DiscoveredEndpoint)
	if result.TLSResult != nil {
		tlsResult := CloneTargetResult(*result.TLSResult)
		cloned.TLSResult = &tlsResult
	}
	return cloned
}

func cloneDiscoveryHints(hints []DiscoveryHint) []DiscoveryHint {
	if len(hints) == 0 {
		return nil
	}

	cloned := make([]DiscoveryHint, 0, len(hints))
	for _, hint := range hints {
		hintClone := hint
		hintClone.Evidence = append([]string(nil), hint.Evidence...)
		cloned = append(cloned, hintClone)
	}

	return cloned
}

func cloneCertificateRefs(refs []CertificateRef) []CertificateRef {
	if len(refs) == 0 {
		return nil
	}

	cloned := make([]CertificateRef, 0, len(refs))
	for _, ref := range refs {
		refClone := ref
		refClone.DNSNames = append([]string(nil), ref.DNSNames...)
		cloned = append(cloned, refClone)
	}

	return cloned
}

func cloneFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	cloned := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		findingClone := finding
		findingClone.Evidence = append([]string(nil), finding.Evidence...)
		cloned = append(cloned, findingClone)
	}

	return cloned
}

func cloneInventoryAnnotation(annotation *InventoryAnnotation) *InventoryAnnotation {
	if annotation == nil {
		return nil
	}

	cloned := *annotation
	cloned.Ports = append([]int(nil), annotation.Ports...)
	cloned.Tags = append([]string(nil), annotation.Tags...)
	cloned.Provenance = cloneInventoryProvenance(annotation.Provenance)
	return &cloned
}

func cloneInventoryProvenance(provenance []InventoryProvenance) []InventoryProvenance {
	if len(provenance) == 0 {
		return nil
	}

	cloned := make([]InventoryProvenance, 0, len(provenance))
	cloned = append(cloned, provenance...)
	return cloned
}

// CloneWorkflowContext returns a deep copy of one workflow context.
func CloneWorkflowContext(context *WorkflowContext) *WorkflowContext {
	if context == nil {
		return nil
	}

	cloned := *context
	cloned.Filters = cloneWorkflowFilters(context.Filters)
	return &cloned
}

// CloneGroupedSummaries returns a deep copy of grouped-summary data.
func CloneGroupedSummaries(summaries []GroupedSummary) []GroupedSummary {
	if len(summaries) == 0 {
		return nil
	}

	cloned := make([]GroupedSummary, 0, len(summaries))
	for _, summary := range summaries {
		summaryClone := summary
		summaryClone.Groups = cloneGroupedSummaryGroups(summary.Groups)
		cloned = append(cloned, summaryClone)
	}

	return cloned
}

// CloneWorkflowFindings returns a deep copy of workflow findings.
func CloneWorkflowFindings(findings []WorkflowFinding) []WorkflowFinding {
	if len(findings) == 0 {
		return nil
	}

	cloned := make([]WorkflowFinding, 0, len(findings))
	for _, finding := range findings {
		findingClone := finding
		findingClone.Evidence = append([]string(nil), finding.Evidence...)
		cloned = append(cloned, findingClone)
	}

	return cloned
}

func cloneWorkflowFilters(filters []WorkflowFilter) []WorkflowFilter {
	if len(filters) == 0 {
		return nil
	}

	cloned := make([]WorkflowFilter, 0, len(filters))
	for _, filter := range filters {
		filterClone := filter
		filterClone.Values = append([]string(nil), filter.Values...)
		cloned = append(cloned, filterClone)
	}

	return cloned
}

func cloneGroupedSummaryGroups(groups []GroupedSummaryGroup) []GroupedSummaryGroup {
	if len(groups) == 0 {
		return nil
	}

	cloned := make([]GroupedSummaryGroup, 0, len(groups))
	for _, group := range groups {
		groupClone := group
		groupClone.SeverityBreakdown = cloneStringIntMap(group.SeverityBreakdown)
		groupClone.CodeBreakdown = cloneStringIntMap(group.CodeBreakdown)
		groupClone.DirectionBreakdown = cloneStringIntMap(group.DirectionBreakdown)
		groupClone.ChangeBreakdown = cloneStringIntMap(group.ChangeBreakdown)
		cloned = append(cloned, groupClone)
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
