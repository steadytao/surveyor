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
