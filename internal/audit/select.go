package audit

import (
	"fmt"

	"github.com/steadytao/surveyor/internal/core"
)

func SelectEndpoints(endpoints []core.DiscoveredEndpoint) []core.AuditResult {
	results := make([]core.AuditResult, 0, len(endpoints))

	for _, endpoint := range endpoints {
		results = append(results, core.AuditResult{
			DiscoveredEndpoint: cloneDiscoveredEndpoint(endpoint),
			Selection:          selectEndpoint(endpoint),
		})
	}

	return results
}

func selectEndpoint(endpoint core.DiscoveredEndpoint) core.AuditSelection {
	if len(endpoint.Errors) > 0 {
		return skippedSelection("discovery result contains errors")
	}

	if endpoint.Transport != "tcp" {
		return skippedSelection(fmt.Sprintf("no supported scanner for %s endpoint", endpoint.Transport))
	}

	if endpoint.State != "listening" {
		return skippedSelection(fmt.Sprintf("unsupported tcp endpoint state %s", endpoint.State))
	}

	for _, hint := range endpoint.Hints {
		if hint.Protocol != "tls" {
			continue
		}

		return core.AuditSelection{
			Status:          core.AuditSelectionStatusSelected,
			SelectedScanner: "tls",
			Reason:          fmt.Sprintf("tls hint on %s/%d", endpoint.Transport, endpoint.Port),
		}
	}

	if len(endpoint.Hints) == 0 {
		return skippedSelection("no supported scanner for endpoint without recognised hints")
	}

	return skippedSelection("no supported scanner for hinted protocols")
}

func skippedSelection(reason string) core.AuditSelection {
	return core.AuditSelection{
		Status: core.AuditSelectionStatusSkipped,
		Reason: reason,
	}
}

func cloneDiscoveredEndpoint(endpoint core.DiscoveredEndpoint) core.DiscoveredEndpoint {
	cloned := endpoint
	cloned.Hints = append([]core.DiscoveryHint(nil), endpoint.Hints...)
	cloned.Warnings = append([]string(nil), endpoint.Warnings...)
	cloned.Errors = append([]string(nil), endpoint.Errors...)

	return cloned
}
