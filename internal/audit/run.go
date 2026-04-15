package audit

import (
	"context"
	"fmt"

	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
	"github.com/steadytao/surveyor/internal/discovery"
	"github.com/steadytao/surveyor/internal/scanners/tlsinventory"
)

// Discoverer returns local endpoint facts for audit orchestration.
type Discoverer interface {
	Enumerate(context.Context) ([]core.DiscoveredEndpoint, error)
}

// TargetScanner scans one explicit target and returns the canonical TLS result.
type TargetScanner interface {
	ScanTarget(context.Context, config.Target) core.TargetResult
}

// SelectFunc turns discovered endpoints into audit results with selection decisions.
type SelectFunc func([]core.DiscoveredEndpoint) []core.AuditResult

// LocalRunner performs the current local audit workflow: discovery, selection
// and supported scanner handoff.
type LocalRunner struct {
	Discoverer Discoverer
	TLSScanner TargetScanner
	Select     SelectFunc
}

// Run executes the local audit flow and returns one audit result per discovered endpoint.
func (r LocalRunner) Run(ctx context.Context) ([]core.AuditResult, error) {
	discoverer := r.Discoverer
	if discoverer == nil {
		discoverer = discovery.LocalEnumerator{}
	}

	selector := r.Select
	if selector == nil {
		selector = SelectEndpoints
	}

	tlsScanner := r.TLSScanner
	if tlsScanner == nil {
		tlsScanner = tlsinventory.Scanner{}
	}

	endpoints, err := discoverer.Enumerate(ctx)
	if err != nil {
		return nil, err
	}

	results := selector(endpoints)
	for index := range results {
		result := &results[index]
		if result.Selection.Status != core.AuditSelectionStatusSelected {
			continue
		}

		switch result.Selection.SelectedScanner {
		case "tls":
			// Reuse the explicit-target validation path before handing a
			// discovered endpoint to the TLS scanner. Audit should not invent a
			// looser target model than the standalone TLS path accepts.
			target, err := config.ValidateTarget(config.Target{
				Host: result.DiscoveredEndpoint.Host,
				Port: result.DiscoveredEndpoint.Port,
			})
			if err != nil {
				result.Selection = skippedSelection(fmt.Sprintf("invalid discovered endpoint for tls scan: %v", err))
				continue
			}

			scanResult := tlsScanner.ScanTarget(ctx, target)
			result.TLSResult = &scanResult
		default:
			// Keep unsupported selections explicit in the report instead of
			// silently dropping them.
			result.Selection = skippedSelection(fmt.Sprintf("selected scanner %q is not implemented", result.Selection.SelectedScanner))
		}
	}

	return results, nil
}
