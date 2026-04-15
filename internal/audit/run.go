package audit

import (
	"context"
	"fmt"

	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
	"github.com/steadytao/surveyor/internal/discovery"
	"github.com/steadytao/surveyor/internal/scanners/tlsinventory"
)

type Discoverer interface {
	Enumerate(context.Context) ([]core.DiscoveredEndpoint, error)
}

type TargetScanner interface {
	ScanTarget(context.Context, config.Target) core.TargetResult
}

type SelectFunc func([]core.DiscoveredEndpoint) []core.AuditResult

type LocalRunner struct {
	Discoverer Discoverer
	TLSScanner TargetScanner
	Select     SelectFunc
}

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
			target, err := config.ValidateTarget(config.Target{
				Host: result.DiscoveredEndpoint.Address,
				Port: result.DiscoveredEndpoint.Port,
			})
			if err != nil {
				result.Selection = skippedSelection(fmt.Sprintf("invalid discovered endpoint for tls scan: %v", err))
				continue
			}

			scanResult := tlsScanner.ScanTarget(ctx, target)
			result.TLSResult = &scanResult
		default:
			result.Selection = skippedSelection(fmt.Sprintf("selected scanner %q is not implemented", result.Selection.SelectedScanner))
		}
	}

	return results, nil
}
