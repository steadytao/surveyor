package audit

import (
	"context"
	"fmt"
	"sync"

	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
	"github.com/steadytao/surveyor/internal/discovery"
	"github.com/steadytao/surveyor/internal/scanners/tlsinventory"
)

// DefaultScanConcurrency is the default worker count for independent TLS scan
// handoff when the caller does not supply a narrower limit.
const DefaultScanConcurrency = 8

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
	Discoverer      Discoverer
	TLSScanner      TargetScanner
	Select          SelectFunc
	ScanConcurrency int
}

// Run executes the local audit flow and returns one audit result per discovered endpoint.
func (r LocalRunner) Run(ctx context.Context) ([]core.AuditResult, error) {
	discoverer := r.Discoverer
	if discoverer == nil {
		discoverer = discovery.LocalEnumerator{}
	}

	return runAuditFlow(ctx, discoverer, r.Select, r.TLSScanner, normalizedScanConcurrency(r.ScanConcurrency))
}

// RemoteRunner performs the current remote audit workflow: scoped remote
// discovery, selection and supported scanner handoff.
type RemoteRunner struct {
	Scope           config.RemoteScope
	Discoverer      Discoverer
	TLSScanner      TargetScanner
	Select          SelectFunc
	ScanConcurrency int
}

// Run executes the remote audit flow and returns one audit result per
// discovered endpoint within the declared remote scope.
func (r RemoteRunner) Run(ctx context.Context) ([]core.AuditResult, error) {
	discoverer := r.Discoverer
	if discoverer == nil {
		discoverer = discovery.RemoteEnumerator{Scope: r.Scope}
	}

	return runAuditFlow(ctx, discoverer, r.Select, r.TLSScanner, normalizedScanConcurrency(r.ScanConcurrency, r.Scope.MaxConcurrency))
}

func runAuditFlow(ctx context.Context, discoverer Discoverer, selectFunc SelectFunc, scanner TargetScanner, scanConcurrency int) ([]core.AuditResult, error) {
	if selectFunc == nil {
		selectFunc = SelectEndpoints
	}

	tlsScanner := scanner
	if tlsScanner == nil {
		tlsScanner = tlsinventory.Scanner{}
	}

	endpoints, err := discoverer.Enumerate(ctx)
	if err != nil {
		return nil, err
	}

	results := selectFunc(endpoints)
	jobs := make([]auditScanJob, 0, len(results))
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

			jobs = append(jobs, auditScanJob{
				index:  index,
				target: target,
			})
		default:
			// Keep unsupported selections explicit in the report instead of
			// silently dropping them.
			result.Selection = skippedSelection(fmt.Sprintf("selected scanner %q is not implemented", result.Selection.SelectedScanner))
		}
	}

	applyAuditScanResults(ctx, tlsScanner, results, jobs, scanConcurrency)

	return results, nil
}

type auditScanJob struct {
	index  int
	target config.Target
}

type auditScanResult struct {
	index  int
	result core.TargetResult
}

func normalizedScanConcurrency(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}

	return DefaultScanConcurrency
}

func applyAuditScanResults(ctx context.Context, scanner TargetScanner, results []core.AuditResult, jobs []auditScanJob, maxConcurrency int) {
	if len(jobs) == 0 {
		return
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	if maxConcurrency > len(jobs) {
		maxConcurrency = len(jobs)
	}

	jobCh := make(chan auditScanJob)
	resultCh := make(chan auditScanResult, maxConcurrency)

	var workerGroup sync.WaitGroup
	for worker := 0; worker < maxConcurrency; worker++ {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()

			for job := range jobCh {
				resultCh <- auditScanResult{
					index:  job.index,
					result: scanner.ScanTarget(ctx, job.target),
				}
			}
		}()
	}

	ordered := make(map[int]core.TargetResult, len(jobs))
	var collectGroup sync.WaitGroup
	collectGroup.Add(1)
	go func() {
		defer collectGroup.Done()

		for result := range resultCh {
			ordered[result.index] = result.result
		}
	}()

	for _, job := range jobs {
		jobCh <- job
	}
	close(jobCh)

	workerGroup.Wait()
	close(resultCh)
	collectGroup.Wait()

	for _, job := range jobs {
		scanResult := ordered[job.index]
		results[job.index].TLSResult = &scanResult
	}
}
