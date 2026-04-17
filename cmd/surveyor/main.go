package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	auditflow "github.com/steadytao/surveyor/internal/audit"
	"github.com/steadytao/surveyor/internal/baseline"
	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
	diffreport "github.com/steadytao/surveyor/internal/diff"
	"github.com/steadytao/surveyor/internal/discovery"
	"github.com/steadytao/surveyor/internal/outputs"
	prioritizereport "github.com/steadytao/surveyor/internal/prioritize"
	"github.com/steadytao/surveyor/internal/scanners/tlsinventory"
)

type auditRunner interface {
	Run(context.Context) ([]core.AuditResult, error)
}

type discoverer interface {
	Enumerate(context.Context) ([]core.DiscoveredEndpoint, error)
}

type explicitTargetScanner interface {
	ScanTarget(context.Context, config.Target) core.TargetResult
}

type stringSliceFlag []string

func (values *stringSliceFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *stringSliceFlag) Set(raw string) error {
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		*values = append(*values, trimmed)
	}

	return nil
}

// Package-level factories keep the CLI entrypoint thin while still letting
// tests replace the real runners and discoverers without wiring a bespoke
// dependency graph through main.
var newLocalAuditRunner = func(now func() time.Time) auditRunner {
	return auditflow.LocalRunner{
		TLSScanner:      tlsinventory.Scanner{Now: now},
		ScanConcurrency: auditflow.DefaultScanConcurrency,
	}
}

var newRemoteAuditRunner = func(scope config.RemoteScope, now func() time.Time) auditRunner {
	return auditflow.RemoteRunner{
		Scope:           scope,
		TLSScanner:      tlsinventory.Scanner{Now: now, Timeout: scope.Timeout},
		ScanConcurrency: scope.MaxConcurrency,
	}
}

var newLocalDiscoverer = func() discoverer {
	return discovery.LocalEnumerator{}
}

var newRemoteDiscoverer = func(scope config.RemoteScope) discoverer {
	return discovery.RemoteEnumerator{
		Scope: scope,
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}

func run(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "audit":
		return runAudit(args[1:], stdout, stderr, now)
	case "discover":
		return runDiscover(args[1:], stdout, stderr, now)
	case "diff":
		return runDiff(args[1:], stdout, stderr, now)
	case "prioritize", "prioritise":
		return runPrioritize(args[1:], stdout, stderr, now, args[0])
	case "scan":
		return runScan(args[1:], stdout, stderr, now)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runDiff(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	normalizedArgs, err := normalizeDiffArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		printDiffUsage(stderr)
		return 2
	}

	fs := flag.NewFlagSet("surveyor diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		printDiffUsage(stderr)
	}

	markdownPath := fs.String("output", "", "Write Markdown report output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown report output to this path")

	jsonPath := fs.String("json", "", "Write canonical JSON report output to this path")
	fs.StringVar(jsonPath, "j", "", "Write canonical JSON report output to this path")

	groupBy := fs.String("group-by", "", "Group workflow output by owner, environment or source")

	var includeOwners stringSliceFlag
	fs.Var(&includeOwners, "include-owner", "Include only inventory-backed endpoints owned by this value; may be repeated")

	var includeEnvironments stringSliceFlag
	fs.Var(&includeEnvironments, "include-environment", "Include only inventory-backed endpoints in this environment; may be repeated")

	var includeTags stringSliceFlag
	fs.Var(&includeTags, "include-tag", "Include only inventory-backed endpoints with this tag; may be repeated")

	if err := fs.Parse(normalizedArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if fs.NArg() != 2 {
		fmt.Fprintf(stderr, "diff requires exactly two input files: baseline.json and current.json\n\n")
		printDiffUsage(stderr)
		return 2
	}

	baselinePath := fs.Arg(0)
	currentPath := fs.Arg(1)
	workflowView, err := workflowViewFromFlags(*groupBy, includeOwners, includeEnvironments, includeTags)
	if err != nil {
		fmt.Fprintln(stderr, err)
		printDiffUsage(stderr)
		return 2
	}

	diffNow := now
	if diffNow == nil {
		diffNow = time.Now
	}

	report, err := buildDiffReportFromFiles(baselinePath, currentPath, diffNow().UTC(), workflowView)
	if err != nil {
		fmt.Fprintf(stderr, "diff: %v\n", err)
		return 1
	}

	return writeDiffOutputs(report, stdout, stderr, *markdownPath, *jsonPath)
}

func runPrioritize(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time, commandName string) int {
	normalizedArgs, err := normalizePrioritizeArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		printPrioritizeUsage(stderr)
		return 2
	}

	fs := flag.NewFlagSet("surveyor "+commandName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		printPrioritizeUsage(stderr)
	}

	profileText := fs.String("profile", "", "Prioritization profile: migration-readiness or change-risk")

	markdownPath := fs.String("output", "", "Write Markdown report output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown report output to this path")

	jsonPath := fs.String("json", "", "Write canonical JSON report output to this path")
	fs.StringVar(jsonPath, "j", "", "Write canonical JSON report output to this path")

	groupBy := fs.String("group-by", "", "Group workflow output by owner, environment or source")

	var includeOwners stringSliceFlag
	fs.Var(&includeOwners, "include-owner", "Include only inventory-backed endpoints owned by this value; may be repeated")

	var includeEnvironments stringSliceFlag
	fs.Var(&includeEnvironments, "include-environment", "Include only inventory-backed endpoints in this environment; may be repeated")

	var includeTags stringSliceFlag
	fs.Var(&includeTags, "include-tag", "Include only inventory-backed endpoints with this tag; may be repeated")

	if err := fs.Parse(normalizedArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "%s requires exactly one input file: current.json\n\n", commandName)
		printPrioritizeUsage(stderr)
		return 2
	}

	profile, err := prioritizereport.ParseProfile(*profileText)
	if err != nil {
		fmt.Fprintln(stderr, err)
		printPrioritizeUsage(stderr)
		return 2
	}

	workflowView, err := workflowViewFromFlags(*groupBy, includeOwners, includeEnvironments, includeTags)
	if err != nil {
		fmt.Fprintln(stderr, err)
		printPrioritizeUsage(stderr)
		return 2
	}

	prioritizeNow := now
	if prioritizeNow == nil {
		prioritizeNow = time.Now
	}

	report, err := buildPrioritizationReportFromFile(fs.Arg(0), profile, prioritizeNow().UTC(), workflowView)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", commandName, err)
		return 1
	}

	return writePrioritizationOutputs(report, stdout, stderr, *markdownPath, *jsonPath)
}

func runAudit(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	if len(args) == 0 {
		printAuditUsage(stderr)
		return 2
	}

	switch args[0] {
	case "local":
		return runAuditLocal(args[1:], stdout, stderr, now)
	case "remote":
		return runAuditRemote(args[1:], stdout, stderr, now)
	case "subnet":
		return runAuditSubnet(args[1:], stdout, stderr, now)
	case "-h", "--help", "help":
		printAuditUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown audit target %q\n\n", args[0])
		printAuditUsage(stderr)
		return 2
	}
}

func runDiscover(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	if len(args) == 0 {
		printDiscoverUsage(stderr)
		return 2
	}

	switch args[0] {
	case "local":
		return runDiscoverLocal(args[1:], stdout, stderr, now)
	case "remote":
		return runDiscoverRemote(args[1:], stdout, stderr, now)
	case "subnet":
		return runDiscoverSubnet(args[1:], stdout, stderr, now)
	case "-h", "--help", "help":
		printDiscoverUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown discovery target %q\n\n", args[0])
		printDiscoverUsage(stderr)
		return 2
	}
}

func runScan(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	if len(args) == 0 {
		printScanUsage(stderr)
		return 2
	}

	switch args[0] {
	case "tls":
		return runScanTLS(args[1:], stdout, stderr, now)
	case "-h", "--help", "help":
		printScanUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown scan target %q\n\n", args[0])
		printScanUsage(stderr)
		return 2
	}
}

func runScanTLS(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	fs := flag.NewFlagSet("surveyor scan tls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		printScanTLSUsage(stderr)
	}

	configPath := fs.String("config", "", "Path to a YAML config file with explicit TLS targets")
	fs.StringVar(configPath, "c", "", "Path to a YAML config file with explicit TLS targets")

	targetsArg := fs.String("targets", "", "Comma-separated explicit host:port targets")
	fs.StringVar(targetsArg, "t", "", "Comma-separated explicit host:port targets")

	markdownPath := fs.String("output", "", "Write Markdown report output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown report output to this path")

	jsonPath := fs.String("json", "", "Write canonical JSON report output to this path")
	fs.StringVar(jsonPath, "j", "", "Write canonical JSON report output to this path")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	targets, err := resolveTargets(*configPath, *targetsArg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	scannerNow := now
	if scannerNow == nil {
		scannerNow = time.Now
	}

	scanner := tlsinventory.Scanner{
		Now: scannerNow,
	}

	results := scanExplicitTargets(context.Background(), scanner, targets, auditflow.DefaultScanConcurrency)

	report := outputs.BuildReportWithMetadata(results, scannerNow().UTC(), explicitReportScopeMetadata(*configPath, *targetsArg))

	if *jsonPath != "" {
		jsonData, err := outputs.MarshalJSON(report)
		if err != nil {
			fmt.Fprintf(stderr, "build JSON output: %v\n", err)
			return 1
		}

		if err := writeOutputFile(*jsonPath, jsonData); err != nil {
			fmt.Fprintf(stderr, "write JSON output %q: %v\n", *jsonPath, err)
			return 1
		}
	}

	markdown := outputs.RenderMarkdown(report)

	if *markdownPath != "" {
		if err := writeOutputFile(*markdownPath, []byte(markdown)); err != nil {
			fmt.Fprintf(stderr, "write Markdown output %q: %v\n", *markdownPath, err)
			return 1
		}
	}

	if *markdownPath == "" && *jsonPath == "" {
		if _, err := io.WriteString(stdout, markdown); err != nil {
			fmt.Fprintf(stderr, "write stdout: %v\n", err)
			return 1
		}
	}

	return 0
}

type indexedExplicitTarget struct {
	index  int
	target config.Target
}

type indexedExplicitScanResult struct {
	index  int
	result core.TargetResult
}

func scanExplicitTargets(ctx context.Context, scanner explicitTargetScanner, targets []config.Target, maxConcurrency int) []core.TargetResult {
	if len(targets) == 0 {
		return nil
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	if maxConcurrency > len(targets) {
		maxConcurrency = len(targets)
	}

	jobs := make(chan indexedExplicitTarget)
	results := make(chan indexedExplicitScanResult, maxConcurrency)

	var workerGroup sync.WaitGroup
	for worker := 0; worker < maxConcurrency; worker++ {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()

			for job := range jobs {
				results <- indexedExplicitScanResult{
					index:  job.index,
					result: scanner.ScanTarget(ctx, job.target),
				}
			}
		}()
	}

	ordered := make([]core.TargetResult, len(targets))
	var collectGroup sync.WaitGroup
	collectGroup.Add(1)
	go func() {
		defer collectGroup.Done()

		for result := range results {
			ordered[result.index] = result.result
		}
	}()

	for index, target := range targets {
		jobs <- indexedExplicitTarget{
			index:  index,
			target: target,
		}
	}
	close(jobs)

	workerGroup.Wait()
	close(results)
	collectGroup.Wait()

	return ordered
}

func runDiscoverLocal(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	fs := flag.NewFlagSet("surveyor discover local", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		printDiscoverLocalUsage(stderr)
	}

	markdownPath := fs.String("output", "", "Write Markdown report output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown report output to this path")

	jsonPath := fs.String("json", "", "Write canonical JSON report output to this path")
	fs.StringVar(jsonPath, "j", "", "Write canonical JSON report output to this path")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "discover local does not accept positional arguments: %s\n\n", strings.Join(fs.Args(), " "))
		printDiscoverLocalUsage(stderr)
		return 2
	}

	discoverNow := now
	if discoverNow == nil {
		discoverNow = time.Now
	}

	results, err := newLocalDiscoverer().Enumerate(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "discover local: %v\n", err)
		return 1
	}

	return writeDiscoveryOutputs("discover local", results, discoverNow().UTC(), localReportScopeMetadata(), nil, stdout, stderr, *markdownPath, *jsonPath)
}

func runDiscoverRemote(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	return runRemoteDiscoveryCommand(args, stdout, stderr, now, remoteCommandOptions{
		commandName:        "discover remote",
		printUsage:         printDiscoverRemoteUsage,
		allowTargetsFile:   true,
		allowInventoryFile: true,
	})
}

func runDiscoverSubnet(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	return runRemoteDiscoveryCommand(args, stdout, stderr, now, remoteCommandOptions{
		commandName:        "discover subnet",
		printUsage:         printDiscoverSubnetUsage,
		allowTargetsFile:   false,
		allowInventoryFile: false,
	})
}

type remoteCommandOptions struct {
	commandName        string
	printUsage         func(io.Writer)
	allowTargetsFile   bool
	allowInventoryFile bool
}

func runRemoteDiscoveryCommand(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time, opts remoteCommandOptions) int {
	fs := flag.NewFlagSet(opts.commandName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		opts.printUsage(stderr)
	}

	cidr := fs.String("cidr", "", "CIDR scope to discover, for example 10.0.0.0/24")
	var targetsFile *string
	var inventoryFile *string
	var adapter *string
	var adapterBinary *string
	if opts.allowTargetsFile {
		targetsFile = fs.String("targets-file", "", "Path to a newline-delimited host or IP scope file")
	}
	if opts.allowInventoryFile {
		inventoryFile = fs.String("inventory-file", "", "Path to a structured imported inventory file")
		adapter = fs.String("adapter", "", "Explicit platform adapter for --inventory-file, for example caddy or kubernetes-ingress-v1")
		adapterBinary = fs.String("adapter-bin", "", "Path to an external adapter executable when the selected adapter needs one")
	}
	ports := fs.String("ports", "", "Comma-separated remote ports, required for --cidr and --targets-file and overriding inventory entry ports when set")
	profile := fs.String("profile", "", "Remote pace profile: cautious, balanced or aggressive")
	dryRun := fs.Bool("dry-run", false, "Print the execution plan without performing network I/O")
	maxHosts := fs.Int("max-hosts", 0, "Hard cap on expanded host count, defaulting to the fixed command default")
	maxAttempts := fs.Int("max-attempts", 0, "Hard cap on expanded host:port attempts, defaulting to the fixed command default")
	maxConcurrency := fs.Int("max-concurrency", 0, "Maximum concurrent remote probe attempts")
	timeout := fs.Duration("timeout", 0, "Per probe or connection attempt timeout")

	markdownPath := fs.String("output", "", "Write Markdown report output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown report output to this path")

	jsonPath := fs.String("json", "", "Write canonical JSON report output to this path")
	fs.StringVar(jsonPath, "j", "", "Write canonical JSON report output to this path")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "%s does not accept positional arguments: %s\n\n", opts.commandName, strings.Join(fs.Args(), " "))
		opts.printUsage(stderr)
		return 2
	}

	targetsFileValue := ""
	if targetsFile != nil {
		targetsFileValue = *targetsFile
	}
	inventoryFileValue := ""
	if inventoryFile != nil {
		inventoryFileValue = *inventoryFile
	}
	adapterValue := ""
	if adapter != nil {
		adapterValue = *adapter
	}
	adapterBinaryValue := ""
	if adapterBinary != nil {
		adapterBinaryValue = *adapterBinary
	}
	if !opts.allowTargetsFile && strings.TrimSpace(*cidr) == "" {
		fmt.Fprintln(stderr, "--cidr is required")
		return 2
	}

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		CIDR:           *cidr,
		TargetsFile:    targetsFileValue,
		InventoryFile:  inventoryFileValue,
		Adapter:        adapterValue,
		AdapterBinary:  adapterBinaryValue,
		Ports:          *ports,
		Profile:        *profile,
		MaxHosts:       *maxHosts,
		MaxAttempts:    *maxAttempts,
		MaxConcurrency: *maxConcurrency,
		Timeout:        *timeout,
		DryRun:         *dryRun,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if scope.DryRun {
		if *jsonPath != "" {
			fmt.Fprintf(stderr, "%s --dry-run does not support --json\n", opts.commandName)
			return 2
		}

		plan := renderRemoteExecutionPlanMarkdown(opts.commandName, scope, "none, discovery only")
		if *markdownPath != "" {
			if err := writeOutputFile(*markdownPath, []byte(plan)); err != nil {
				fmt.Fprintf(stderr, "write dry-run Markdown output %q: %v\n", *markdownPath, err)
				return 1
			}
		}
		if *markdownPath == "" {
			if _, err := io.WriteString(stdout, plan); err != nil {
				fmt.Fprintf(stderr, "write stdout: %v\n", err)
				return 1
			}
		}

		return 0
	}

	discoverNow := now
	if discoverNow == nil {
		discoverNow = time.Now
	}

	results, err := newRemoteDiscoverer(scope).Enumerate(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", opts.commandName, err)
		return 1
	}

	reportScope, execution := remoteReportMetadata(scope)
	return writeDiscoveryOutputs(opts.commandName, results, discoverNow().UTC(), reportScope, execution, stdout, stderr, *markdownPath, *jsonPath)
}

func writeDiscoveryOutputs(commandName string, results []core.DiscoveredEndpoint, generatedAt time.Time, reportScope *core.ReportScope, execution *core.ReportExecution, stdout io.Writer, stderr io.Writer, markdownPath string, jsonPath string) int {
	report := outputs.BuildDiscoveryReportWithMetadata(results, generatedAt.UTC(), reportScope, execution)

	if jsonPath != "" {
		jsonData, err := outputs.MarshalDiscoveryJSON(report)
		if err != nil {
			fmt.Fprintf(stderr, "build discovery JSON output: %v\n", err)
			return 1
		}

		if err := writeOutputFile(jsonPath, jsonData); err != nil {
			fmt.Fprintf(stderr, "write discovery JSON output %q: %v\n", jsonPath, err)
			return 1
		}
	}

	markdown := outputs.RenderDiscoveryMarkdown(report)

	if markdownPath != "" {
		if err := writeOutputFile(markdownPath, []byte(markdown)); err != nil {
			fmt.Fprintf(stderr, "write discovery Markdown output %q: %v\n", markdownPath, err)
			return 1
		}
	}

	if markdownPath == "" && jsonPath == "" {
		if _, err := io.WriteString(stdout, markdown); err != nil {
			fmt.Fprintf(stderr, "%s: write stdout: %v\n", commandName, err)
			return 1
		}
	}

	return 0
}

func runAuditLocal(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	fs := flag.NewFlagSet("surveyor audit local", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		printAuditLocalUsage(stderr)
	}

	markdownPath := fs.String("output", "", "Write Markdown report output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown report output to this path")

	jsonPath := fs.String("json", "", "Write canonical JSON report output to this path")
	fs.StringVar(jsonPath, "j", "", "Write canonical JSON report output to this path")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "audit local does not accept positional arguments: %s\n\n", strings.Join(fs.Args(), " "))
		printAuditLocalUsage(stderr)
		return 2
	}

	auditNow := now
	if auditNow == nil {
		auditNow = time.Now
	}

	results, err := newLocalAuditRunner(auditNow).Run(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "audit local: %v\n", err)
		return 1
	}

	return writeAuditOutputs("audit local", results, auditNow().UTC(), localReportScopeMetadata(), nil, stdout, stderr, *markdownPath, *jsonPath)
}

func runAuditRemote(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	return runRemoteAuditCommand(args, stdout, stderr, now, remoteCommandOptions{
		commandName:        "audit remote",
		printUsage:         printAuditRemoteUsage,
		allowTargetsFile:   true,
		allowInventoryFile: true,
	})
}

func runAuditSubnet(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	return runRemoteAuditCommand(args, stdout, stderr, now, remoteCommandOptions{
		commandName:        "audit subnet",
		printUsage:         printAuditSubnetUsage,
		allowTargetsFile:   false,
		allowInventoryFile: false,
	})
}

func runRemoteAuditCommand(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time, opts remoteCommandOptions) int {
	fs := flag.NewFlagSet(opts.commandName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		opts.printUsage(stderr)
	}

	cidr := fs.String("cidr", "", "CIDR scope to audit, for example 10.0.0.0/24")
	var targetsFile *string
	var inventoryFile *string
	var adapter *string
	var adapterBinary *string
	if opts.allowTargetsFile {
		targetsFile = fs.String("targets-file", "", "Path to a newline-delimited host or IP scope file")
	}
	if opts.allowInventoryFile {
		inventoryFile = fs.String("inventory-file", "", "Path to a structured imported inventory file")
		adapter = fs.String("adapter", "", "Explicit platform adapter for --inventory-file, for example caddy or kubernetes-ingress-v1")
		adapterBinary = fs.String("adapter-bin", "", "Path to an external adapter executable when the selected adapter needs one")
	}
	ports := fs.String("ports", "", "Comma-separated remote ports, required for --cidr and --targets-file and overriding inventory entry ports when set")
	profile := fs.String("profile", "", "Remote pace profile: cautious, balanced or aggressive")
	dryRun := fs.Bool("dry-run", false, "Print the execution plan without performing network I/O")
	maxHosts := fs.Int("max-hosts", 0, "Hard cap on expanded host count, defaulting to the fixed command default")
	maxAttempts := fs.Int("max-attempts", 0, "Hard cap on expanded host:port attempts, defaulting to the fixed command default")
	maxConcurrency := fs.Int("max-concurrency", 0, "Maximum concurrent remote probe attempts")
	timeout := fs.Duration("timeout", 0, "Per probe or connection attempt timeout")

	markdownPath := fs.String("output", "", "Write Markdown report output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown report output to this path")

	jsonPath := fs.String("json", "", "Write canonical JSON report output to this path")
	fs.StringVar(jsonPath, "j", "", "Write canonical JSON report output to this path")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "%s does not accept positional arguments: %s\n\n", opts.commandName, strings.Join(fs.Args(), " "))
		opts.printUsage(stderr)
		return 2
	}

	targetsFileValue := ""
	if targetsFile != nil {
		targetsFileValue = *targetsFile
	}
	inventoryFileValue := ""
	if inventoryFile != nil {
		inventoryFileValue = *inventoryFile
	}
	adapterValue := ""
	if adapter != nil {
		adapterValue = *adapter
	}
	adapterBinaryValue := ""
	if adapterBinary != nil {
		adapterBinaryValue = *adapterBinary
	}
	if !opts.allowTargetsFile && strings.TrimSpace(*cidr) == "" {
		fmt.Fprintln(stderr, "--cidr is required")
		return 2
	}

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		CIDR:           *cidr,
		TargetsFile:    targetsFileValue,
		InventoryFile:  inventoryFileValue,
		Adapter:        adapterValue,
		AdapterBinary:  adapterBinaryValue,
		Ports:          *ports,
		Profile:        *profile,
		MaxHosts:       *maxHosts,
		MaxAttempts:    *maxAttempts,
		MaxConcurrency: *maxConcurrency,
		Timeout:        *timeout,
		DryRun:         *dryRun,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if scope.DryRun {
		if *jsonPath != "" {
			fmt.Fprintf(stderr, "%s --dry-run does not support --json\n", opts.commandName)
			return 2
		}

		plan := renderRemoteExecutionPlanMarkdown(opts.commandName, scope, "tls")
		if *markdownPath != "" {
			if err := writeOutputFile(*markdownPath, []byte(plan)); err != nil {
				fmt.Fprintf(stderr, "write dry-run Markdown output %q: %v\n", *markdownPath, err)
				return 1
			}
		}
		if *markdownPath == "" {
			if _, err := io.WriteString(stdout, plan); err != nil {
				fmt.Fprintf(stderr, "write stdout: %v\n", err)
				return 1
			}
		}

		return 0
	}

	auditNow := now
	if auditNow == nil {
		auditNow = time.Now
	}

	results, err := newRemoteAuditRunner(scope, auditNow).Run(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", opts.commandName, err)
		return 1
	}

	reportScope, execution := remoteReportMetadata(scope)
	return writeAuditOutputs(opts.commandName, results, auditNow().UTC(), reportScope, execution, stdout, stderr, *markdownPath, *jsonPath)
}

func writeAuditOutputs(commandName string, results []core.AuditResult, generatedAt time.Time, reportScope *core.ReportScope, execution *core.ReportExecution, stdout io.Writer, stderr io.Writer, markdownPath string, jsonPath string) int {
	report := outputs.BuildAuditReportWithMetadata(results, generatedAt.UTC(), reportScope, execution)

	if jsonPath != "" {
		jsonData, err := outputs.MarshalAuditJSON(report)
		if err != nil {
			fmt.Fprintf(stderr, "build audit JSON output: %v\n", err)
			return 1
		}

		if err := writeOutputFile(jsonPath, jsonData); err != nil {
			fmt.Fprintf(stderr, "write audit JSON output %q: %v\n", jsonPath, err)
			return 1
		}
	}

	markdown := outputs.RenderAuditMarkdown(report)

	if markdownPath != "" {
		if err := writeOutputFile(markdownPath, []byte(markdown)); err != nil {
			fmt.Fprintf(stderr, "write audit Markdown output %q: %v\n", markdownPath, err)
			return 1
		}
	}

	if markdownPath == "" && jsonPath == "" {
		if _, err := io.WriteString(stdout, markdown); err != nil {
			fmt.Fprintf(stderr, "%s: write stdout: %v\n", commandName, err)
			return 1
		}
	}

	return 0
}

func workflowViewFromFlags(groupByRaw string, includeOwners []string, includeEnvironments []string, includeTags []string) (*core.WorkflowContext, error) {
	groupByText := strings.TrimSpace(groupByRaw)
	if groupByText == "" && len(includeOwners) == 0 && len(includeEnvironments) == 0 && len(includeTags) == 0 {
		return nil, nil
	}

	var groupBy core.WorkflowGroupBy
	switch strings.ToLower(groupByText) {
	case "":
	case string(core.WorkflowGroupByOwner):
		groupBy = core.WorkflowGroupByOwner
	case string(core.WorkflowGroupByEnvironment):
		groupBy = core.WorkflowGroupByEnvironment
	case string(core.WorkflowGroupBySource):
		groupBy = core.WorkflowGroupBySource
	default:
		return nil, fmt.Errorf("invalid --group-by %q: must be one of owner, environment or source", groupByRaw)
	}

	filters := make([]core.WorkflowFilter, 0, 3)
	if values := normalizedWorkflowFilterValues(includeOwners); len(values) > 0 {
		filters = append(filters, core.WorkflowFilter{
			Field:  core.WorkflowFilterFieldOwner,
			Values: values,
		})
	}
	if values := normalizedWorkflowFilterValues(includeEnvironments); len(values) > 0 {
		filters = append(filters, core.WorkflowFilter{
			Field:  core.WorkflowFilterFieldEnvironment,
			Values: values,
		})
	}
	if values := normalizedWorkflowFilterValues(includeTags); len(values) > 0 {
		filters = append(filters, core.WorkflowFilter{
			Field:  core.WorkflowFilterFieldTag,
			Values: values,
		})
	}

	return &core.WorkflowContext{
		GroupBy: groupBy,
		Filters: filters,
	}, nil
}

func normalizedWorkflowFilterValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	return normalized
}

func buildDiffReportFromFiles(baselinePath string, currentPath string, generatedAt time.Time, workflowView *core.WorkflowContext) (diffreport.Report, error) {
	baselineHeader, baselineData, err := readReportInputFile(baselinePath)
	if err != nil {
		return diffreport.Report{}, err
	}
	currentHeader, currentData, err := readReportInputFile(currentPath)
	if err != nil {
		return diffreport.Report{}, err
	}

	if _, err := baseline.ValidateCompatibility(baselineHeader, currentHeader); err != nil {
		return diffreport.Report{}, err
	}

	switch baselineHeader.ReportKind {
	case core.ReportKindTLSScan:
		baselineReport, err := decodeTLSReport(baselinePath, baselineData)
		if err != nil {
			return diffreport.Report{}, err
		}
		currentReport, err := decodeTLSReport(currentPath, currentData)
		if err != nil {
			return diffreport.Report{}, err
		}

		return diffreport.BuildTLSReport(baselineReport, currentReport, generatedAt, workflowView)
	case core.ReportKindAudit:
		baselineReport, err := decodeAuditReport(baselinePath, baselineData)
		if err != nil {
			return diffreport.Report{}, err
		}
		currentReport, err := decodeAuditReport(currentPath, currentData)
		if err != nil {
			return diffreport.Report{}, err
		}

		return diffreport.BuildAuditReport(baselineReport, currentReport, generatedAt, workflowView)
	default:
		return diffreport.Report{}, fmt.Errorf("report_kind %q is not supported for diffing", baselineHeader.ReportKind)
	}
}

func buildPrioritizationReportFromFile(path string, profile prioritizereport.Profile, generatedAt time.Time, workflowView *core.WorkflowContext) (prioritizereport.Report, error) {
	header, data, err := readReportInputFile(path)
	if err != nil {
		return prioritizereport.Report{}, err
	}

	switch header.ReportKind {
	case core.ReportKindTLSScan:
		report, err := decodeTLSReport(path, data)
		if err != nil {
			return prioritizereport.Report{}, err
		}

		return prioritizereport.BuildTLSReport(report, profile, generatedAt, workflowView)
	case core.ReportKindAudit:
		report, err := decodeAuditReport(path, data)
		if err != nil {
			return prioritizereport.Report{}, err
		}

		return prioritizereport.BuildAuditReport(report, profile, generatedAt, workflowView)
	default:
		return prioritizereport.Report{}, fmt.Errorf("report_kind %q is not supported for prioritization; prioritize currently supports tls_scan and audit input only", header.ReportKind)
	}
}

func readReportInputFile(path string) (baseline.ReportHeader, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return baseline.ReportHeader{}, nil, fmt.Errorf("read report %q: %w", path, err)
	}

	header, err := baseline.ParseReportHeader(data)
	if err != nil {
		return baseline.ReportHeader{}, nil, fmt.Errorf("parse report %q: %w", path, err)
	}

	return header, data, nil
}

func decodeTLSReport(path string, data []byte) (core.Report, error) {
	var report core.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return core.Report{}, fmt.Errorf("parse TLS report %q: %w", path, err)
	}

	return report, nil
}

func decodeAuditReport(path string, data []byte) (core.AuditReport, error) {
	var report core.AuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		return core.AuditReport{}, fmt.Errorf("parse audit report %q: %w", path, err)
	}

	return report, nil
}

func writeDiffOutputs(report diffreport.Report, stdout io.Writer, stderr io.Writer, markdownPath string, jsonPath string) int {
	if jsonPath != "" {
		jsonData, err := outputs.MarshalDiffJSON(report)
		if err != nil {
			fmt.Fprintf(stderr, "build diff JSON output: %v\n", err)
			return 1
		}

		if err := writeOutputFile(jsonPath, jsonData); err != nil {
			fmt.Fprintf(stderr, "write diff JSON output %q: %v\n", jsonPath, err)
			return 1
		}
	}

	markdown := outputs.RenderDiffMarkdown(report)

	if markdownPath != "" {
		if err := writeOutputFile(markdownPath, []byte(markdown)); err != nil {
			fmt.Fprintf(stderr, "write diff Markdown output %q: %v\n", markdownPath, err)
			return 1
		}
	}

	if markdownPath == "" && jsonPath == "" {
		if _, err := io.WriteString(stdout, markdown); err != nil {
			fmt.Fprintf(stderr, "diff: write stdout: %v\n", err)
			return 1
		}
	}

	return 0
}

func writePrioritizationOutputs(report prioritizereport.Report, stdout io.Writer, stderr io.Writer, markdownPath string, jsonPath string) int {
	if jsonPath != "" {
		jsonData, err := outputs.MarshalPrioritizationJSON(report)
		if err != nil {
			fmt.Fprintf(stderr, "build prioritization JSON output: %v\n", err)
			return 1
		}

		if err := writeOutputFile(jsonPath, jsonData); err != nil {
			fmt.Fprintf(stderr, "write prioritization JSON output %q: %v\n", jsonPath, err)
			return 1
		}
	}

	markdown := outputs.RenderPrioritizationMarkdown(report)

	if markdownPath != "" {
		if err := writeOutputFile(markdownPath, []byte(markdown)); err != nil {
			fmt.Fprintf(stderr, "write prioritization Markdown output %q: %v\n", markdownPath, err)
			return 1
		}
	}

	if markdownPath == "" && jsonPath == "" {
		if _, err := io.WriteString(stdout, markdown); err != nil {
			fmt.Fprintf(stderr, "prioritize: write stdout: %v\n", err)
			return 1
		}
	}

	return 0
}

func resolveTargets(configPath string, targetsArg string) ([]config.Target, error) {
	hasConfig := strings.TrimSpace(configPath) != ""
	hasTargets := strings.TrimSpace(targetsArg) != ""

	switch {
	case hasConfig && hasTargets:
		return nil, errors.New("use either --config or --targets, not both")
	case !hasConfig && !hasTargets:
		return nil, errors.New("one of --config or --targets is required")
	case hasConfig:
		cfg, err := config.Load(configPath)
		if err != nil {
			return nil, err
		}

		return cfg.Targets, nil
	default:
		return parseTargetsArg(targetsArg)
	}
}

func parseTargetsArg(value string) ([]config.Target, error) {
	parts := strings.Split(value, ",")
	targets := make([]config.Target, 0, len(parts))

	for index, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			return nil, fmt.Errorf("targets[%d] must not be empty", index)
		}

		host, portText, err := net.SplitHostPort(entry)
		if err != nil {
			return nil, fmt.Errorf("targets[%d] must be in host:port form: %w", index, err)
		}

		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, fmt.Errorf("targets[%d] port must be numeric: %w", index, err)
		}

		target, err := config.ValidateTarget(config.Target{
			Host: host,
			Port: port,
		})
		if err != nil {
			return nil, fmt.Errorf("targets[%d]: %w", index, err)
		}

		targets = append(targets, target)
	}

	if len(targets) == 0 {
		return nil, errors.New("at least one target is required")
	}

	return targets, nil
}

func writeOutputFile(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("output path must not be empty")
	}

	return os.WriteFile(path, data, 0o644)
}

func normalizeDiffArgs(args []string) ([]string, error) {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "-h" || arg == "--help":
			flags = append(flags, arg)
		case arg == "-o" || arg == "--output" || arg == "-j" || arg == "--json" || arg == "--group-by" || arg == "--include-owner" || arg == "--include-environment" || arg == "--include-tag":
			if index+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a value", arg)
			}
			flags = append(flags, arg, args[index+1])
			index += 1
		case strings.HasPrefix(arg, "--output=") || strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "--group-by=") || strings.HasPrefix(arg, "--include-owner=") || strings.HasPrefix(arg, "--include-environment=") || strings.HasPrefix(arg, "--include-tag="):
			flags = append(flags, arg)
		case strings.HasPrefix(arg, "-o=") || strings.HasPrefix(arg, "-j="):
			flags = append(flags, arg)
		case strings.HasPrefix(arg, "-"):
			return nil, fmt.Errorf("unknown flag %q", arg)
		default:
			positionals = append(positionals, arg)
		}
	}

	return append(flags, positionals...), nil
}

func normalizePrioritizeArgs(args []string) ([]string, error) {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "-h" || arg == "--help":
			flags = append(flags, arg)
		case arg == "-o" || arg == "--output" || arg == "-j" || arg == "--json" || arg == "--profile" || arg == "--group-by" || arg == "--include-owner" || arg == "--include-environment" || arg == "--include-tag":
			if index+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a value", arg)
			}
			flags = append(flags, arg, args[index+1])
			index += 1
		case strings.HasPrefix(arg, "--output=") || strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "--profile=") || strings.HasPrefix(arg, "--group-by=") || strings.HasPrefix(arg, "--include-owner=") || strings.HasPrefix(arg, "--include-environment=") || strings.HasPrefix(arg, "--include-tag="):
			flags = append(flags, arg)
		case strings.HasPrefix(arg, "-o=") || strings.HasPrefix(arg, "-j="):
			flags = append(flags, arg)
		case strings.HasPrefix(arg, "-"):
			return nil, fmt.Errorf("unknown flag %q", arg)
		default:
			positionals = append(positionals, arg)
		}
	}

	return append(flags, positionals...), nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Surveyor")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Inventory, audit, compare and prioritise transport-facing cryptographic exposure from explicit targets, local endpoints and declared remote scope.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor <command> [<args>...]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor scan tls --config examples/targets.yaml -o report.md -j report.json")
	fmt.Fprintln(w, "  surveyor discover remote --targets-file examples/approved-hosts.txt --ports 443 --dry-run")
	fmt.Fprintln(w, "  surveyor audit remote --inventory-file examples/inventory.yaml -o audit.md -j audit.json")
	fmt.Fprintln(w, "  surveyor diff baseline.json current.json -o diff.md -j diff.json")
	fmt.Fprintln(w, "  surveyor prioritize current.json --profile migration-readiness -o priorities.md -j priorities.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  diff            Compare two compatible Surveyor JSON reports and emit Markdown and optional JSON output")
	fmt.Fprintln(w, "  prioritize      Rank a current Surveyor JSON report; prioritise is supported as a CLI alias")
	fmt.Fprintln(w, "  audit local     Audit local endpoints by chaining discovery into supported scanners")
	fmt.Fprintln(w, "  audit remote    Audit declared remote scope across CIDR, host-list and structured inventory inputs")
	fmt.Fprintln(w, "  audit subnet    CIDR-only compatibility alias for remote audit from v0.4.x")
	fmt.Fprintln(w, "  discover local  Enumerate local endpoints and emit Markdown and optional JSON output")
	fmt.Fprintln(w, "  discover remote Enumerate declared remote scope across CIDR, host-list and structured inventory inputs")
	fmt.Fprintln(w, "  discover subnet CIDR-only compatibility alias for remote discovery from v0.4.x")
	fmt.Fprintln(w, "  scan tls        Scan explicit TLS targets and emit Markdown and optional JSON output")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'surveyor audit local --help' for audit-specific help.")
	fmt.Fprintln(w, "Run 'surveyor audit remote --help' for canonical remote audit help.")
	fmt.Fprintln(w, "Run 'surveyor audit subnet --help' for subnet audit help.")
	fmt.Fprintln(w, "Run 'surveyor diff --help' for diff help.")
	fmt.Fprintln(w, "Run 'surveyor discover local --help' for discovery-specific help.")
	fmt.Fprintln(w, "Run 'surveyor discover remote --help' for canonical remote discovery help.")
	fmt.Fprintln(w, "Run 'surveyor discover subnet --help' for subnet discovery help.")
	fmt.Fprintln(w, "Run 'surveyor prioritize --help' for prioritisation help.")
	fmt.Fprintln(w, "Run 'surveyor scan tls --help' for command-specific help.")
}

func printDiffUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor diff baseline.json current.json [--group-by owner|environment|source] [--include-owner NAME] [--include-environment NAME] [--include-tag TAG] [-o diff.md] [-j diff.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Compare two compatible canonical Surveyor JSON reports.")
	fmt.Fprintln(w, "  The first release supports tls_scan-to-tls_scan and audit-to-audit comparisons only.")
	fmt.Fprintln(w, "  Workflow grouping and filtering apply to inventory-backed audit comparisons only.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor diff baseline.json current.json")
	fmt.Fprintln(w, "  surveyor diff baseline.json current.json --group-by owner --include-environment prod")
	fmt.Fprintln(w, "  surveyor diff baseline.json current.json -o diff.md -j diff.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --group-by     Group workflow output by owner, environment or source")
	fmt.Fprintln(w, "  --include-owner        Include only inventory-backed endpoints owned by this value; may be repeated")
	fmt.Fprintln(w, "  --include-environment  Include only inventory-backed endpoints in this environment; may be repeated")
	fmt.Fprintln(w, "  --include-tag          Include only inventory-backed endpoints with this tag; may be repeated")
	fmt.Fprintln(w, "  -o, --output   Write Markdown report output to this path")
	fmt.Fprintln(w, "  -j, --json     Write canonical JSON report output to this path")
}

func printPrioritizeUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor prioritize current.json [--profile migration-readiness] [--group-by owner|environment|source] [--include-owner NAME] [--include-environment NAME] [--include-tag TAG] [-o priorities.md] [-j priorities.json]")
	fmt.Fprintln(w, "  surveyor prioritise current.json [--profile migration-readiness] [--group-by owner|environment|source] [--include-owner NAME] [--include-environment NAME] [--include-tag TAG] [-o priorities.md] [-j priorities.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Rank a current canonical Surveyor JSON report for human attention.")
	fmt.Fprintln(w, "  The first release supports tls_scan and audit input only.")
	fmt.Fprintln(w, "  Workflow grouping and filtering apply to inventory-backed audit input only.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor prioritize current.json")
	fmt.Fprintln(w, "  surveyor prioritize current.json --group-by owner --include-environment prod")
	fmt.Fprintln(w, "  surveyor prioritise current.json --profile change-risk -o priorities.md -j priorities.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --profile      Prioritisation profile: migration-readiness or change-risk")
	fmt.Fprintln(w, "  --group-by     Group workflow output by owner, environment or source")
	fmt.Fprintln(w, "  --include-owner        Include only inventory-backed endpoints owned by this value; may be repeated")
	fmt.Fprintln(w, "  --include-environment  Include only inventory-backed endpoints in this environment; may be repeated")
	fmt.Fprintln(w, "  --include-tag          Include only inventory-backed endpoints with this tag; may be repeated")
	fmt.Fprintln(w, "  -o, --output   Write Markdown report output to this path")
	fmt.Fprintln(w, "  -j, --json     Write canonical JSON report output to this path")
}

func printAuditUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor audit <subcommand> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Audit local or declared remote scope, preserving the current inventory-first and TLS-only verified-scanner boundaries.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  local     Audit local endpoints by chaining discovery into supported TLS scanning")
	fmt.Fprintln(w, "  remote    Audit declared remote scope from CIDR, host-list or inventory inputs")
	fmt.Fprintln(w, "  subnet    CIDR-only compatibility alias for remote audit from v0.4.x")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'surveyor audit local --help' for local audit help.")
	fmt.Fprintln(w, "Run 'surveyor audit remote --help' for canonical remote audit help.")
	fmt.Fprintln(w, "Run 'surveyor audit subnet --help' for remote subnet audit help.")
}

func printDiscoverUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor discover <subcommand> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Enumerate local or declared remote scope, recording observed endpoint facts and conservative hints without verified scanner execution.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  local     Enumerate local endpoints")
	fmt.Fprintln(w, "  remote    Enumerate declared remote scope from CIDR, host-list or inventory inputs")
	fmt.Fprintln(w, "  subnet    CIDR-only compatibility alias for remote discovery from v0.4.x")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'surveyor discover local --help' for local discovery help.")
	fmt.Fprintln(w, "Run 'surveyor discover remote --help' for canonical remote discovery help.")
	fmt.Fprintln(w, "Run 'surveyor discover subnet --help' for remote subnet discovery help.")
}

func printScanUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor scan <subcommand> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Run explicit scanner-oriented inventory commands.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  tls       Scan explicit TLS targets from --config or --targets")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'surveyor scan tls --help' for flags and examples.")
}

func printAuditLocalUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor audit local [-o report.md] [-j report.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Run local discovery, select supported TLS-like endpoints conservatively and emit local audit output.")
	fmt.Fprintln(w, "  This command does not imply aggressive probing or non-TLS scanner support.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor audit local")
	fmt.Fprintln(w, "  surveyor audit local -o audit.md -j audit.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -o, --output   Write Markdown report output to this path")
	fmt.Fprintln(w, "  -j, --json     Write canonical JSON report output to this path")
}

func printAuditRemoteUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor audit remote [--cidr CIDR | --targets-file PATH | --inventory-file PATH] [--adapter NAME] [--adapter-bin PATH] [--ports 443,8443] [--profile cautious] [--dry-run] [--max-hosts N] [--max-attempts N] [-o audit.md] [-j audit.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Canonical remote audit command. It executes against CIDR-backed scope, simple file-backed host scope and structured inventory manifests.")
	fmt.Fprintln(w, "  Exactly one of --cidr, --targets-file or --inventory-file is required.")
	fmt.Fprintln(w, "  Caddyfile input auto-selects the caddy adapter when the file name is unambiguous.")
	fmt.Fprintln(w, "  This command only hands selected TLS candidates into the existing TLS scanner.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443")
	fmt.Fprintln(w, "  surveyor audit remote --targets-file approved-hosts.txt --ports 443,8443")
	fmt.Fprintln(w, "  surveyor audit remote --inventory-file inventory.yaml")
	fmt.Fprintln(w, "  surveyor audit remote --inventory-file Caddyfile")
	fmt.Fprintln(w, "  surveyor audit remote --inventory-file Caddyfile --adapter-bin /path/to/caddy")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --cidr              CIDR scope to audit, for example 10.0.0.0/24")
	fmt.Fprintln(w, "  --targets-file      Path to a newline-delimited host or IP scope file; blank lines and # comments are ignored")
	fmt.Fprintln(w, "  --inventory-file    Path to a structured imported inventory file or adapter-supported source file such as Caddyfile")
	fmt.Fprintln(w, "  --adapter           Explicit platform adapter for --inventory-file, for example caddy or kubernetes-ingress-v1")
	fmt.Fprintln(w, "  --adapter-bin       Path to an external adapter executable when the selected adapter needs one")
	fmt.Fprintln(w, "  --ports             Explicit remote ports, required for --cidr and --targets-file; overrides inventory entry ports when set")
	fmt.Fprintln(w, "  --profile           Remote pace profile: cautious, balanced or aggressive")
	fmt.Fprintln(w, "  --dry-run           Print an execution plan without performing network I/O")
	fmt.Fprintln(w, "  --max-hosts         Hard cap on expanded host count, defaulting to the command default")
	fmt.Fprintln(w, "  --max-attempts      Hard cap on expanded host:port attempts, defaulting to the command default")
	fmt.Fprintln(w, "  --max-concurrency   Maximum concurrent remote probe attempts")
	fmt.Fprintln(w, "  --timeout           Per probe or connection attempt timeout")
	fmt.Fprintln(w, "  -o, --output        Write Markdown report output to this path")
	fmt.Fprintln(w, "  -j, --json          Write canonical JSON report output to this path")
}

func printAuditSubnetUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor audit subnet --cidr 10.0.0.0/24 --ports 443,8443 [--profile cautious] [--dry-run] [-o audit.md] [-j audit.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  CIDR-only compatibility alias for remote audit from v0.4.x.")
	fmt.Fprintln(w, "  This command only accepts --cidr, not --targets-file, and only hands selected TLS candidates into the existing TLS scanner.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor audit subnet --cidr 10.0.0.0/24 --ports 443,8443")
	fmt.Fprintln(w, "  surveyor audit subnet --cidr 10.0.0.0/24 --ports 443 --profile balanced -o audit.md -j audit.json")
	fmt.Fprintln(w, "  surveyor audit subnet --cidr 10.0.0.0/24 --ports 443,8443 --dry-run")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --cidr              CIDR scope to audit, for example 10.0.0.0/24")
	fmt.Fprintln(w, "  --ports             Comma-separated explicit remote ports, for example 443,8443")
	fmt.Fprintln(w, "  --profile           Remote pace profile: cautious, balanced or aggressive")
	fmt.Fprintln(w, "  --dry-run           Print an execution plan without performing network I/O")
	fmt.Fprintln(w, "  --max-hosts         Hard cap on expanded host count, defaulting to the command default")
	fmt.Fprintln(w, "  --max-attempts      Hard cap on expanded host:port attempts, defaulting to the command default")
	fmt.Fprintln(w, "  --max-concurrency   Maximum concurrent remote probe attempts")
	fmt.Fprintln(w, "  --timeout           Per probe or connection attempt timeout")
	fmt.Fprintln(w, "  -o, --output        Write Markdown report output to this path")
	fmt.Fprintln(w, "  -j, --json          Write canonical JSON report output to this path")
}

func printDiscoverLocalUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor discover local [-o report.md] [-j report.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Enumerate local endpoints and emit discovery output.")
	fmt.Fprintln(w, "  This command does not perform active probing or verified protocol scans.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor discover local")
	fmt.Fprintln(w, "  surveyor discover local -o discovery.md -j discovery.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -o, --output   Write Markdown report output to this path")
	fmt.Fprintln(w, "  -j, --json     Write canonical JSON report output to this path")
}

func printDiscoverRemoteUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor discover remote [--cidr CIDR | --targets-file PATH | --inventory-file PATH] [--adapter NAME] [--adapter-bin PATH] [--ports 443,8443] [--profile cautious] [--dry-run] [--max-hosts N] [--max-attempts N] [-o discovery.md] [-j discovery.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Canonical remote discovery command. It executes against CIDR-backed scope, simple file-backed host scope and structured inventory manifests.")
	fmt.Fprintln(w, "  Exactly one of --cidr, --targets-file or --inventory-file is required.")
	fmt.Fprintln(w, "  Caddyfile input auto-selects the caddy adapter when the file name is unambiguous.")
	fmt.Fprintln(w, "  This command records observed reachability facts and conservative hints only; it does not run verified scanners.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443")
	fmt.Fprintln(w, "  surveyor discover remote --targets-file approved-hosts.txt --ports 443,8443")
	fmt.Fprintln(w, "  surveyor discover remote --inventory-file inventory.yaml")
	fmt.Fprintln(w, "  surveyor discover remote --inventory-file Caddyfile")
	fmt.Fprintln(w, "  surveyor discover remote --inventory-file Caddyfile --adapter-bin /path/to/caddy")
	fmt.Fprintln(w, "  surveyor discover remote --inventory-file ingress.yaml --adapter kubernetes-ingress-v1")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --cidr              CIDR scope to discover, for example 10.0.0.0/24")
	fmt.Fprintln(w, "  --targets-file      Path to a newline-delimited host or IP scope file; blank lines and # comments are ignored")
	fmt.Fprintln(w, "  --inventory-file    Path to a structured imported inventory file or adapter-supported source file such as Caddyfile")
	fmt.Fprintln(w, "  --adapter           Explicit platform adapter for --inventory-file, for example caddy or kubernetes-ingress-v1")
	fmt.Fprintln(w, "  --adapter-bin       Path to an external adapter executable when the selected adapter needs one")
	fmt.Fprintln(w, "  --ports             Explicit remote ports, required for --cidr and --targets-file; overrides inventory entry ports when set")
	fmt.Fprintln(w, "  --profile           Remote pace profile: cautious, balanced or aggressive")
	fmt.Fprintln(w, "  --dry-run           Print an execution plan without performing network I/O")
	fmt.Fprintln(w, "  --max-hosts         Hard cap on expanded host count, defaulting to the command default")
	fmt.Fprintln(w, "  --max-attempts      Hard cap on expanded host:port attempts, defaulting to the command default")
	fmt.Fprintln(w, "  --max-concurrency   Maximum concurrent remote probe attempts")
	fmt.Fprintln(w, "  --timeout           Per probe or connection attempt timeout")
	fmt.Fprintln(w, "  -o, --output        Write Markdown report output to this path")
	fmt.Fprintln(w, "  -j, --json          Write canonical JSON report output to this path")
}

func printDiscoverSubnetUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor discover subnet --cidr 10.0.0.0/24 --ports 443,8443 [--profile cautious] [--dry-run] [-o discovery.md] [-j discovery.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  CIDR-only compatibility alias for remote discovery from v0.4.x.")
	fmt.Fprintln(w, "  This command only accepts --cidr, not --targets-file, and records observed reachability facts and conservative hints only.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor discover subnet --cidr 10.0.0.0/24 --ports 443,8443")
	fmt.Fprintln(w, "  surveyor discover subnet --cidr 10.0.0.0/24 --ports 443 --profile balanced -o discovery.md -j discovery.json")
	fmt.Fprintln(w, "  surveyor discover subnet --cidr 10.0.0.0/24 --ports 443,8443 --dry-run")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --cidr              CIDR scope to discover, for example 10.0.0.0/24")
	fmt.Fprintln(w, "  --ports             Comma-separated explicit remote ports, for example 443,8443")
	fmt.Fprintln(w, "  --profile           Remote pace profile: cautious, balanced or aggressive")
	fmt.Fprintln(w, "  --dry-run           Print an execution plan without performing network I/O")
	fmt.Fprintln(w, "  --max-hosts         Hard cap on expanded host count, defaulting to the command default")
	fmt.Fprintln(w, "  --max-attempts      Hard cap on expanded host:port attempts, defaulting to the command default")
	fmt.Fprintln(w, "  --max-concurrency   Maximum concurrent remote probe attempts")
	fmt.Fprintln(w, "  --timeout           Per probe or connection attempt timeout")
	fmt.Fprintln(w, "  -o, --output        Write Markdown report output to this path")
	fmt.Fprintln(w, "  -j, --json          Write canonical JSON report output to this path")
}

func renderRemoteExecutionPlanMarkdown(commandName string, scope config.RemoteScope, supportedScanners string) string {
	var builder strings.Builder

	builder.WriteString("# Surveyor Execution Plan\n\n")
	builder.WriteString(fmt.Sprintf("- Command: %s\n", commandName))
	builder.WriteString(fmt.Sprintf("- Scope kind: remote\n"))
	builder.WriteString(fmt.Sprintf("- Input kind: %s\n", scope.InputKind))
	if scope.CIDR.IsValid() {
		builder.WriteString(fmt.Sprintf("- Scope: %s\n", scope.CIDR.String()))
	}
	if scope.TargetsFile != "" {
		builder.WriteString(fmt.Sprintf("- Targets file: %s\n", scope.TargetsFile))
	}
	if scope.InventoryFile != "" {
		builder.WriteString(fmt.Sprintf("- Inventory file: %s\n", scope.InventoryFile))
	}
	if scope.Adapter != "" {
		builder.WriteString(fmt.Sprintf("- Adapter: %s\n", scope.Adapter))
	}
	builder.WriteString(fmt.Sprintf("- Host count: %d\n", scope.HostCount))
	builder.WriteString(fmt.Sprintf("- Attempt count: %d\n", scope.AttemptCount))
	builder.WriteString(fmt.Sprintf("- Ports: %s\n", describeRemotePlanPorts(scope)))
	builder.WriteString(fmt.Sprintf("- Profile: %s\n", scope.Profile))
	builder.WriteString(fmt.Sprintf("- Max hosts: %d\n", scope.MaxHosts))
	builder.WriteString(fmt.Sprintf("- Max attempts: %d\n", scope.MaxAttempts))
	builder.WriteString(fmt.Sprintf("- Max concurrency: %d\n", scope.MaxConcurrency))
	builder.WriteString(fmt.Sprintf("- Timeout per attempt: %s\n", scope.Timeout))
	builder.WriteString("- Network I/O: disabled (dry run)\n")
	builder.WriteString(fmt.Sprintf("- Supported scanners: %s\n", supportedScanners))

	return builder.String()
}

func localReportScopeMetadata() *core.ReportScope {
	return &core.ReportScope{
		ScopeKind: core.ReportScopeKindLocal,
	}
}

func explicitReportScopeMetadata(configPath string, targetsArg string) *core.ReportScope {
	scope := &core.ReportScope{
		ScopeKind: core.ReportScopeKindExplicit,
	}

	switch {
	case strings.TrimSpace(configPath) != "":
		scope.InputKind = core.ReportInputKindConfig
	case strings.TrimSpace(targetsArg) != "":
		scope.InputKind = core.ReportInputKindTargets
	}

	return scope
}

func remoteReportMetadata(scope config.RemoteScope) (*core.ReportScope, *core.ReportExecution) {
	cidr := ""
	if scope.CIDR.IsValid() {
		cidr = scope.CIDR.String()
	}

	return &core.ReportScope{
			ScopeKind:     core.ReportScopeKindRemote,
			InputKind:     core.ReportInputKind(scope.InputKind),
			CIDR:          cidr,
			TargetsFile:   scope.TargetsFile,
			InventoryFile: scope.InventoryFile,
			Adapter:       scope.Adapter,
			Ports:         append([]int(nil), scope.Ports...),
		}, &core.ReportExecution{
			Profile:        string(scope.Profile),
			MaxHosts:       scope.MaxHosts,
			MaxAttempts:    scope.MaxAttempts,
			AttemptCount:   scope.AttemptCount,
			MaxConcurrency: scope.MaxConcurrency,
			Timeout:        scope.Timeout.String(),
		}
}

func describeRemotePlanPorts(scope config.RemoteScope) string {
	if len(scope.Ports) > 0 {
		return joinPorts(scope.Ports)
	}
	if scope.InputKind == config.RemoteScopeInputKindInventoryFile {
		return "per-entry inventory ports"
	}

	return ""
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}

	return strings.Join(values, ",")
}

func printScanTLSUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor scan tls [--config PATH | --targets host:port,host:port] [-o report.md] [-j report.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	fmt.Fprintln(w, "  Exactly one of --config or --targets is required.")
	fmt.Fprintln(w, "  --targets requires explicit host:port entries. Config files accept explicit host and port fields.")
	fmt.Fprintln(w, "  IPv6 targets on the command line must use bracket form, for example [::1]:443.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor scan tls --config examples/targets.yaml -o report.md -j report.json")
	fmt.Fprintln(w, "  surveyor scan tls --targets 127.0.0.1:443,[::1]:8443")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -c, --config   Path to a YAML config file with explicit TLS targets")
	fmt.Fprintln(w, "  -t, --targets  Comma-separated explicit host:port targets")
	fmt.Fprintln(w, "  -o, --output   Write Markdown report output to this path")
	fmt.Fprintln(w, "  -j, --json     Write canonical JSON report output to this path")
}
