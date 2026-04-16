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
	"time"

	auditflow "github.com/steadytao/surveyor/internal/audit"
	"github.com/steadytao/surveyor/internal/baseline"
	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
	diffreport "github.com/steadytao/surveyor/internal/diff"
	"github.com/steadytao/surveyor/internal/discovery"
	"github.com/steadytao/surveyor/internal/outputs"
	"github.com/steadytao/surveyor/internal/scanners/tlsinventory"
)

type auditRunner interface {
	Run(context.Context) ([]core.AuditResult, error)
}

type discoverer interface {
	Enumerate(context.Context) ([]core.DiscoveredEndpoint, error)
}

// Package-level factories keep the CLI entrypoint thin while still letting
// tests replace the real runners and discoverers without wiring a bespoke
// dependency graph through main.
var newLocalAuditRunner = func(now func() time.Time) auditRunner {
	return auditflow.LocalRunner{
		TLSScanner: tlsinventory.Scanner{Now: now},
	}
}

var newRemoteAuditRunner = func(scope config.RemoteScope, now func() time.Time) auditRunner {
	return auditflow.RemoteRunner{
		Scope:      scope,
		TLSScanner: tlsinventory.Scanner{Now: now, Timeout: scope.Timeout},
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

	markdownPath := fs.String("output", "", "Write Markdown output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown output to this path")

	jsonPath := fs.String("json", "", "Write JSON output to this path")
	fs.StringVar(jsonPath, "j", "", "Write JSON output to this path")

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

	diffNow := now
	if diffNow == nil {
		diffNow = time.Now
	}

	report, err := buildDiffReportFromFiles(baselinePath, currentPath, diffNow().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "diff: %v\n", err)
		return 1
	}

	return writeDiffOutputs(report, stdout, stderr, *markdownPath, *jsonPath)
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

	markdownPath := fs.String("output", "", "Write Markdown output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown output to this path")

	jsonPath := fs.String("json", "", "Write JSON output to this path")
	fs.StringVar(jsonPath, "j", "", "Write JSON output to this path")

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

	results := make([]core.TargetResult, 0, len(targets))
	for _, target := range targets {
		results = append(results, scanner.ScanTarget(context.Background(), target))
	}

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

func runDiscoverLocal(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	fs := flag.NewFlagSet("surveyor discover local", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		printDiscoverLocalUsage(stderr)
	}

	markdownPath := fs.String("output", "", "Write Markdown output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown output to this path")

	jsonPath := fs.String("json", "", "Write JSON output to this path")
	fs.StringVar(jsonPath, "j", "", "Write JSON output to this path")

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
		commandName:      "discover remote",
		printUsage:       printDiscoverRemoteUsage,
		allowTargetsFile: true,
	})
}

func runDiscoverSubnet(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	return runRemoteDiscoveryCommand(args, stdout, stderr, now, remoteCommandOptions{
		commandName:      "discover subnet",
		printUsage:       printDiscoverSubnetUsage,
		allowTargetsFile: false,
	})
}

type remoteCommandOptions struct {
	commandName      string
	printUsage       func(io.Writer)
	allowTargetsFile bool
}

func runRemoteDiscoveryCommand(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time, opts remoteCommandOptions) int {
	fs := flag.NewFlagSet(opts.commandName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		opts.printUsage(stderr)
	}

	cidr := fs.String("cidr", "", "CIDR scope to discover, for example 10.0.0.0/24")
	var targetsFile *string
	if opts.allowTargetsFile {
		targetsFile = fs.String("targets-file", "", "Path to a newline-delimited host or IP scope file")
	}
	ports := fs.String("ports", "", "Comma-separated explicit remote ports, for example 443,8443")
	profile := fs.String("profile", "", "Remote pace profile: cautious, balanced or aggressive")
	dryRun := fs.Bool("dry-run", false, "Print the execution plan without performing network I/O")
	maxHosts := fs.Int("max-hosts", 0, "Hard cap on expanded host count, defaulting to the profile-safe command default")
	maxConcurrency := fs.Int("max-concurrency", 0, "Maximum concurrent remote probe attempts")
	timeout := fs.Duration("timeout", 0, "Per probe or connection attempt timeout")

	markdownPath := fs.String("output", "", "Write Markdown output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown output to this path")

	jsonPath := fs.String("json", "", "Write JSON output to this path")
	fs.StringVar(jsonPath, "j", "", "Write JSON output to this path")

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

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		CIDR:           *cidr,
		TargetsFile:    targetsFileValue,
		Ports:          *ports,
		Profile:        *profile,
		MaxHosts:       *maxHosts,
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

	markdownPath := fs.String("output", "", "Write Markdown output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown output to this path")

	jsonPath := fs.String("json", "", "Write JSON output to this path")
	fs.StringVar(jsonPath, "j", "", "Write JSON output to this path")

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
		commandName:      "audit remote",
		printUsage:       printAuditRemoteUsage,
		allowTargetsFile: true,
	})
}

func runAuditSubnet(args []string, stdout io.Writer, stderr io.Writer, now func() time.Time) int {
	return runRemoteAuditCommand(args, stdout, stderr, now, remoteCommandOptions{
		commandName:      "audit subnet",
		printUsage:       printAuditSubnetUsage,
		allowTargetsFile: false,
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
	if opts.allowTargetsFile {
		targetsFile = fs.String("targets-file", "", "Path to a newline-delimited host or IP scope file")
	}
	ports := fs.String("ports", "", "Comma-separated explicit remote ports, for example 443,8443")
	profile := fs.String("profile", "", "Remote pace profile: cautious, balanced or aggressive")
	dryRun := fs.Bool("dry-run", false, "Print the execution plan without performing network I/O")
	maxHosts := fs.Int("max-hosts", 0, "Hard cap on expanded host count, defaulting to the profile-safe command default")
	maxConcurrency := fs.Int("max-concurrency", 0, "Maximum concurrent remote probe attempts")
	timeout := fs.Duration("timeout", 0, "Per probe or connection attempt timeout")

	markdownPath := fs.String("output", "", "Write Markdown output to this path")
	fs.StringVar(markdownPath, "o", "", "Write Markdown output to this path")

	jsonPath := fs.String("json", "", "Write JSON output to this path")
	fs.StringVar(jsonPath, "j", "", "Write JSON output to this path")

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

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		CIDR:           *cidr,
		TargetsFile:    targetsFileValue,
		Ports:          *ports,
		Profile:        *profile,
		MaxHosts:       *maxHosts,
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

func buildDiffReportFromFiles(baselinePath string, currentPath string, generatedAt time.Time) (diffreport.Report, error) {
	baselineHeader, baselineData, err := readDiffInputFile(baselinePath)
	if err != nil {
		return diffreport.Report{}, err
	}
	currentHeader, currentData, err := readDiffInputFile(currentPath)
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

		return diffreport.BuildTLSReport(baselineReport, currentReport, generatedAt)
	case core.ReportKindAudit:
		baselineReport, err := decodeAuditReport(baselinePath, baselineData)
		if err != nil {
			return diffreport.Report{}, err
		}
		currentReport, err := decodeAuditReport(currentPath, currentData)
		if err != nil {
			return diffreport.Report{}, err
		}

		return diffreport.BuildAuditReport(baselineReport, currentReport, generatedAt)
	default:
		return diffreport.Report{}, fmt.Errorf("report_kind %q is not supported for diffing", baselineHeader.ReportKind)
	}
}

func readDiffInputFile(path string) (baseline.ReportHeader, []byte, error) {
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
		case arg == "-o" || arg == "--output" || arg == "-j" || arg == "--json":
			if index+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a value", arg)
			}
			flags = append(flags, arg, args[index+1])
			index += 1
		case strings.HasPrefix(arg, "--output=") || strings.HasPrefix(arg, "--json="):
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
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor diff baseline.json current.json [-o diff.md] [-j diff.json]")
	fmt.Fprintln(w, "  surveyor audit local [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor audit remote [--cidr CIDR | --targets-file PATH] --ports 443,8443 [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor audit subnet --cidr 10.0.0.0/24 --ports 443,8443 [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor discover local [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor discover remote [--cidr CIDR | --targets-file PATH] --ports 443,8443 [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor discover subnet --cidr 10.0.0.0/24 --ports 443,8443 [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor scan tls [--config PATH | --targets host:port,host:port] [-o report.md] [-j report.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  diff            Compare two compatible Surveyor JSON reports and emit Markdown and optional JSON output")
	fmt.Fprintln(w, "  audit local     Audit local endpoints by chaining discovery into supported scanners")
	fmt.Fprintln(w, "  audit remote    Audit declared remote scope across CIDR and file-backed host inputs")
	fmt.Fprintln(w, "  audit subnet    CIDR-only compatibility alias for remote audit during v0.5.x")
	fmt.Fprintln(w, "  discover local  Enumerate local endpoints and emit Markdown and optional JSON output")
	fmt.Fprintln(w, "  discover remote Enumerate declared remote scope across CIDR and file-backed host inputs")
	fmt.Fprintln(w, "  discover subnet CIDR-only compatibility alias for remote discovery during v0.5.x")
	fmt.Fprintln(w, "  scan tls        Scan explicit TLS targets and emit Markdown and optional JSON output")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'surveyor audit local --help' for audit-specific help.")
	fmt.Fprintln(w, "Run 'surveyor audit remote --help' for canonical remote audit help.")
	fmt.Fprintln(w, "Run 'surveyor audit subnet --help' for subnet audit help.")
	fmt.Fprintln(w, "Run 'surveyor diff --help' for diff help.")
	fmt.Fprintln(w, "Run 'surveyor discover local --help' for discovery-specific help.")
	fmt.Fprintln(w, "Run 'surveyor discover remote --help' for canonical remote discovery help.")
	fmt.Fprintln(w, "Run 'surveyor discover subnet --help' for subnet discovery help.")
	fmt.Fprintln(w, "Run 'surveyor scan tls --help' for command-specific help.")
}

func printDiffUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor diff baseline.json current.json [-o diff.md] [-j diff.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scope:")
	fmt.Fprintln(w, "  Compare two compatible canonical Surveyor JSON reports.")
	fmt.Fprintln(w, "  The first release supports tls_scan-to-tls_scan and audit-to-audit comparisons only.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor diff baseline.json current.json")
	fmt.Fprintln(w, "  surveyor diff baseline.json current.json -o diff.md -j diff.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -o, --output   Write Markdown output to this path")
	fmt.Fprintln(w, "  -j, --json     Write JSON output to this path")
}

func printAuditUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor audit local [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor audit remote [--cidr CIDR | --targets-file PATH] --ports 443,8443 [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor audit subnet --cidr 10.0.0.0/24 --ports 443,8443 [-o report.md] [-j report.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'surveyor audit local --help' for local audit help.")
	fmt.Fprintln(w, "Run 'surveyor audit remote --help' for canonical remote audit help.")
	fmt.Fprintln(w, "Run 'surveyor audit subnet --help' for remote subnet audit help.")
}

func printDiscoverUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor discover local [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor discover remote [--cidr CIDR | --targets-file PATH] --ports 443,8443 [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "  surveyor discover subnet --cidr 10.0.0.0/24 --ports 443,8443 [-o report.md] [-j report.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'surveyor discover local --help' for local discovery help.")
	fmt.Fprintln(w, "Run 'surveyor discover remote --help' for canonical remote discovery help.")
	fmt.Fprintln(w, "Run 'surveyor discover subnet --help' for remote subnet discovery help.")
}

func printScanUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor scan tls [--config PATH | --targets host:port,host:port] [-o report.md] [-j report.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'surveyor scan tls --help' for flags and examples.")
}

func printAuditLocalUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor audit local [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "Scope:")
	fmt.Fprintln(w, "  Run local discovery, select supported TLS-like endpoints conservatively and emit local audit output.")
	fmt.Fprintln(w, "  This command does not imply aggressive probing or non-TLS scanner support.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor audit local")
	fmt.Fprintln(w, "  surveyor audit local -o audit.md -j audit.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -o, --output   Write Markdown output to this path")
	fmt.Fprintln(w, "  -j, --json     Write JSON output to this path")
}

func printAuditRemoteUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor audit remote [--cidr CIDR | --targets-file PATH] --ports 443,8443 [--profile cautious] [--dry-run] [-o audit.md] [-j audit.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scope:")
	fmt.Fprintln(w, "  Canonical remote audit command. It executes against CIDR-backed scope and simple file-backed host scope.")
	fmt.Fprintln(w, "  This command only hands selected TLS candidates into the existing TLS scanner.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor audit remote --cidr 10.0.0.0/24 --ports 443,8443")
	fmt.Fprintln(w, "  surveyor audit remote --targets-file approved-hosts.txt --ports 443,8443")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --cidr              CIDR scope to audit, for example 10.0.0.0/24")
	fmt.Fprintln(w, "  --targets-file      Path to a newline-delimited host or IP scope file")
	fmt.Fprintln(w, "  --ports             Comma-separated explicit remote ports, for example 443,8443")
	fmt.Fprintln(w, "  --profile           Remote pace profile: cautious, balanced or aggressive")
	fmt.Fprintln(w, "  --dry-run           Print the execution plan without performing network I/O")
	fmt.Fprintln(w, "  --max-hosts         Hard cap on expanded host count, defaulting to the command default")
	fmt.Fprintln(w, "  --max-concurrency   Maximum concurrent remote probe attempts")
	fmt.Fprintln(w, "  --timeout           Per probe or connection attempt timeout")
	fmt.Fprintln(w, "  -o, --output        Write Markdown output to this path")
	fmt.Fprintln(w, "  -j, --json          Write JSON output to this path")
}

func printAuditSubnetUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor audit subnet --cidr 10.0.0.0/24 --ports 443,8443 [--profile cautious] [--dry-run] [-o audit.md] [-j audit.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scope:")
	fmt.Fprintln(w, "  CIDR-only compatibility alias for remote audit during v0.5.x.")
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
	fmt.Fprintln(w, "  --dry-run           Print the execution plan without performing network I/O")
	fmt.Fprintln(w, "  --max-hosts         Hard cap on expanded host count, defaulting to the command default")
	fmt.Fprintln(w, "  --max-concurrency   Maximum concurrent remote probe attempts")
	fmt.Fprintln(w, "  --timeout           Per probe or connection attempt timeout")
	fmt.Fprintln(w, "  -o, --output        Write Markdown output to this path")
	fmt.Fprintln(w, "  -j, --json          Write JSON output to this path")
}

func printDiscoverLocalUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor discover local [-o report.md] [-j report.json]")
	fmt.Fprintln(w, "Scope:")
	fmt.Fprintln(w, "  Enumerate local endpoints and emit discovery output.")
	fmt.Fprintln(w, "  This command does not perform active probing or verified protocol scans.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor discover local")
	fmt.Fprintln(w, "  surveyor discover local -o discovery.md -j discovery.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -o, --output   Write Markdown output to this path")
	fmt.Fprintln(w, "  -j, --json     Write JSON output to this path")
}

func printDiscoverRemoteUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor discover remote [--cidr CIDR | --targets-file PATH] --ports 443,8443 [--profile cautious] [--dry-run] [-o discovery.md] [-j discovery.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scope:")
	fmt.Fprintln(w, "  Canonical remote discovery command. It executes against CIDR-backed scope and simple file-backed host scope.")
	fmt.Fprintln(w, "  This command records observed reachability facts and conservative hints only; it does not run verified scanners.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor discover remote --cidr 10.0.0.0/24 --ports 443,8443")
	fmt.Fprintln(w, "  surveyor discover remote --targets-file approved-hosts.txt --ports 443,8443")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --cidr              CIDR scope to discover, for example 10.0.0.0/24")
	fmt.Fprintln(w, "  --targets-file      Path to a newline-delimited host or IP scope file")
	fmt.Fprintln(w, "  --ports             Comma-separated explicit remote ports, for example 443,8443")
	fmt.Fprintln(w, "  --profile           Remote pace profile: cautious, balanced or aggressive")
	fmt.Fprintln(w, "  --dry-run           Print the execution plan without performing network I/O")
	fmt.Fprintln(w, "  --max-hosts         Hard cap on expanded host count, defaulting to the command default")
	fmt.Fprintln(w, "  --max-concurrency   Maximum concurrent remote probe attempts")
	fmt.Fprintln(w, "  --timeout           Per probe or connection attempt timeout")
	fmt.Fprintln(w, "  -o, --output        Write Markdown output to this path")
	fmt.Fprintln(w, "  -j, --json          Write JSON output to this path")
}

func printDiscoverSubnetUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  surveyor discover subnet --cidr 10.0.0.0/24 --ports 443,8443 [--profile cautious] [--dry-run] [-o discovery.md] [-j discovery.json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scope:")
	fmt.Fprintln(w, "  CIDR-only compatibility alias for remote discovery during v0.5.x.")
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
	fmt.Fprintln(w, "  --dry-run           Print the execution plan without performing network I/O")
	fmt.Fprintln(w, "  --max-hosts         Hard cap on expanded host count, defaulting to the command default")
	fmt.Fprintln(w, "  --max-concurrency   Maximum concurrent remote probe attempts")
	fmt.Fprintln(w, "  --timeout           Per probe or connection attempt timeout")
	fmt.Fprintln(w, "  -o, --output        Write Markdown output to this path")
	fmt.Fprintln(w, "  -j, --json          Write JSON output to this path")
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
	builder.WriteString(fmt.Sprintf("- Host count: %d\n", scope.HostCount))
	builder.WriteString(fmt.Sprintf("- Ports: %s\n", joinPorts(scope.Ports)))
	builder.WriteString(fmt.Sprintf("- Profile: %s\n", scope.Profile))
	builder.WriteString(fmt.Sprintf("- Max hosts: %d\n", scope.MaxHosts))
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
	return &core.ReportScope{
			ScopeKind:   core.ReportScopeKindRemote,
			InputKind:   core.ReportInputKind(scope.InputKind),
			CIDR:        scope.CIDR.String(),
			TargetsFile: scope.TargetsFile,
			Ports:       append([]int(nil), scope.Ports...),
		}, &core.ReportExecution{
			Profile:        string(scope.Profile),
			MaxHosts:       scope.MaxHosts,
			MaxConcurrency: scope.MaxConcurrency,
			Timeout:        scope.Timeout.String(),
		}
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
	fmt.Fprintln(w, "Input:")
	fmt.Fprintln(w, "  Exactly one of --config or --targets is required.")
	fmt.Fprintln(w, "  --targets requires explicit host:port entries.")
	fmt.Fprintln(w, "  IPv6 targets must use bracket form, for example [::1]:443.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  surveyor scan tls --config examples/targets.yaml -o report.md -j report.json")
	fmt.Fprintln(w, "  surveyor scan tls --targets 127.0.0.1:443,[::1]:8443")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -c, --config   Path to a YAML config file with explicit TLS targets")
	fmt.Fprintln(w, "  -t, --targets  Comma-separated explicit host:port targets")
	fmt.Fprintln(w, "  -o, --output   Write Markdown output to this path")
	fmt.Fprintln(w, "  -j, --json     Write JSON output to this path")
}
