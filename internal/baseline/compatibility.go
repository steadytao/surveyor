package baseline

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/steadytao/surveyor/internal/core"
)

// Comparison records the validated relationship between a baseline report and
// a current report before any diff engine runs.
type Comparison struct {
	Baseline     ReportHeader
	Current      ReportHeader
	ScopeChanged bool
}

// ValidateCompatibility checks whether two canonical Surveyor reports can be
// compared by the first diffing release.
func ValidateCompatibility(baseline ReportHeader, current ReportHeader) (Comparison, error) {
	if err := validateDiffInput("baseline", baseline); err != nil {
		return Comparison{}, err
	}
	if err := validateDiffInput("current", current); err != nil {
		return Comparison{}, err
	}

	baselineMajor, err := schemaMajor(baseline.SchemaVersion)
	if err != nil {
		return Comparison{}, fmt.Errorf("baseline schema_version %q is invalid: %w", baseline.SchemaVersion, err)
	}
	currentMajor, err := schemaMajor(current.SchemaVersion)
	if err != nil {
		return Comparison{}, fmt.Errorf("current schema_version %q is invalid: %w", current.SchemaVersion, err)
	}

	supportedMajor, err := schemaMajor(core.CurrentSchemaVersion)
	if err != nil {
		return Comparison{}, fmt.Errorf("current schema version %q is invalid: %w", core.CurrentSchemaVersion, err)
	}
	if baselineMajor != supportedMajor {
		return Comparison{}, fmt.Errorf("baseline schema major %d is unsupported: this build supports schema major %d", baselineMajor, supportedMajor)
	}
	if currentMajor != supportedMajor {
		return Comparison{}, fmt.Errorf("current schema major %d is unsupported: this build supports schema major %d", currentMajor, supportedMajor)
	}
	if baselineMajor != currentMajor {
		return Comparison{}, fmt.Errorf("schema major mismatch: baseline=%q current=%q", baseline.SchemaVersion, current.SchemaVersion)
	}

	if baseline.ReportKind != current.ReportKind {
		return Comparison{}, fmt.Errorf("report kind mismatch: baseline=%q current=%q", baseline.ReportKind, current.ReportKind)
	}
	if baseline.ScopeKind != current.ScopeKind {
		return Comparison{}, fmt.Errorf("scope kind mismatch: baseline=%q current=%q", baseline.ScopeKind, current.ScopeKind)
	}

	return Comparison{
		Baseline:     baseline,
		Current:      current,
		ScopeChanged: scopesDiffer(baseline.Scope, current.Scope),
	}, nil
}

func validateDiffInput(label string, header ReportHeader) error {
	switch header.ReportKind {
	case core.ReportKindTLSScan:
		if header.ScopeKind != core.ReportScopeKindExplicit {
			return fmt.Errorf("%s tls_scan report must use scope_kind explicit", label)
		}
	case core.ReportKindAudit:
		if header.ScopeKind != core.ReportScopeKindLocal && header.ScopeKind != core.ReportScopeKindRemote {
			return fmt.Errorf("%s audit report must use scope_kind local or remote", label)
		}
	case core.ReportKindDiscovery:
		return fmt.Errorf("%s report_kind %q is not supported for diffing yet", label, header.ReportKind)
	case core.ReportKindDiff, core.ReportKindPrioritization:
		return fmt.Errorf("%s report_kind %q cannot be used as a diff input", label, header.ReportKind)
	default:
		return fmt.Errorf("%s report_kind %q is not supported for diffing", label, header.ReportKind)
	}

	return nil
}

func schemaMajor(version string) (int, error) {
	head, _, _ := strings.Cut(version, ".")
	if head == "" {
		return 0, fmt.Errorf("missing major version")
	}

	major, err := strconv.Atoi(head)
	if err != nil {
		return 0, fmt.Errorf("parse major version: %w", err)
	}
	if major < 0 {
		return 0, fmt.Errorf("major version must not be negative")
	}

	return major, nil
}

func scopesDiffer(left *core.ReportScope, right *core.ReportScope) bool {
	switch {
	case left == nil && right == nil:
		return false
	case left == nil || right == nil:
		return true
	}

	if left.ScopeKind != right.ScopeKind ||
		left.InputKind != right.InputKind ||
		left.CIDR != right.CIDR ||
		left.TargetsFile != right.TargetsFile ||
		left.InventoryFile != right.InventoryFile {
		return true
	}

	leftPorts := append([]int(nil), left.Ports...)
	rightPorts := append([]int(nil), right.Ports...)
	sort.Ints(leftPorts)
	sort.Ints(rightPorts)

	return !slices.Equal(leftPorts, rightPorts)
}
