package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

// ReportHeader is the minimum canonical report envelope needed for baseline
// compatibility checks before diffing.
type ReportHeader struct {
	core.ReportMetadata
	GeneratedAt time.Time         `json:"generated_at"`
	Scope       *core.ReportScope `json:"scope,omitempty"`
}

// ReadReportHeader reads and validates the baseline-compatible report envelope
// from disk.
func ReadReportHeader(path string) (ReportHeader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ReportHeader{}, fmt.Errorf("read report %q: %w", path, err)
	}

	header, err := ParseReportHeader(data)
	if err != nil {
		return ReportHeader{}, fmt.Errorf("parse report %q: %w", path, err)
	}

	return header, nil
}

// ParseReportHeader decodes and validates the baseline-compatible report
// envelope from canonical Surveyor JSON.
func ParseReportHeader(data []byte) (ReportHeader, error) {
	var header ReportHeader

	if err := json.Unmarshal(data, &header); err != nil {
		return ReportHeader{}, fmt.Errorf("parse report JSON: %w", err)
	}

	if err := validateReportHeader(header); err != nil {
		return ReportHeader{}, err
	}

	return header, nil
}

func validateReportHeader(header ReportHeader) error {
	if header.SchemaVersion == "" {
		return fmt.Errorf("report is missing schema_version")
	}
	if header.ToolVersion == "" {
		return fmt.Errorf("report is missing tool_version")
	}
	if header.ReportKind == "" {
		return fmt.Errorf("report is missing report_kind")
	}
	if !isKnownReportKind(header.ReportKind) {
		return fmt.Errorf("unsupported report_kind %q", header.ReportKind)
	}
	if header.ScopeKind == "" {
		return fmt.Errorf("report is missing scope_kind")
	}
	if !isKnownScopeKind(header.ScopeKind) {
		return fmt.Errorf("unsupported scope_kind %q", header.ScopeKind)
	}
	if header.ScopeDescription == "" {
		return fmt.Errorf("report is missing scope_description")
	}
	if header.GeneratedAt.IsZero() {
		return fmt.Errorf("report is missing generated_at")
	}

	switch header.ReportKind {
	case core.ReportKindTLSScan, core.ReportKindDiscovery, core.ReportKindAudit:
		if header.Scope == nil {
			return fmt.Errorf("report is missing scope metadata")
		}
		if err := validateReportScope(header.ScopeKind, header.Scope); err != nil {
			return err
		}
	case core.ReportKindDiff, core.ReportKindPrioritization:
		if header.Scope != nil {
			if err := validateKnownScope(header.Scope.ScopeKind); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateReportScope(scopeKind core.ReportScopeKind, scope *core.ReportScope) error {
	if scope.ScopeKind == "" {
		return fmt.Errorf("report scope is missing scope_kind")
	}
	if scope.ScopeKind != scopeKind {
		return fmt.Errorf("report scope_kind %q does not match scope.scope_kind %q", scopeKind, scope.ScopeKind)
	}
	if err := validateKnownScope(scope.ScopeKind); err != nil {
		return err
	}

	switch scope.ScopeKind {
	case core.ReportScopeKindExplicit:
		if scope.InputKind != core.ReportInputKindConfig && scope.InputKind != core.ReportInputKindTargets {
			return fmt.Errorf("explicit report scope must use input_kind config or targets")
		}
		if scope.CIDR != "" || scope.TargetsFile != "" || scope.InventoryFile != "" || scope.Adapter != "" || len(scope.Ports) != 0 {
			return fmt.Errorf("explicit report scope must not include remote scope fields")
		}
	case core.ReportScopeKindLocal:
		if scope.InputKind != "" {
			return fmt.Errorf("local report scope must not include input_kind")
		}
		if scope.CIDR != "" || scope.TargetsFile != "" || scope.InventoryFile != "" || scope.Adapter != "" || len(scope.Ports) != 0 {
			return fmt.Errorf("local report scope must not include remote scope fields")
		}
	case core.ReportScopeKindRemote:
		switch scope.InputKind {
		case core.ReportInputKindCIDR:
			if scope.CIDR == "" {
				return fmt.Errorf("remote CIDR scope must include cidr")
			}
			if scope.TargetsFile != "" || scope.InventoryFile != "" || scope.Adapter != "" {
				return fmt.Errorf("remote CIDR scope must not include targets_file, inventory_file or adapter")
			}
			if len(scope.Ports) == 0 {
				return fmt.Errorf("remote CIDR scope must include ports")
			}
		case core.ReportInputKindTargetsFile:
			if scope.TargetsFile == "" {
				return fmt.Errorf("remote targets-file scope must include targets_file")
			}
			if scope.CIDR != "" || scope.InventoryFile != "" || scope.Adapter != "" {
				return fmt.Errorf("remote targets-file scope must not include cidr, inventory_file or adapter")
			}
			if len(scope.Ports) == 0 {
				return fmt.Errorf("remote targets-file scope must include ports")
			}
		case core.ReportInputKindInventoryFile:
			if scope.InventoryFile == "" {
				return fmt.Errorf("remote inventory-file scope must include inventory_file")
			}
			if scope.CIDR != "" || scope.TargetsFile != "" {
				return fmt.Errorf("remote inventory-file scope must not include cidr or targets_file")
			}
		default:
			return fmt.Errorf("remote report scope must use input_kind cidr, targets_file or inventory_file")
		}
	}

	return nil
}

func isKnownReportKind(kind core.ReportKind) bool {
	switch kind {
	case core.ReportKindTLSScan, core.ReportKindDiscovery, core.ReportKindAudit, core.ReportKindDiff, core.ReportKindPrioritization:
		return true
	default:
		return false
	}
}

func isKnownScopeKind(kind core.ReportScopeKind) bool {
	switch kind {
	case core.ReportScopeKindExplicit, core.ReportScopeKindLocal, core.ReportScopeKindRemote:
		return true
	default:
		return false
	}
}

func validateKnownScope(kind core.ReportScopeKind) error {
	if !isKnownScopeKind(kind) {
		return fmt.Errorf("unsupported scope.scope_kind %q", kind)
	}

	return nil
}
