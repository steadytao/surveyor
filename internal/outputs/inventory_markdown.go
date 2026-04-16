package outputs

import (
	"fmt"
	"strings"

	"github.com/steadytao/surveyor/internal/core"
)

func renderInventoryFileScope(builder *strings.Builder, scope *core.ReportScope) {
	if scope == nil || scope.InventoryFile == "" {
		return
	}

	builder.WriteString(fmt.Sprintf("- Inventory file: %s\n", scope.InventoryFile))
}

func renderScopePorts(builder *strings.Builder, scope *core.ReportScope) {
	if scope == nil {
		return
	}
	if len(scope.Ports) > 0 {
		builder.WriteString(fmt.Sprintf("- Ports: %s\n", renderPortsList(scope.Ports)))
		return
	}
	if scope.InputKind == core.ReportInputKindInventoryFile {
		builder.WriteString("- Ports: per-entry inventory ports\n")
	}
}

func renderInventoryAnnotation(builder *strings.Builder, annotation *core.InventoryAnnotation) {
	if annotation == nil {
		return
	}

	builder.WriteString("\n#### Inventory\n\n")
	if len(annotation.Ports) > 0 {
		builder.WriteString(fmt.Sprintf("- Imported ports: %s\n", renderPortsList(annotation.Ports)))
	}
	if annotation.Name != "" {
		builder.WriteString(fmt.Sprintf("- Name: %s\n", annotation.Name))
	}
	if annotation.Owner != "" {
		builder.WriteString(fmt.Sprintf("- Owner: %s\n", annotation.Owner))
	}
	if annotation.Environment != "" {
		builder.WriteString(fmt.Sprintf("- Environment: %s\n", annotation.Environment))
	}
	if len(annotation.Tags) > 0 {
		builder.WriteString(fmt.Sprintf("- Tags: %s\n", strings.Join(annotation.Tags, ", ")))
	}
	if annotation.Notes != "" {
		builder.WriteString(fmt.Sprintf("- Notes: %s\n", annotation.Notes))
	}
	if len(annotation.Provenance) > 0 {
		builder.WriteString("- Provenance:\n")
		for _, provenance := range annotation.Provenance {
			builder.WriteString(fmt.Sprintf("  - %s\n", formatInventoryProvenance(provenance)))
		}
	}
}

func formatInventoryProvenance(provenance core.InventoryProvenance) string {
	parts := make([]string, 0, 4)
	if provenance.SourceKind != "" {
		parts = append(parts, "kind="+string(provenance.SourceKind))
	}
	if provenance.SourceFormat != "" {
		parts = append(parts, "format="+string(provenance.SourceFormat))
	}
	if provenance.SourceName != "" {
		parts = append(parts, "source="+provenance.SourceName)
	}
	if provenance.SourceRecord != "" {
		parts = append(parts, "record="+provenance.SourceRecord)
	}

	return strings.Join(parts, ", ")
}
