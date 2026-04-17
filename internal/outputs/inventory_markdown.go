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
	if scope.Adapter != "" {
		builder.WriteString(fmt.Sprintf("- Adapter: %s\n", scope.Adapter))
	}
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
	if len(annotation.AdapterWarnings) > 0 {
		builder.WriteString("- Adapter warnings:\n")
		for _, warning := range annotation.AdapterWarnings {
			builder.WriteString(fmt.Sprintf("  - %s: %s\n", warning.Code, warning.Summary))
			for _, evidence := range warning.Evidence {
				builder.WriteString(fmt.Sprintf("    - evidence: %s\n", evidence))
			}
		}
	}
}

func formatInventoryProvenance(provenance core.InventoryProvenance) string {
	parts := make([]string, 0, 6)
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
	if provenance.Adapter != "" {
		parts = append(parts, "adapter="+string(provenance.Adapter))
	}
	if provenance.SourceObject != "" {
		parts = append(parts, "object="+provenance.SourceObject)
	}

	return strings.Join(parts, ", ")
}
