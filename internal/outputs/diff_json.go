package outputs

import (
	"encoding/json"
	"fmt"

	diffreport "github.com/steadytao/surveyor/internal/diff"
)

// MarshalDiffJSON serialises a diff report as stable, indented JSON.
func MarshalDiffJSON(report diffreport.Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal diff report JSON: %w", err)
	}

	return append(data, '\n'), nil
}
