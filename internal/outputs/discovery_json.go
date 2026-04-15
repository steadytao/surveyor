package outputs

import (
	"encoding/json"
	"fmt"

	"github.com/steadytao/surveyor/internal/core"
)

// MarshalDiscoveryJSON serialises a discovery report as stable, indented JSON.
func MarshalDiscoveryJSON(report core.DiscoveryReport) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal discovery report JSON: %w", err)
	}

	return append(data, '\n'), nil
}
