package config

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/steadytao/surveyor/internal/debugassert"
)

func normalize(raw rawConfig) (Config, error) {
	if len(raw.Targets) == 0 {
		return Config{}, fmt.Errorf("config must include at least one target")
	}

	targets := make([]Target, 0, len(raw.Targets))

	for index, target := range raw.Targets {
		normalizedTarget, err := normalizeTarget(target, index)
		if err != nil {
			return Config{}, err
		}

		targets = append(targets, normalizedTarget)
	}

	config := Config{
		Targets: targets,
	}
	assertValidConfig(config)
	return config, nil
}

func normalizeTarget(target rawTarget, index int) (Target, error) {
	pathPrefix := fmt.Sprintf("targets[%d]", index)

	return normalizeTargetFields(target.Name, target.Host, target.Port, target.Tags, pathPrefix)
}

// ValidateTarget normalises one in-memory target and enforces the same rules
// used for file-backed config input.
func ValidateTarget(target Target) (Target, error) {
	return normalizeTargetFields(target.Name, target.Host, target.Port, target.Tags, "target")
}

func normalizeTargetFields(name string, host string, port int, tags []string, pathPrefix string) (Target, error) {
	trimmedHost := normalizeExplicitTargetHost(host)
	trimmedName := strings.TrimSpace(name)

	if trimmedHost == "" {
		return Target{}, fmt.Errorf("%s.host must not be empty", pathPrefix)
	}

	if port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("%s.port must be between 1 and 65535", pathPrefix)
	}

	if name != "" && trimmedName == "" {
		return Target{}, fmt.Errorf("%s.name must not be blank", pathPrefix)
	}

	normalizedTags := normalizeTags(tags)

	normalizedTarget := Target{
		Name: trimmedName,
		Host: trimmedHost,
		Port: port,
		Tags: normalizedTags,
	}
	assertValidTarget(normalizedTarget)
	return normalizedTarget, nil
}

func normalizeExplicitTargetHost(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 2 && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		if address, err := netip.ParseAddr(strings.TrimSpace(trimmed[1 : len(trimmed)-1])); err == nil {
			return address.String()
		}
	}

	return trimmed
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(tags))

	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed == "" {
			continue
		}

		normalized = append(normalized, trimmed)
	}

	if len(normalized) == 0 {
		return nil
	}

	return normalized
}

func assertValidConfig(config Config) {
	if !debugassert.Enabled {
		return
	}

	debugassert.That(len(config.Targets) > 0, "config must contain at least one target after normalisation")
	for index, target := range config.Targets {
		debugassert.That(target.Host != "", "target %d has empty host", index)
		debugassert.That(target.Port >= 1 && target.Port <= 65535, "target %d has invalid port %d", index, target.Port)
		assertNoBlankStrings(target.Tags, "target %d tag", index)
	}
}

func assertValidTarget(target Target) {
	if !debugassert.Enabled {
		return
	}

	debugassert.That(target.Host != "", "normalised target has empty host")
	debugassert.That(target.Port >= 1 && target.Port <= 65535, "normalised target has invalid port %d", target.Port)
	assertNoBlankStrings(target.Tags, "normalised target tag")
}

func assertNoBlankStrings(values []string, format string, args ...any) {
	if !debugassert.Enabled {
		return
	}

	for _, value := range values {
		debugassert.That(strings.TrimSpace(value) != "", format+" must not be blank", args...)
	}
}
