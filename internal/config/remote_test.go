package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseSubnetScopeDefaults(t *testing.T) {
	t.Parallel()

	scope, err := ParseSubnetScope(SubnetScopeInput{
		CIDR:   "10.0.0.23/24",
		Ports:  "8443,443,443",
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("ParseSubnetScope() error = %v", err)
	}

	if got, want := scope.CIDR.String(), "10.0.0.0/24"; got != want {
		t.Fatalf("scope.CIDR = %q, want %q", got, want)
	}
	if got, want := scope.Profile, RemoteProfileCautious; got != want {
		t.Fatalf("scope.Profile = %q, want %q", got, want)
	}
	if got, want := scope.Ports, []int{443, 8443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Ports = %v, want %v", got, want)
	}
	if got, want := scope.MaxHosts, defaultRemoteMaxHosts; got != want {
		t.Fatalf("scope.MaxHosts = %d, want %d", got, want)
	}
	if got, want := scope.HostCount, 256; got != want {
		t.Fatalf("scope.HostCount = %d, want %d", got, want)
	}
	if got, want := scope.MaxConcurrency, 8; got != want {
		t.Fatalf("scope.MaxConcurrency = %d, want %d", got, want)
	}
	if got, want := scope.Timeout, 3*time.Second; got != want {
		t.Fatalf("scope.Timeout = %s, want %s", got, want)
	}
	if !scope.DryRun {
		t.Fatal("scope.DryRun = false, want true")
	}
}

func TestParseSubnetScopeOverrides(t *testing.T) {
	t.Parallel()

	scope, err := ParseSubnetScope(SubnetScopeInput{
		CIDR:           "10.0.0.0/25",
		Ports:          "9443,443",
		Profile:        "balanced",
		MaxHosts:       512,
		MaxConcurrency: 12,
		Timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ParseSubnetScope() error = %v", err)
	}

	if got, want := scope.Profile, RemoteProfileBalanced; got != want {
		t.Fatalf("scope.Profile = %q, want %q", got, want)
	}
	if got, want := scope.Ports, []int{443, 9443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Ports = %v, want %v", got, want)
	}
	if got, want := scope.MaxHosts, 512; got != want {
		t.Fatalf("scope.MaxHosts = %d, want %d", got, want)
	}
	if got, want := scope.HostCount, 128; got != want {
		t.Fatalf("scope.HostCount = %d, want %d", got, want)
	}
	if got, want := scope.MaxConcurrency, 12; got != want {
		t.Fatalf("scope.MaxConcurrency = %d, want %d", got, want)
	}
	if got, want := scope.Timeout, 5*time.Second; got != want {
		t.Fatalf("scope.Timeout = %s, want %s", got, want)
	}
}

func TestParseSubnetScopeProfileDefaults(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		profile            string
		wantProfile        RemoteProfile
		wantMaxConcurrency int
		wantTimeout        time.Duration
	}{
		{
			name:               "cautious",
			profile:            "cautious",
			wantProfile:        RemoteProfileCautious,
			wantMaxConcurrency: 8,
			wantTimeout:        3 * time.Second,
		},
		{
			name:               "balanced",
			profile:            "balanced",
			wantProfile:        RemoteProfileBalanced,
			wantMaxConcurrency: 24,
			wantTimeout:        2 * time.Second,
		},
		{
			name:               "aggressive",
			profile:            "aggressive",
			wantProfile:        RemoteProfileAggressive,
			wantMaxConcurrency: 64,
			wantTimeout:        1 * time.Second,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			scope, err := ParseSubnetScope(SubnetScopeInput{
				CIDR:    "10.0.0.0/24",
				Ports:   "443",
				Profile: testCase.profile,
			})
			if err != nil {
				t.Fatalf("ParseSubnetScope() error = %v", err)
			}

			if got, want := scope.Profile, testCase.wantProfile; got != want {
				t.Fatalf("scope.Profile = %q, want %q", got, want)
			}
			if got, want := scope.MaxConcurrency, testCase.wantMaxConcurrency; got != want {
				t.Fatalf("scope.MaxConcurrency = %d, want %d", got, want)
			}
			if got, want := scope.Timeout, testCase.wantTimeout; got != want {
				t.Fatalf("scope.Timeout = %s, want %s", got, want)
			}
		})
	}
}

func TestParseSubnetScopeInvalidInput(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       SubnetScopeInput
		wantErrText string
	}{
		{
			name: "missing scope",
			input: SubnetScopeInput{
				Ports: "443",
			},
			wantErrText: "one of --cidr or --targets-file is required",
		},
		{
			name: "both scope inputs",
			input: SubnetScopeInput{
				CIDR:        "10.0.0.0/24",
				TargetsFile: "approved-targets.txt",
				Ports:       "443",
			},
			wantErrText: "use either --cidr or --targets-file, not both",
		},
		{
			name: "targets file deferred",
			input: SubnetScopeInput{
				TargetsFile: "approved-targets.txt",
				Ports:       "443",
			},
			wantErrText: "--targets-file is not supported yet",
		},
		{
			name: "invalid cidr",
			input: SubnetScopeInput{
				CIDR:  "10.0.0.0/99",
				Ports: "443",
			},
			wantErrText: "invalid --cidr",
		},
		{
			name: "missing ports",
			input: SubnetScopeInput{
				CIDR: "10.0.0.0/24",
			},
			wantErrText: "--ports is required",
		},
		{
			name: "blank port entry",
			input: SubnetScopeInput{
				CIDR:  "10.0.0.0/24",
				Ports: "443, ,8443",
			},
			wantErrText: "--ports[1] must not be empty",
		},
		{
			name: "non numeric port",
			input: SubnetScopeInput{
				CIDR:  "10.0.0.0/24",
				Ports: "443,https",
			},
			wantErrText: "--ports[1] must be numeric",
		},
		{
			name: "port out of range",
			input: SubnetScopeInput{
				CIDR:  "10.0.0.0/24",
				Ports: "70000",
			},
			wantErrText: "--ports[0] must be between 1 and 65535",
		},
		{
			name: "invalid profile",
			input: SubnetScopeInput{
				CIDR:    "10.0.0.0/24",
				Ports:   "443",
				Profile: "reckless",
			},
			wantErrText: "invalid --profile",
		},
		{
			name: "negative max hosts",
			input: SubnetScopeInput{
				CIDR:     "10.0.0.0/24",
				Ports:    "443",
				MaxHosts: -1,
			},
			wantErrText: "--max-hosts must not be negative",
		},
		{
			name: "negative max concurrency",
			input: SubnetScopeInput{
				CIDR:           "10.0.0.0/24",
				Ports:          "443",
				MaxConcurrency: -1,
			},
			wantErrText: "--max-concurrency must not be negative",
		},
		{
			name: "negative timeout",
			input: SubnetScopeInput{
				CIDR:    "10.0.0.0/24",
				Ports:   "443",
				Timeout: -1 * time.Second,
			},
			wantErrText: "--timeout must not be negative",
		},
		{
			name: "scope exceeds max hosts",
			input: SubnetScopeInput{
				CIDR:     "10.0.0.0/24",
				Ports:    "443",
				MaxHosts: 64,
			},
			wantErrText: "exceeds --max-hosts=64",
		},
		{
			name: "host count too large",
			input: SubnetScopeInput{
				CIDR:  "2001:db8::/64",
				Ports: "443",
			},
			wantErrText: "host count is too large to support",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseSubnetScope(testCase.input)
			if err == nil {
				t.Fatal("ParseSubnetScope() error = nil, want non-nil")
			}

			if !strings.Contains(err.Error(), testCase.wantErrText) {
				t.Fatalf("ParseSubnetScope() error = %q, want substring %q", err.Error(), testCase.wantErrText)
			}
		})
	}
}
