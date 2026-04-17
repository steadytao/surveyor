package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/steadytao/surveyor/internal/core"
)

func TestParseWithKubernetesAdapterSimpleIngressYAML(t *testing.T) {
	t.Parallel()

	document, err := ParseWithAdapter([]byte(`
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: payments-api
  namespace: payments
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - api.example.com
      secretName: payments-api-tls
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: payments-api
                port:
                  number: 80
`), core.InventorySourceFormatYAML, "ingress.yaml", core.InventoryAdapterKubernetesIngressV1, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}

	entry := document.Entries[0]
	if got, want := entry.Host, "api.example.com"; got != want {
		t.Fatalf("entry.Host = %q, want %q", got, want)
	}
	if got, want := entry.Ports, []int{80, 443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("entry.Ports = %v, want %v", got, want)
	}
	if got, want := len(entry.Provenance), 2; got != want {
		t.Fatalf("len(entry.Provenance) = %d, want %d", got, want)
	}
	if got, want := entry.Provenance[0].Adapter, core.InventoryAdapterKubernetesIngressV1; got != want {
		t.Fatalf("entry.Provenance[0].Adapter = %q, want %q", got, want)
	}
	if got, want := entry.Provenance[0].SourceObject, "Ingress/payments/payments-api"; got != want {
		t.Fatalf("entry.Provenance[0].SourceObject = %q, want %q", got, want)
	}
	if !containsWarningCode(entry.AdapterWarnings, "ingress-controller-required") {
		t.Fatalf("entry.AdapterWarnings = %#v, want ingress-controller-required", entry.AdapterWarnings)
	}
	if containsWarningCode(entry.AdapterWarnings, "host-without-declared-tls") {
		t.Fatalf("entry.AdapterWarnings = %#v, want no host-without-declared-tls warning", entry.AdapterWarnings)
	}
}

func TestParseWithKubernetesAdapterMapsRuleOnlyHostToPort80(t *testing.T) {
	t.Parallel()

	document, err := ParseWithAdapter([]byte(`
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-http
spec:
  rules:
    - host: public.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: public-http
                port:
                  number: 80
`), core.InventorySourceFormatYAML, "ingress.yaml", core.InventoryAdapterKubernetesIngressV1, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	entry := document.Entries[0]
	if got, want := entry.Ports, []int{80}; !reflect.DeepEqual(got, want) {
		t.Fatalf("entry.Ports = %v, want %v", got, want)
	}
	if !containsWarningCode(entry.AdapterWarnings, "host-without-declared-tls") {
		t.Fatalf("entry.AdapterWarnings = %#v, want host-without-declared-tls", entry.AdapterWarnings)
	}
	if !containsWarningCode(entry.AdapterWarnings, "ingress-class-unspecified") {
		t.Fatalf("entry.AdapterWarnings = %#v, want ingress-class-unspecified", entry.AdapterWarnings)
	}
}

func TestParseWithKubernetesAdapterIgnoresNonConcreteAndHostlessRules(t *testing.T) {
	t.Parallel()

	document, err := ParseWithAdapter([]byte(`
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mixed
  namespace: default
spec:
  ingressClassName: nginx
  rules:
    - host: "*.example.com"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: wildcard
                port:
                  number: 80
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: hostless
                port:
                  number: 80
    - host: concrete.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: concrete
                port:
                  number: 80
`), core.InventorySourceFormatYAML, "ingress.yaml", core.InventoryAdapterKubernetesIngressV1, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
	entry := document.Entries[0]
	if got, want := entry.Host, "concrete.example.com"; got != want {
		t.Fatalf("entry.Host = %q, want %q", got, want)
	}
	if !containsWarningCode(entry.AdapterWarnings, "non-concrete-host-ignored") {
		t.Fatalf("entry.AdapterWarnings = %#v, want non-concrete-host-ignored", entry.AdapterWarnings)
	}
	if !containsWarningCode(entry.AdapterWarnings, "hostless-rule-ignored") {
		t.Fatalf("entry.AdapterWarnings = %#v, want hostless-rule-ignored", entry.AdapterWarnings)
	}
}

func TestParseWithKubernetesAdapterMergesDuplicateHostAcrossManifests(t *testing.T) {
	t.Parallel()

	document, err := ParseWithAdapter([]byte(`
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-http
  namespace: platform
spec:
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: public-http
                port:
                  number: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-https
  namespace: platform
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - api.example.com
      secretName: public-https-tls
`), core.InventorySourceFormatYAML, "ingress.yaml", core.InventoryAdapterKubernetesIngressV1, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
	entry := document.Entries[0]
	if got, want := entry.Ports, []int{80, 443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("entry.Ports = %v, want %v", got, want)
	}
	if got, want := len(entry.Provenance), 2; got != want {
		t.Fatalf("len(entry.Provenance) = %d, want %d", got, want)
	}
}

func TestParseWithKubernetesAdapterSupportsJSONList(t *testing.T) {
	t.Parallel()

	document, err := ParseWithAdapter([]byte(`{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {
      "apiVersion": "networking.k8s.io/v1",
      "kind": "Ingress",
      "metadata": {
        "name": "api",
        "namespace": "platform"
      },
      "spec": {
        "ingressClassName": "nginx",
        "tls": [
          {
            "hosts": ["api.example.com"]
          }
        ]
      }
    }
  ]
}`), core.InventorySourceFormatJSON, "ingress.json", core.InventoryAdapterKubernetesIngressV1, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
	if got, want := document.Entries[0].Ports, []int{443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("document.Entries[0].Ports = %v, want %v", got, want)
	}
}

func TestParseWithKubernetesAdapterRejectsUnsupportedIngressVersion(t *testing.T) {
	t.Parallel()

	_, err := ParseWithAdapter([]byte(`
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: legacy
spec:
  rules:
    - host: legacy.example.com
`), core.InventorySourceFormatYAML, "ingress.yaml", core.InventoryAdapterKubernetesIngressV1, AdapterOptions{})
	if err == nil {
		t.Fatal("ParseWithAdapter() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "requires apiVersion networking.k8s.io/v1") {
		t.Fatalf("ParseWithAdapter() error = %q, want apiVersion error", err.Error())
	}
}

func TestLoadWithKubernetesAdapterUsesRealManifestFile(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "ingress.yaml")
	if err := os.WriteFile(path, []byte(`
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api
  namespace: platform
spec:
  ingressClassName: nginx
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 80
`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	document, err := LoadWithAdapter(path, core.InventoryAdapterKubernetesIngressV1, AdapterOptions{})
	if err != nil {
		t.Fatalf("LoadWithAdapter() error = %v", err)
	}
	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
}
