# Adapter: Kubernetes

This document defines the current Kubernetes adapter boundary for `v0.9.0`.

## External references

Implementation is grounded in Kubernetes' official documentation:

- Ingress concept docs
- Ingress v1 API reference
- Service docs
- Secret docs
- Ingress controller docs

Those sources define the meaning of the input. Surveyor maps that meaning into
its canonical imported-inventory model rather than copying Kubernetes'
resource model into the rest of the codebase.

## Current supported source

The current Kubernetes source is Ingress v1 manifests:

- `apiVersion: networking.k8s.io/v1`
- `kind: Ingress`

Supported input forms:

- YAML, including multi-document YAML
- JSON, including arrays and `List` objects

Current adapter name:

- `kubernetes-ingress-v1`

Current command example:

```bash
surveyor audit remote --inventory-file examples/ingress.yaml --adapter kubernetes-ingress-v1
```

## Related resources

Services and Secrets matter to interpretation, but they remain secondary
context in the current version.

Specifically:

- Service references help explain backend ports and exposure shape
- Secret references help explain TLS intent and provenance

Neither becomes the primary imported-target identity.

## What Surveyor extracts

The adapter extracts conservatively:

- `spec.rules[].host`
- `spec.tls[].hosts[]`
- namespace and object identity
- `ingressClassName` where present
- referenced Service names and ports as provenance or hints
- referenced TLS Secret names as provenance or hints

Current mapping:

- `spec.rules[].host` maps to port `80`
- `spec.tls[].hosts[]` maps to port `443`

## Controller caveat

Ingress semantics are controller-dependent.

Surveyor preserves that uncertainty rather than flattening it away. The
adapter does not imply that an Ingress object alone proves effective exposure
or uniform behaviour across controllers.

## Current warning cases

Warnings are explicit when:

- no clean host or TLS mapping exists
- `ingressClassName` is omitted
- the manifest implies HTTP routing but not clearly auditable TLS exposure
- controller-dependent behaviour materially affects interpretation
- multiple manifests collapse to one imported endpoint
- Secret or Service references are present but insufficient to make stronger
  claims
