# Adapter: Kubernetes

This document defines the planned `v0.9.0` Kubernetes adapter boundary.

It does not describe current shipped behaviour.

## External references

Implementation should be grounded in Kubernetes' official documentation:

- Ingress concept docs
- Ingress v1 API reference
- Service docs
- Secret docs
- Ingress controller docs

Those sources define the meaning of the input. Surveyor should map that meaning
into its canonical imported-inventory model rather than copying Kubernetes'
resource model into the rest of the codebase.

## First supported source

The first Kubernetes source should be Ingress v1 manifests:

- `apiVersion: networking.k8s.io/v1`
- `kind: Ingress`

That is the right first target because Ingress is the stable HTTP and HTTPS
entry-point object and maps cleanly enough to externally meaningful remote
inventory targets.

## Related resources

Services and Secrets matter to interpretation, but they should remain secondary
context in the first version.

Specifically:

- Service references help explain backend ports and exposure shape
- Secret references help explain TLS intent and provenance

Neither should become the primary imported-target identity in the first
adapter slice.

## What Surveyor should extract

The adapter should extract conservatively:

- `spec.rules[].host`
- `spec.tls[].hosts[]`
- namespace and object identity
- `ingressClassName` where present
- referenced Service names and ports as provenance or hints
- referenced TLS Secret names as provenance or hints

## Controller caveat

Ingress semantics are controller-dependent.

Surveyor should preserve that uncertainty rather than flattening it away. The
adapter should not imply that an Ingress object alone proves effective exposure
or uniform behaviour across controllers.

## Warning cases

Warnings should be explicit when:

- no clean host or TLS mapping exists
- the manifest implies HTTP routing but not clearly auditable TLS exposure
- controller-specific behaviour materially affects interpretation
- multiple manifests collapse to one imported endpoint
- Secret or Service references are present but insufficient to make stronger
  claims
