# Surveyor Audit Report

- Generated: 2026-04-26T01:30:00Z
- Total endpoints: 1
- TLS candidates: 1
- Scanned endpoints: 1
- Skipped endpoints: 0

## Scope

- Scope kind: remote
- Input kind: inventory_file
- Inventory file: examples/ingress.yaml
- Adapter: kubernetes-ingress-v1
- Ports: per-entry inventory ports

## Execution

- Profile: cautious
- Max hosts: 256
- Max concurrency: 8
- Timeout per attempt: 3s

## Selection summary

- tls: 1

## Verified classification summary

- modern_tls_ready: 1

## Endpoints

### api.example.com:443/tcp

- Scope kind: remote
- Host: api.example.com
- Port: 443
- Transport: tcp
- State: responsive

#### Inventory

- Imported ports: 80,443
- Provenance:
  - kind=inventory_file, format=yaml, source=examples/ingress.yaml, record=documents[0].spec.tls[0].hosts[0], adapter=kubernetes-ingress-v1, object=Ingress/payments/payments-api
  - kind=inventory_file, format=yaml, source=examples/ingress.yaml, record=documents[0].spec.rules[0], adapter=kubernetes-ingress-v1, object=Ingress/payments/payments-api
- Adapter warnings:
  - ingress-controller-required: Ingress effective exposure and TLS behaviour depend on the ingress controller; the manifest alone does not prove live external exposure.
    - evidence: adapter=kubernetes-ingress-v1
    - evidence: source_name=examples/ingress.yaml
    - evidence: source_object=Ingress/payments/payments-api
    - evidence: source_record=documents[0]
  - ingress-class-unspecified: The Ingress manifest omits ingressClassName, so controller selection depends on cluster defaults or controller-specific behaviour.
    - evidence: adapter=kubernetes-ingress-v1
    - evidence: source_name=examples/ingress.yaml
    - evidence: source_object=Ingress/payments/payments-api
    - evidence: source_record=documents[0].spec

#### Hints

- tls (low)
  - evidence: transport=tcp
  - evidence: port=443

#### Selection

- Status: selected
- Selected scanner: tls
- Reason: tls hint on tcp/443

#### Verified TLS Result

- Classification: modern_tls_ready
- Reachable: true
- TLS version: TLS 1.3
- Cipher suite: TLS_AES_128_GCM_SHA256
- Leaf key algorithm: ecdsa
- Leaf key size: 256
- Leaf signature algorithm: ecdsa-with-SHA256
