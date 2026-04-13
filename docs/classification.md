# Classification

Surveyor's current classification layer is conservative by design.

It does not try to answer whether a service is "quantum-safe". It answers a narrower question: based on the TLS and certificate evidence currently observed, what migration posture does this target appear to have?

If the evidence is incomplete or outside the current rule set, the correct answer is manual review, not false certainty.

## Current buckets

### `unreachable`

Meaning:
- the target could not be reached with a TLS connection

Typical trigger:
- connection failure before a usable TLS connection state exists

What it does not mean:
- that the target is non-existent
- that the target is not TLS-capable
- that the target was fully assessed

Current finding:
- `target-unreachable`

### `manual_review_required`

Meaning:
- Surveyor reached the service or observed part of it, but the available certificate evidence is incomplete or outside the recognised rule set

Typical triggers:
- no presented peer certificates
- missing leaf key or signature metadata
- an identity algorithm or signature algorithm outside the current recognised classical set

What it does not mean:
- that the target is necessarily broken
- that the target is post-quantum aware
- that Surveyor has enough evidence to classify the target more strongly

Current findings:
- `incomplete-certificate-observation`
- `unsupported-certificate-identity`

### `legacy_tls_exposure`

Meaning:
- the target negotiated a legacy TLS version and the observed certificate identity remains classical

Current legacy set:
- `SSL 3.0`
- `TLS 1.0`
- `TLS 1.1`

What it implies:
- transport posture should be prioritised before treating the service as modern

What it does not mean:
- that the service is comprehensively understood across all protocol paths

Current findings:
- `legacy-tls-version`
- `classical-certificate-identity`

### `modern_tls_classical_identity`

Meaning:
- the target negotiated a modern TLS version, but the observed certificate identity remains classical

Current modern set:
- `TLS 1.2`
- `TLS 1.3`

What it implies:
- transport posture appears modern
- certificate and PKI migration work still remains

What it does not mean:
- that the service is post-quantum ready
- that trust validation or service identity validation has been completed

Current finding:
- `classical-certificate-identity`

### `classical_certificates`

Meaning:
- the observed certificate identity remains classical, but the TLS version does not land in the current modern or legacy sets

Why this exists:
- it avoids pretending the transport posture is well-understood when the certificate posture is clearer than the negotiated version category

What it does not mean:
- that the transport layer is safe
- that the target is fully understood

Current finding:
- `classical-certificate-identity`

## Recognised algorithm sets

Current recognised classical identity algorithms:
- `rsa`
- `dsa`
- `ecdsa`
- `ed25519`

Current recognised classical signature handling:
- any normalised signature algorithm string containing `rsa`
- any normalised signature algorithm string containing `dsa`
- any normalised signature algorithm string containing `ecdsa`
- any normalised signature algorithm string containing `ed25519`

Anything outside those sets currently falls back to `manual_review_required`.

That is intentional. Surveyor should extend its rule set only when the new behaviour is understood, documented and tested.

## Current limitations

The current classifier does not yet consider:
- trust-store validation
- hostname validation
- incomplete chains beyond presented metadata
- revocation
- certificate transparency
- experimental or draft PQ / hybrid TLS behaviour
- vendor-specific transport quirks

These are real limits. A classification result should be read in light of them.

## Wording rules

Surveyor should use cautious language, for example:
- "observed"
- "appears"
- "current evidence suggests"
- "manual review required"

Surveyor should avoid stronger claims such as:
- "quantum-safe"
- "fully PQ-ready"
- "compliant"
- "secure"

Those claims require stronger evidence and broader validation than the current scanner performs.
