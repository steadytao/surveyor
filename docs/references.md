# References

Surveyor is a standards-facing project. That means its terminology, findings and future migration guidance should be anchored to primary sources rather than loose industry shorthand.

This file is the current reference set for the TLS inventory and the next layer of work around identity and migration posture.

## Product and migration framing

### NCCoE: Migration to Post-Quantum Cryptography

<https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc>

Why it matters:
- frames the real organisational problem as discovery, inventory and prioritised migration
- aligns closely with Surveyor's thesis

### NIST IR 8547: Transition to Post-Quantum Cryptography Standards

<https://csrc.nist.gov/pubs/ir/8547/ipd>

Why it matters:
- useful source for transition language
- supports migration-posture wording rather than simplistic badge labels

### NIST Post-Quantum Cryptography project

<https://csrc.nist.gov/projects/post-quantum-cryptography>

Why it matters:
- current programme status for the PQC standardisation effort
- useful when later guidance needs to reference the standards landscape

## TLS and X.509 foundations

### RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3

<https://datatracker.ietf.org/doc/html/rfc8446>

Why it matters:
- normative baseline for modern TLS behaviour and terminology

### RFC 9325: Recommendations for Secure Use of TLS and DTLS

<https://datatracker.ietf.org/doc/html/rfc9325>

Why it matters:
- current best-current-practice source for modern versus legacy TLS posture

### RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile

<https://datatracker.ietf.org/doc/html/rfc5280>

Why it matters:
- normative source for certificate field meaning and chain terminology

### RFC 9525: Service Identity in TLS

<https://datatracker.ietf.org/doc/html/rfc9525>

Why it matters:
- correct source for hostname and service identity validation semantics

### RFC 6066: Transport Layer Security (TLS) Extensions

<https://datatracker.ietf.org/doc/html/rfc6066>

Why it matters:
- relevant for SNI and related TLS extension behaviour

## Forward-looking PQ standards

These are not yet central to the current implementation but they matter once Surveyor starts discussing concrete remediation paths or future cryptographic migration work.

### FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard

<https://csrc.nist.gov/pubs/fips/203/final>

### FIPS 204: Module-Lattice-Based Digital Signature Standard

<https://csrc.nist.gov/pubs/fips/204/final>

### SP 800-227: Recommendations for Key-Encapsulation Mechanisms

<https://csrc.nist.gov/pubs/sp/800/227/final>

## How these references should be used

Practical rules:
- use standards and NIST material for definitions and strong claims
- use code and tests to describe what Surveyor currently does
- do not present draft or experimental behaviour as settled unless the document status justifies that
- if implementation diverges from a reference, document the difference explicitly

This file is not a substitute for reading the source material. It is the minimum shared reference set the project should stay anchored to.
