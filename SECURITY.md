# Security Policy

If you believe you have found a security issue in Surveyor itself, please do not open a public issue or pull request.

Use GitHub private vulnerability reporting:
- <https://github.com/steadytao/surveyor/security/advisories/new>

If that is not suitable, email is also acceptable:
- `security@steadytao.com`

OpenPGP-encrypted email is highly preferred for sensitive matters. My public key and contact details are available at:
- <https://steadytao.com/contact/>

## What is in scope

Surveyor is a defensive inventory and reporting tool. Security reports should therefore focus on vulnerabilities in Surveyor itself, not on ordinary weaknesses in the systems being scanned.

Examples that may be in scope:
- unsafe handling of untrusted input
- unintended network behaviour caused by Surveyor
- exposure of credentials, tokens, or secrets
- trust-boundary failures
- privilege escalation in local or hosted use
- materially incorrect behaviour caused by a reproducible defect that could lead users to make unsafe decisions

The important point is that the bug needs to be in Surveyor.

## What is out of scope

The following are generally out of scope:
- vulnerabilities in scanned targets
- ordinary TLS misconfiguration or legacy cryptography discovered by Surveyor as part of its intended function
- disagreement with a classification outcome unless it is caused by a reproducible defect
- incorrect conclusions caused by incomplete visibility, middleboxes, or opaque infrastructure where Surveyor is behaving as designed
- dependency or platform issues outside this repository unless the report shows a vulnerability in how Surveyor uses them
- reports that depend on unauthorised access or abuse of third-party systems

In short, Surveyor reporting a bad TLS deployment is not itself a security bug in Surveyor.

## What makes a good report

Please keep reports practical and reproducible.

Useful reports usually include:
- affected version, commit, or branch, if known
- a short explanation of the issue and why it is a vulnerability in Surveyor
- the smallest possible reproduction
- exact commands used
- relevant config, output, logs, or traces
- expected behaviour and actual behaviour
- a patch or suggested fix, if you have one

The less guesswork required to reproduce the issue, the easier it is to verify and fix.

## Disclosure

Surveyor is a personal open-source project. There is currently no bug bounty programme.

If a report is valid and results in a fix, I will not credit you publicly unless you ask me to. If you do want credit, please say so and include the name and handle to use.
