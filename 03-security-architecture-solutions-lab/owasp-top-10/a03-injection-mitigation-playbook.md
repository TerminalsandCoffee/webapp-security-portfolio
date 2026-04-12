# A03 - Injection Mitigation Playbook

## OWASP Category

A03:2021 - Injection

## Threat Summary

Injection attacks happen when untrusted input is interpreted as commands or queries by downstream components. In modern web environments, the most common examples include:

- SQL injection
- command injection
- template injection
- header or parameter manipulation
- malicious payloads embedded in JSON bodies or query strings

## What a WAF Can Help With

A WAF can reduce exposure by detecting known malicious payload patterns before they reach the application. Useful controls include:

- managed rule groups for common web exploits
- dedicated SQL injection protections
- known-bad-input signatures
- rate limiting to reduce exploit automation
- logging and dashboards for rapid pattern identification

## What a WAF Cannot Solve Alone

A WAF should not be treated as the primary fix for injection risk. The application still needs:

- parameterized queries
- safe command execution patterns
- strict input validation
- output encoding where relevant
- secure software development and testing practices

## Recommended Control Stack

### Edge and Traffic Controls

- Enable managed WAF protections for common attack patterns
- Keep logging enabled for block and count actions
- Use rate limiting on sensitive or high-value endpoints

### Application Controls

- Parameterize all database queries
- Remove dangerous shell invocation paths where possible
- Validate and constrain payload formats at the API boundary
- Implement secure error handling so backend details are not exposed

### Detection and Operations

- Track top blocked payloads and targeted endpoints
- Review count-mode findings before enforcing new rules broadly
- Tune exceptions narrowly and document expiration criteria
- Correlate WAF telemetry with application logs for root cause analysis

## Architecture Guidance

If a customer asks whether a WAF is enough for injection protection, the answer should be no. The correct guidance is defense in depth: use the WAF to reduce exploit traffic and improve visibility, but require application-layer fixes to meaningfully reduce risk.

## Customer-Facing Summary

WAF protections are valuable for quickly reducing common injection traffic, especially during rollout or while application changes are being planned. They are most effective when paired with secure coding controls, good logging, and a disciplined tuning process that balances protection with false-positive management.
