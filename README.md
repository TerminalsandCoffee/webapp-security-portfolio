# Web Application Security Portfolio

Hands-on cloud application security projects focused on WAF operations, observability, incident response, and customer-facing security analysis.

## Portfolio Roadmap

### 1. AWS WAF + Logging Integration Module

Located in [`01-aws-waf-logging-integration-module`](./01-aws-waf-logging-integration-module/), this reusable Terraform module provisions AWS WAFv2 protections with:

- AWS managed rule groups aligned to OWASP Top 10 coverage
- Rate limiting, geo-blocking, and explicit IPv4/IPv6 IP allow/block controls
- CloudWatch logging and dashboarding for WAF decisions
- Compliance-focused outputs showing protection coverage and enforcement state
- Environment, sensitivity, and trusted network configuration for repeatable deployments

Status: In progress

See [`01-aws-waf-logging-integration-module/README.md`](./01-aws-waf-logging-integration-module/README.md) for usage, examples, and outputs.

### 2. Smart WAF Analyzer

Located in [`02-smart-waf-analyzer`](./02-smart-waf-analyzer/).

Planned analytics project for ingesting WAF logs, summarizing attack activity, identifying likely false positives, and recommending tuning changes that an analyst or customer success engineer can act on quickly.

Status: Planned

### 3. Security Incident Triage Assistant

Located in [`03-security-incident-triage-assistant`](./03-security-incident-triage-assistant/).

Planned incident-response project for turning security alerts and log bundles into concise triage summaries, severity guidance, likely root cause, and remediation next steps for operators and customers.

Status: Planned
