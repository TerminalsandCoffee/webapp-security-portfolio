# Web Application Security Portfolio

Hands-on cloud and web application security projects focused on reusable infrastructure, observability, and operational security controls.

## Projects

### AWS WAFv2 Terraform Module

Located in [`project-2-waf-terraform`](./project-2-waf-terraform/), this reusable Terraform module provisions AWS WAFv2 protections with:

- AWS managed rule groups aligned to OWASP Top 10 coverage
- Rate limiting, geo-blocking, and explicit IP allow/block controls
- CloudWatch logging and dashboarding for WAF decisions
- Compliance-focused outputs showing protection coverage and enforcement state
- Environment, sensitivity, and trusted network configuration for reuse across deployments

See [`project-2-waf-terraform/README.md`](./project-2-waf-terraform/README.md) for module usage, examples, and outputs.
