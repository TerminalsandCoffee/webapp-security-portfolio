# AWS WAF + Logging Integration Module

Reusable Terraform module that provisions AWS WAFv2 with comprehensive OWASP Top 10 protection, rate limiting, geo-blocking, IP reputation filtering, and full CloudWatch observability.

Designed for enterprise environments where operational visibility, phased rollout, and reusable security controls matter.

## Features

- **8 rule groups** covering OWASP Top 10 attack categories
- **3 sensitivity levels** (`low`/`medium`/`high`) for phased deployment
- **IPv4/IPv6 allowlist/blocklist** for trusted networks and known threats
- **Geo-blocking** by country code
- **Rate limiting** with sensitivity-aware thresholds
- **CloudWatch logging** with configurable retention
- **CloudWatch dashboard** with blocked/allowed metrics, per-rule breakdown, and log insights
- **Enterprise tagging** (environment, owner, cost center, data classification)
- **Compliance output** — `terraform output compliance_summary` shows OWASP coverage and enforcement state

## Usage

### Minimal (dev/staging — count mode for baselining)

```hcl
module "waf" {
  source = "./01-aws-waf-logging-integration-module"

  environment       = "dev"
  sensitivity_level = "low"
  resource_arn      = aws_lb.main.arn
}
```

### Production (full enforcement)

```hcl
module "waf" {
  source = "./01-aws-waf-logging-integration-module"

  environment          = "production"
  sensitivity_level    = "high"
  resource_arn         = aws_lb.main.arn
  rate_limit_threshold = 1000

  allowed_ip_ranges     = ["10.0.0.0/8", "172.16.0.0/12", "2001:db8:100::/48"]
  blocked_ip_ranges     = ["198.51.100.0/24", "2001:db8:ffff::/48"]
  blocked_country_codes = ["KP", "IR", "SY", "CU"]

  enable_anonymous_ip_list = true
  log_retention_days       = 365

  owner               = "security-team"
  cost_center          = "SEC-001"
  data_classification  = "confidential"

  tags = {
    Project         = "customer-portal"
    ComplianceScope = "hipaa,soc2"
  }
}
```

See [`examples/`](examples/) for complete working configurations.

## Sensitivity Levels

| Level | Managed Rules | Custom Rules | AnonymousIPList | Rate Limit |
|---|---|---|---|---|
| `low` | Count only | Count only | Count only | Default threshold |
| `medium` | Block | Block | Count only | Default threshold |
| `high` | Block | Block | Block | 50% of threshold |

**Recommended rollout**: Deploy at `low` for 1-2 weeks to baseline traffic, review CloudWatch logs for false positives, then promote to `medium`, then `high`.

**Important**: Explicit IP allowlists and blocklists always enforce, even in `low` mode. The compliance output marks managed, geo, and rate protections as monitoring-only while baselining.

## Anonymous IP List — Operational Note

The `AWSManagedRulesAnonymousIpList` rule group is **disabled by default** (`enable_anonymous_ip_list = false`).

This rule blocks traffic from VPNs, Tor exit nodes, and hosting providers. While effective against automated attacks, it **will cause false positives** in environments where:

- Developers use corporate VPNs for remote work
- CI/CD pipelines run from cloud-hosted runners (GitHub Actions, GitLab CI)
- Partners connect through hosting provider IP ranges

**Recommendation**: Enable only after reviewing traffic patterns in `low` mode. Even at `medium` sensitivity, this rule runs in count-only mode — it only blocks at `high`.

## Inputs

| Variable | Type | Default | Description |
|---|---|---|---|
| `environment` | string | — (required) | `dev`, `staging`, or `production` |
| `resource_arn` | string | — (required) | ARN of the regional resource to protect |
| `sensitivity_level` | string | `"medium"` | `low`, `medium`, or `high` |
| `default_action` | string | `"allow"` | Default action when no rules match |
| `rate_limit_threshold` | number | `2000` | Max requests per 5-min window per IP |
| `allowed_ip_ranges` | list(string) | `[]` | IPv4 or IPv6 CIDRs to always allow |
| `blocked_ip_ranges` | list(string) | `[]` | IPv4 or IPv6 CIDRs to always block |
| `blocked_country_codes` | list(string) | `[]` | ISO country codes to block |
| `enable_anonymous_ip_list` | bool | `false` | Enable VPN/Tor blocking (see note above) |
| `log_retention_days` | number | `90` | CloudWatch log retention |
| `enable_dashboard` | bool | `true` | Create CloudWatch dashboard |
| `tags` | map(string) | `{}` | Additional tags for all resources |
| `owner` | string | `""` | Owner tag for billing/compliance |
| `cost_center` | string | `""` | Cost center tag |
| `data_classification` | string | `"internal"` | `public`, `internal`, `confidential`, `restricted` |

## Outputs

| Output | Description |
|---|---|
| `web_acl_arn` | ARN of the WAF WebACL |
| `web_acl_id` | ID of the WAF WebACL |
| `web_acl_capacity` | WCU consumed |
| `log_group_arn` | CloudWatch Log Group ARN |
| `log_group_name` | CloudWatch Log Group name |
| `compliance_summary` | OWASP Top 10 coverage matrix with monitoring/enforcement state (JSON) |

## Compliance

See [compliance-matrix.md](compliance-matrix.md) for the full OWASP Top 10 mapping with Imperva Cloud WAF equivalents.

## Portfolio Context

This project is the infrastructure and integration foundation of the portfolio. It is meant to pair with a future WAF analytics project and an incident triage project so the overall repo demonstrates deployment, monitoring, and response workflows together.

## Requirements

| Name | Version |
|---|---|
| Terraform | >= 1.5.0 |
| AWS Provider | >= 5.0.0 |
