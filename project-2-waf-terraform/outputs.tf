# -----------------------------------------------------------------------------
# Resource Outputs
# -----------------------------------------------------------------------------

output "web_acl_arn" {
  description = "ARN of the WAF WebACL"
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "ID of the WAF WebACL"
  value       = aws_wafv2_web_acl.this.id
}

output "web_acl_capacity" {
  description = "WCU (Web ACL Capacity Units) consumed by this WebACL"
  value       = aws_wafv2_web_acl.this.capacity
}

output "log_group_arn" {
  description = "ARN of the CloudWatch Log Group for WAF logs"
  value       = aws_cloudwatch_log_group.waf.arn
}

output "log_group_name" {
  description = "Name of the CloudWatch Log Group for WAF logs"
  value       = aws_cloudwatch_log_group.waf.name
}

# -----------------------------------------------------------------------------
# Compliance Summary
# Maps each active WAF rule to the OWASP Top 10 (2021) categories it covers
# Run: terraform output -json compliance_summary
# -----------------------------------------------------------------------------

output "compliance_summary" {
  description = "OWASP Top 10 coverage matrix for active WAF rules"
  value = {
    owasp_coverage = {
      "A01:2021 - Broken Access Control" = {
        covered_by = compact([
          "AWSCommonRuleSet (${lower(local.managed_rule_action_mode)} mode; path traversal, file inclusion)",
          "RateLimit (${lower(local.rate_limit_action_mode)} mode; brute force mitigation)",
          length(var.blocked_country_codes) > 0 ? "GeoBlock (${lower(local.geo_block_action_mode)} mode; geographic restrictions)" : "",
        ])
        status = local.coverage_status.covered
      }
      "A02:2021 - Cryptographic Failures" = {
        covered_by = ["Not applicable at WAF layer (TLS/encryption is infrastructure-level)"]
        status     = "N/A - Infrastructure Layer"
      }
      "A03:2021 - Injection" = {
        covered_by = [
          "AWSCommonRuleSet (${lower(local.managed_rule_action_mode)} mode; XSS, command injection)",
          "AWSSQLiRuleSet (${lower(local.managed_rule_action_mode)} mode; SQL injection)",
          "AWSKnownBadInputs (${lower(local.managed_rule_action_mode)} mode; Log4Shell, JNDI injection)",
        ]
        status = local.coverage_status.covered
      }
      "A04:2021 - Insecure Design" = {
        covered_by = ["Not applicable at WAF layer (requires application architecture changes)"]
        status     = "N/A - Application Layer"
      }
      "A05:2021 - Security Misconfiguration" = {
        covered_by = [
          "AWSCommonRuleSet (${lower(local.managed_rule_action_mode)} mode; blocks admin path probing)",
          "AWSKnownBadInputs (${lower(local.managed_rule_action_mode)} mode; blocks known exploit payloads)",
        ]
        status = local.coverage_status.partial
      }
      "A06:2021 - Vulnerable and Outdated Components" = {
        covered_by = [
          "AWSKnownBadInputs (${lower(local.managed_rule_action_mode)} mode; Log4Shell CVE-2021-44228, Spring4Shell)",
        ]
        status = local.coverage_status.partial
      }
      "A07:2021 - Identification and Authentication Failures" = {
        covered_by = [
          "RateLimit (${lower(local.rate_limit_action_mode)} mode; credential stuffing / brute force mitigation)",
          "AWSIPReputationList (${lower(local.managed_rule_action_mode)} mode; known botnet IPs)",
        ]
        status = local.coverage_status.partial
      }
      "A08:2021 - Software and Data Integrity Failures" = {
        covered_by = ["AWSKnownBadInputs (${lower(local.managed_rule_action_mode)} mode; deserialization attack patterns)"]
        status     = local.coverage_status.partial
      }
      "A09:2021 - Security Logging and Monitoring Failures" = {
        covered_by = [
          "CloudWatch WAF Logging (full request decision records)",
          "CloudWatch Dashboard (real-time visibility)",
        ]
        status = "COVERED"
      }
      "A10:2021 - Server-Side Request Forgery (SSRF)" = {
        covered_by = [
          "AWSCommonRuleSet (${lower(local.managed_rule_action_mode)} mode; blocks common SSRF patterns in headers/body)",
        ]
        status = local.coverage_status.partial
      }
    }

    sensitivity_level = var.sensitivity_level
    environment       = var.environment
    operating_mode    = var.sensitivity_level == "low" ? "BASELINING" : "ENFORCING"
    rule_actions = {
      managed_rule_groups = local.managed_rule_action_mode
      rate_limit          = local.rate_limit_action_mode
      geo_block           = local.geo_block_action_mode
      anonymous_ip_list   = local.anonymous_ip_action_mode
      ip_allowlists       = local.ip_allowlist_action_mode
      ip_blocklists       = local.ip_blocklist_action_mode
    }
    notes = compact([
      var.sensitivity_level == "low" ? "Managed rule groups, geo match rules, and rate limiting are running in COUNT mode for baselining." : "",
      length(var.allowed_ip_ranges) > 0 || length(var.blocked_ip_ranges) > 0 ? "Explicit IP allowlists and blocklists remain enforcing in every sensitivity level." : "",
      var.enable_anonymous_ip_list && var.sensitivity_level != "high" ? "AWSAnonymousIPList is enabled in COUNT mode until high sensitivity." : "",
    ])
    rules_active = compact([
      "AWSCommonRuleSet (${local.managed_rule_action_mode})",
      "AWSSQLiRuleSet (${local.managed_rule_action_mode})",
      "AWSKnownBadInputs (${local.managed_rule_action_mode})",
      "AWSIPReputationList (${local.managed_rule_action_mode})",
      var.enable_anonymous_ip_list ? "AWSAnonymousIPList (${local.anonymous_ip_action_mode})" : "",
      "RateLimit (${local.rate_limit_action_mode})",
      length(var.blocked_country_codes) > 0 ? "GeoBlock (${local.geo_block_action_mode})" : "",
      length(local.allowed_ipv4_ranges) > 0 ? "IPAllowlist IPv4 (ALLOW)" : "",
      length(local.allowed_ipv6_ranges) > 0 ? "IPAllowlist IPv6 (ALLOW)" : "",
      length(local.blocked_ipv4_ranges) > 0 ? "IPBlocklist IPv4 (BLOCK)" : "",
      length(local.blocked_ipv6_ranges) > 0 ? "IPBlocklist IPv6 (BLOCK)" : "",
    ])
  }
}
