# -----------------------------------------------------------------------------
# Local Values
# -----------------------------------------------------------------------------

locals {
  name_prefix = "waf-${var.environment}"

  # Rate limit scales with sensitivity
  rate_limit = {
    low    = var.rate_limit_threshold
    medium = var.rate_limit_threshold
    high   = max(500, var.rate_limit_threshold / 2) # Stricter in high mode
  }

  resource_region = split(":", var.resource_arn)[3]

  allowed_ipv4_ranges = distinct([
    for cidr in var.allowed_ip_ranges : cidr if !strcontains(cidr, ":")
  ])
  allowed_ipv6_ranges = distinct([
    for cidr in var.allowed_ip_ranges : cidr if strcontains(cidr, ":")
  ])
  blocked_ipv4_ranges = distinct([
    for cidr in var.blocked_ip_ranges : cidr if !strcontains(cidr, ":")
  ])
  blocked_ipv6_ranges = distinct([
    for cidr in var.blocked_ip_ranges : cidr if strcontains(cidr, ":")
  ])

  managed_rule_action_mode = var.sensitivity_level == "low" ? "COUNT" : "BLOCK"
  custom_rule_action_mode  = var.sensitivity_level == "low" ? "COUNT" : "BLOCK"
  geo_block_action_mode    = length(var.blocked_country_codes) > 0 ? local.custom_rule_action_mode : "DISABLED"
  rate_limit_action_mode   = local.custom_rule_action_mode
  anonymous_ip_action_mode = !var.enable_anonymous_ip_list ? "DISABLED" : var.sensitivity_level == "high" ? "BLOCK" : "COUNT"
  ip_allowlist_action_mode = length(var.allowed_ip_ranges) > 0 ? "ALLOW" : "DISABLED"
  ip_blocklist_action_mode = length(var.blocked_ip_ranges) > 0 ? "BLOCK" : "DISABLED"

  coverage_status = {
    covered = var.sensitivity_level == "low" ? "MONITORING_ONLY" : "COVERED"
    partial = var.sensitivity_level == "low" ? "PARTIAL - MONITORING_ONLY" : "PARTIAL"
  }

  # Merge user tags with module-enforced tags
  common_tags = merge(
    var.tags,
    {
      Name               = "${local.name_prefix}-webacl"
      Environment        = var.environment
      ManagedBy          = "terraform"
      Module             = "waf-security"
      SensitivityLevel   = var.sensitivity_level
      DataClassification = var.data_classification
    },
    var.owner != "" ? { Owner = var.owner } : {},
    var.cost_center != "" ? { CostCenter = var.cost_center } : {},
  )
}

# -----------------------------------------------------------------------------
# IP Sets
# -----------------------------------------------------------------------------

resource "aws_wafv2_ip_set" "allowed_ipv4" {
  count              = length(local.allowed_ipv4_ranges) > 0 ? 1 : 0
  name               = "${local.name_prefix}-allowed-ipv4"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = local.allowed_ipv4_ranges
  tags               = local.common_tags
}

resource "aws_wafv2_ip_set" "allowed_ipv6" {
  count              = length(local.allowed_ipv6_ranges) > 0 ? 1 : 0
  name               = "${local.name_prefix}-allowed-ipv6"
  scope              = "REGIONAL"
  ip_address_version = "IPV6"
  addresses          = local.allowed_ipv6_ranges
  tags               = local.common_tags
}

resource "aws_wafv2_ip_set" "blocked_ipv4" {
  count              = length(local.blocked_ipv4_ranges) > 0 ? 1 : 0
  name               = "${local.name_prefix}-blocked-ipv4"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = local.blocked_ipv4_ranges
  tags               = local.common_tags
}

resource "aws_wafv2_ip_set" "blocked_ipv6" {
  count              = length(local.blocked_ipv6_ranges) > 0 ? 1 : 0
  name               = "${local.name_prefix}-blocked-ipv6"
  scope              = "REGIONAL"
  ip_address_version = "IPV6"
  addresses          = local.blocked_ipv6_ranges
  tags               = local.common_tags
}

# -----------------------------------------------------------------------------
# Web ACL
# -----------------------------------------------------------------------------

resource "aws_wafv2_web_acl" "this" {
  name        = "${local.name_prefix}-webacl"
  description = "WAF WebACL for ${var.environment} - Sensitivity: ${var.sensitivity_level}"
  scope       = "REGIONAL"

  default_action {
    dynamic "allow" {
      for_each = var.default_action == "allow" ? [1] : []
      content {}
    }
    dynamic "block" {
      for_each = var.default_action == "block" ? [1] : []
      content {}
    }
  }

  # -------------------------------------------------------------------------
  # Rule 1: IPv4 Allowlist (highest priority — bypass all other rules)
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = length(local.allowed_ipv4_ranges) > 0 ? [1] : []
    content {
      name     = "AllowTrustedIPv4"
      priority = 0

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowed_ipv4[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-allow-ipv4"
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 2: IPv6 Allowlist
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = length(local.allowed_ipv6_ranges) > 0 ? [1] : []
    content {
      name     = "AllowTrustedIPv6"
      priority = 1

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowed_ipv6[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-allow-ipv6"
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 3: IPv4 Blocklist
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = length(local.blocked_ipv4_ranges) > 0 ? [1] : []
    content {
      name     = "BlockDeniedIPv4"
      priority = 10

      action {
        block {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.blocked_ipv4[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-block-ipv4"
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 4: IPv6 Blocklist
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = length(local.blocked_ipv6_ranges) > 0 ? [1] : []
    content {
      name     = "BlockDeniedIPv6"
      priority = 11

      action {
        block {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.blocked_ipv6[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-block-ipv6"
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 5: Geo-Blocking
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = length(var.blocked_country_codes) > 0 ? [1] : []
    content {
      name     = "GeoBlock"
      priority = 20

      action {
        dynamic "block" {
          for_each = var.sensitivity_level != "low" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.sensitivity_level == "low" ? [1] : []
          content {}
        }
      }

      statement {
        geo_match_statement {
          country_codes = var.blocked_country_codes
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-geo-block"
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 6: Rate Limiting
  # -------------------------------------------------------------------------
  rule {
    name     = "RateLimit"
    priority = 30

    action {
      dynamic "block" {
        for_each = var.sensitivity_level != "low" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.sensitivity_level == "low" ? [1] : []
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit              = local.rate_limit[var.sensitivity_level]
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # -------------------------------------------------------------------------
  # Rule 7: AWS Common Rule Set (OWASP core protections)
  # Covers: XSS, SQLi, path traversal, file inclusion, request size
  # -------------------------------------------------------------------------
  rule {
    name     = "AWSCommonRuleSet"
    priority = 100

    override_action {
      dynamic "none" {
        for_each = var.sensitivity_level != "low" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.sensitivity_level == "low" ? [1] : []
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # -------------------------------------------------------------------------
  # Rule 8: SQL Injection Rule Set
  # Dedicated SQLi detection beyond what CommonRuleSet provides
  # -------------------------------------------------------------------------
  rule {
    name     = "AWSSQLiRuleSet"
    priority = 101

    override_action {
      dynamic "none" {
        for_each = var.sensitivity_level != "low" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.sensitivity_level == "low" ? [1] : []
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-sqli-rules"
      sampled_requests_enabled   = true
    }
  }

  # -------------------------------------------------------------------------
  # Rule 9: Known Bad Inputs (Log4j, Java deserialization, etc.)
  # -------------------------------------------------------------------------
  rule {
    name     = "AWSKnownBadInputs"
    priority = 102

    override_action {
      dynamic "none" {
        for_each = var.sensitivity_level != "low" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.sensitivity_level == "low" ? [1] : []
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # -------------------------------------------------------------------------
  # Rule 10: Amazon IP Reputation List
  # Blocks IPs known for malicious activity (botnets, scanners, etc.)
  # -------------------------------------------------------------------------
  rule {
    name     = "AWSIPReputationList"
    priority = 103

    override_action {
      dynamic "none" {
        for_each = var.sensitivity_level != "low" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.sensitivity_level == "low" ? [1] : []
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  # -------------------------------------------------------------------------
  # Rule 11: Anonymous IP List (VPN/Tor/hosting providers)
  # WARNING: Disabled by default — see variable description for rationale
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = var.enable_anonymous_ip_list ? [1] : []
    content {
      name     = "AWSAnonymousIPList"
      priority = 104

      override_action {
        # Always count in low mode; in medium, count as well (conservative);
        # only block in high mode since this rule is prone to false positives
        dynamic "none" {
          for_each = var.sensitivity_level == "high" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.sensitivity_level != "high" ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesAnonymousIpList"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-anonymous-ip"
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # WebACL Visibility Config
  # -------------------------------------------------------------------------
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-webacl"
    sampled_requests_enabled   = true
  }

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# WebACL Association
# Attaches the WAF to the provided resource (ALB, API Gateway, etc.)
# -----------------------------------------------------------------------------

resource "aws_wafv2_web_acl_association" "this" {
  resource_arn = var.resource_arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}
