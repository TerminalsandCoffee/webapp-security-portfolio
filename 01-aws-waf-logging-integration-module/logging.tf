# -----------------------------------------------------------------------------
# CloudWatch Log Group for WAF Logs
# AWS WAFv2 requires the log group name to start with "aws-waf-logs-"
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name_prefix}"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

# -----------------------------------------------------------------------------
# WAF Logging Configuration
# Sends all WAF decisions (allow, block, count) to CloudWatch
# -----------------------------------------------------------------------------

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.this.arn

  # Log all requests that match a rule (blocked, counted, or allowed by rule)
  # Unmatched requests that hit the default action are also logged
  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"

      condition {
        action_condition {
          action = "BLOCK"
        }
      }

      condition {
        action_condition {
          action = "COUNT"
        }
      }
    }
  }
}
