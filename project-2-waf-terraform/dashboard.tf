# -----------------------------------------------------------------------------
# CloudWatch Dashboard — WAF Metrics
# Provides real-time visibility into WAF decisions and attack patterns
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "waf" {
  count          = var.enable_dashboard ? 1 : 0
  dashboard_name = "${local.name_prefix}-waf-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Row 1: High-level request metrics
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Blocked vs Allowed Requests"
          region = local.resource_region
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "ALL", { stat = "Sum", color = "#d62728" }],
            ["AWS/WAFV2", "AllowedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "ALL", { stat = "Sum", color = "#2ca02c" }],
            ["AWS/WAFV2", "CountedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "ALL", { stat = "Sum", color = "#ff7f0e" }],
          ]
          view    = "timeSeries"
          stacked = false
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Block Rate (%)"
          region = local.resource_region
          metrics = [
            [{ expression = "100 * m1 / (m1 + m2)", label = "Block Rate %", id = "e1" }],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "ALL", { stat = "Sum", id = "m1", visible = false }],
            ["AWS/WAFV2", "AllowedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "ALL", { stat = "Sum", id = "m2", visible = false }],
          ]
          view   = "timeSeries"
          period = 300
          yAxis  = { left = { min = 0, max = 100 } }
        }
      },

      # Row 2: Per-rule breakdown
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Blocks by Rule Group"
          region = local.resource_region
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "${local.name_prefix}-common-rules", { stat = "Sum", label = "Common Rules" }],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "${local.name_prefix}-sqli-rules", { stat = "Sum", label = "SQLi Rules" }],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "${local.name_prefix}-known-bad-inputs", { stat = "Sum", label = "Known Bad Inputs" }],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "${local.name_prefix}-ip-reputation", { stat = "Sum", label = "IP Reputation" }],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "${local.name_prefix}-rate-limit", { stat = "Sum", label = "Rate Limit" }],
          ]
          view    = "bar"
          stacked = true
          period  = 3600
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Rate Limited Requests (5-min windows)"
          region = local.resource_region
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.this.name, "Region", local.resource_region, "Rule", "${local.name_prefix}-rate-limit", { stat = "Sum", color = "#d62728" }],
          ]
          view   = "timeSeries"
          period = 300
        }
      },

      # Row 3: Log insights
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 24
        height = 6
        properties = {
          title  = "Recent Blocked Requests (Last 1 Hour)"
          region = local.resource_region
          query  = <<-EOQ
            fields @timestamp, httpRequest.clientIp, httpRequest.uri, httpRequest.httpMethod, terminatingRuleId, action
            | filter action = "BLOCK"
            | sort @timestamp desc
            | limit 50
          EOQ
          source = [aws_cloudwatch_log_group.waf.name]
          view   = "table"
        }
      },
    ]
  })
}
