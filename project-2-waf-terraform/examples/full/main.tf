provider "aws" {
  region = "us-east-1"
}

module "waf" {
  source = "../../"

  # Environment & sensitivity
  environment       = "production"
  sensitivity_level = "high"
  resource_arn      = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/1234567890abcdef"

  # Rate limiting — strict for production
  rate_limit_threshold = 1000

  # IP controls
  allowed_ip_ranges = [
    "10.0.0.0/8",        # Internal corporate network
    "172.16.0.0/12",     # VPN egress range
    "203.0.113.0/24",    # Office public IP range
    "2001:db8:100::/48", # Corporate IPv6 range
  ]
  blocked_ip_ranges = [
    "198.51.100.0/24",    # Known malicious range (from threat intel)
    "2001:db8:ffff::/48", # Known malicious IPv6 range
  ]

  # Geo-blocking — restrict to operating regions only
  blocked_country_codes = ["KP", "IR", "SY", "CU"]

  # Anonymous IP blocking — enabled in high mode with full awareness
  # of false positive risk. Review CloudWatch logs for legitimate VPN traffic.
  enable_anonymous_ip_list = true

  # Logging
  log_retention_days = 365 # 1 year for compliance (HIPAA/SOC2)
  enable_dashboard   = true

  # Enterprise tagging
  owner               = "security-team"
  cost_center         = "SEC-001"
  data_classification = "confidential"

  tags = {
    Project         = "customer-portal"
    ComplianceScope = "hipaa,soc2"
    ChangeControl   = "CHG-2026-0142"
  }
}

output "waf_arn" {
  value = module.waf.web_acl_arn
}

output "waf_capacity" {
  value = module.waf.web_acl_capacity
}

output "compliance_summary" {
  value = module.waf.compliance_summary
}
