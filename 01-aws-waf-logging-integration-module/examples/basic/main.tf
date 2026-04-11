provider "aws" {
  region = "us-east-1"
}

module "waf" {
  source = "../../"

  environment  = "dev"
  resource_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890abcdef"

  # Start in count-only mode to baseline traffic before enforcing
  sensitivity_level = "low"

  tags = {
    Project = "my-app"
  }
}

output "waf_arn" {
  value = module.waf.web_acl_arn
}

output "compliance" {
  value = module.waf.compliance_summary
}
