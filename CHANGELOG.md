# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Project 1 — WAF Rule Engine Simulator
- Planned

### Project 3 — HTTP Request Analyzer
- Planned

## [1.0.0] - 2026-04-11

### Added — Project 2: AWS WAFv2 Terraform Module
- AWS WAFv2 WebACL with 8 rule groups covering OWASP Top 10
- Managed rule groups: CommonRuleSet, SQLiRuleSet, KnownBadInputsRuleSet, AmazonIpReputationList, AnonymousIpList
- Custom rules: rate limiting, geo-blocking, IP allowlist/blocklist
- Three sensitivity levels (low/medium/high) for phased rollout
- CloudWatch logging with configurable retention
- CloudWatch dashboard with blocked/allowed metrics and log insights
- Enterprise tagging (environment, owner, cost center, data classification)
- Compliance summary output mapping rules to OWASP categories
- Compliance matrix with Imperva Cloud WAF equivalents
- Basic and full usage examples
