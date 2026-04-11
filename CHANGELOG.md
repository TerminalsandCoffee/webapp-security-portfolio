# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed — Portfolio Structure
- Renamed the Terraform project folder to `01-aws-waf-logging-integration-module`
- Reframed the portfolio around three role-aligned cloud security projects

### Project 2 — Smart WAF Analyzer
- Planned

### Project 3 — Security Architecture Solutions Lab
- Planned

## [1.0.0] - 2026-04-11

### Added — Project 1: AWS WAF + Logging Integration Module
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
