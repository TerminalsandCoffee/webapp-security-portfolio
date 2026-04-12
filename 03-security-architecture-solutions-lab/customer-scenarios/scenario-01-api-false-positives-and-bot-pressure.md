# Scenario 01 - API False Positives and Bot Pressure

## Customer Situation

A customer runs a public API behind an application load balancer. They recently enabled managed WAF protections and are now seeing two issues at once:

- suspicious spikes in login and search traffic from a small set of autonomous systems
- false positives affecting legitimate mobile application traffic

The customer wants to keep blocking malicious traffic without breaking normal users. They also want guidance they can share with their internal application team.

## What I Would Clarify First

- Which endpoints are generating the most blocks and counts?
- Which specific WAF rules are terminating requests?
- Is the traffic concentrated on authentication, search, checkout, or admin paths?
- Are legitimate requests failing because of request bodies, headers, encodings, or client IP reputation?
- What observability exists today: WAF logs, ALB logs, application logs, and dashboard metrics?

## Primary Risks

- Account takeover or credential stuffing on authentication endpoints
- API abuse and scraping against search or catalog endpoints
- Customer impact from false positives on legitimate mobile traffic
- Operational drift if exceptions are added too broadly without logging and expiry

## Recommended Approach

### Phase 1 - Stabilize and Observe

- Keep managed rules enabled, but move the noisy rule groups or individual rules to count mode temporarily if needed
- Preserve aggressive logging for blocked and counted requests
- Add a short-term dashboard that highlights top blocked URIs, rule IDs, client IPs, and countries
- Separate traffic by endpoint so login protections and search protections can be tuned independently

### Phase 2 - Reduce False Positives Safely

- Review sample blocked requests from legitimate mobile clients
- Add narrowly scoped exceptions based on the exact rule, path, method, and known request shape
- Avoid broad allowlists unless the traffic source is stable and well understood
- Time-box exceptions and document why they were added

### Phase 3 - Increase Targeted Protection

- Add stricter rate limiting on authentication and search endpoints
- Use IP reputation and anonymous IP controls carefully, validating impact on real customers first
- Coordinate with the application team on application-layer controls such as input validation, session protections, and abuse throttling

## What I Would Tell the Customer

The immediate goal is not to disable protection, but to separate malicious traffic from legitimate business traffic with better visibility and narrower tuning. We can keep protective coverage in place while using count mode and targeted exceptions to reduce user impact. The best long-term result comes from combining WAF controls with application-side improvements on authentication and request validation.

## Example Deliverables

- A short triage summary for security operations
- A list of top noisy rules and affected endpoints
- A recommendation table for keep, tune, or exception decisions
- A follow-up plan for moving from baseline mode to enforcement mode

## Why This Scenario Matters

This kind of conversation demonstrates architecture judgment, customer communication, and the ability to balance protection, usability, and operational visibility in a real cloud security engagement.
