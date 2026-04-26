# Expert Review Framework

## Purpose

Major Boundary Probe decisions should be reviewed with explicit domain weighting instead of gut feel.

This framework is for build governance. It is not a customer-facing feature.

## Review Domains

### Network Engineering

Weight: `40%`

Owns:
- diagnostic validity
- signal selection
- confidence thresholds
- false-positive and false-negative risk
- when a rule is strong enough to claim a boundary

### Support / Operations

Weight: `25%`

Owns:
- usefulness of remediation steps
- usefulness of escalation output
- whether the guidance matches what real support flows need
- whether the tool helps a user make a credible case

### Privacy / Security

Weight: `20%`

Owns:
- what data is collected
- what data is stored
- what data may leave the machine
- redaction standards
- abuse and safety concerns for public workflows

### Product / UX

Weight: `15%`

Owns:
- workflow clarity
- user comprehension
- friction in the diagnostic flow
- whether the product encourages safe next actions

## What Requires Review

The following changes should not be treated as casual implementation details:
- new diagnostic collectors
- new or revised confidence rules
- new boundary classes
- automatic remediation recommendations
- upload or sharing behavior
- public-hosted workflow changes
- new escalation templates

## Decision Rule

A major change is approved only when:
- network engineering signs off, and
- at least one of support/operations or privacy/security also signs off

This prevents attractive but unreliable features from shipping.

## Review Prompts

Every major decision should be written up in a short review note answering:

1. What user problem does this change solve?
2. What evidence supports the rule or workflow?
3. What could make this wrong?
4. What data is collected, stored, or transmitted?
5. When should the tool say `inconclusive` instead?

## Confidence Discipline

The review panel must reject any rule that:
- claims high confidence without repeated or boundary-specific evidence
- hides uncertainty in polished language
- recommends actions that create meaningful user risk without strong evidence

## Suggested External Reviewers

Ideal reviewers are:
- one practicing network engineer
- one support or operations person who handles real escalations
- one privacy or security-minded reviewer

These do not all need to be formal advisors at the start, but the roles should exist.

## Working Practice

For now, every major design decision should produce:
- a short written proposal
- a provisional weighted recommendation
- a final accepted decision in repo docs

That keeps the project honest as it grows.
