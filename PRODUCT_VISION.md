# Prometheus Product Vision & Roadmap

Status: Draft
Date: 2026-06-05
Author: Stefan Carter

## What Prometheus Is

Prometheus is a bug bounty validation and reporting tool. It takes raw security scan output, filters out noise, validates real findings with evidence, and generates submission-ready reports for HackerOne and Bugcrowd.

In plain terms: it's a machine that turns scan data into paid bug reports.

## Why This Exists

Manual bug bounty workflow is slow:

1. Run scanners → 200 findings
2. Manually triage → 190 are garbage
3. Manually validate the 10 that look real → 3 actually work
4. Write report, collect evidence, format for platform → hours each

Prometheus automates steps 2-4. You still decide what to submit. But the tool does the grinding.

## Income Model

Direct: You scan targets on bug bounty programs, Prometheus validates findings, you submit reports, you get paid.

No employer. No client. No SaaS customer. Just you, the tool, and the bounty programs.

Target income:
- Baseline: 40M VND/month ($1,525) — covers living costs in Vietnam
- Sweet spot: 70M VND/month ($2,669) — comfortable with family

Bug bounty math:
- Low payout: $150–500 (info disclosure, low-impact XSS)
- Medium payout: $500–2,500 (IDOR, auth bypass, SSRF, account takeovers)
- High payout: $2,500–10,000+ (critical, RCE, chained exploits)

At an average of $500–750 per valid report:
- 40M VND = 2–3 valid reports/month
- 70M VND = 4–5 valid reports/month

This assumes you target programs that actually pay within 30–90 days.

## Target Programs

The PRD and Prometheus config already track these programs. Focus on programs that:
- Allow automated scanning (OpenSea, Tesla, SpaceX/Starlink, Bullish Exchange)
- Have clear payout ranges and fast triage
- Match Prometheus v1 bug classes (IDOR, auth bypass, SSRF, account enumeration)

## Product Roadmap

The technical implementation has 8 phases defined in PROMETHEUS_BUILD_SPEC_PRD.md. Below is the business translation — what each phase means for you, not what code gets written.

### Milestone 1: First Blood (Target: July 2026)

What this means: Prometheus works end-to-end. You run it against a real target. It finds something real. You submit it. You get paid. Any amount.

This proves the model works: tool + your review = real income.

Technical phases covered: Phase 0 (repair baseline), Phase 1 (Hermes model routing), Phase 2 (persistence), Phase 3 (candidate normalization)

Features at this milestone:
- Scan a target and ingest findings
- Automated garbage rejection (headers-only, version disclosure, etc.)
- Normalized finding storage with deduplication
- Basic validation (curl replay, response diffing)

Success metric: 1 valid report submitted and paid. Amount doesn't matter.

### Milestone 2: Consistent Pipeline (Target: October 2026)

What this means: You can scan, validate, and submit at a steady pace. Not one-off. Repeatable weekly workflow.

Technical phases covered: Phase 4 (evidence-first validation), Phase 5 (report artifact generation)

Features at this milestone:
- Structured validation with positive/negative controls
- Evidence storage tied to each finding
- Auto-generated report drafts and PoC artifacts
- Platform-specific formatting (HackerOne, Bugcrowd)

Success metric: 2+ valid reports submitted per month for 2 consecutive months.

### Milestone 3: Income Baseline (Target: January 2027)

What this means: Prometheus is your primary income driver alongside teaching. You hit 40M VND/month from bounties.

Technical phases covered: Phase 6 (TUI workflow), Phase 7 (outcome feedback loop)

Features at this milestone:
- Full pipeline managed from TUI
- Outcome tracking — accepted vs duplicate vs rejected patterns feed back into rejection rules
- The tool gets smarter as you use it

Success metric: 40M VND/month from bounties. 3+ valid reports/month. Less than 30% rejection rate on submissions.

### Milestone 4: Product Decision (Target: January 2027+)

After hitting income baseline, you have a track record and real data. Then decide:

**Option A: Keep private, scale personal income**
- More targets, more scans, higher volume
- Push toward 70M VND/month
- Tool stays yours

**Option B: SaaS product**
- Open Prometheus to other bug bounty hunters
- Monthly subscription model
- Requires support, onboarding, infrastructure

**Option C: Consulting service**
- Use Prometheus for client pentests via withapurpose.co
- Higher per-engagement revenue, but sales-heavy
- Leverages your marketing skills

Don't decide now. Build the tool, get paid, then evaluate with real data.

## What This Means for Your Time

Your current weekly capacity:
- UoPeople: ~15-20 hours/week
- Teaching: evenings/weekends (Mon/Wed free)
- Kids: constant baseline
- Prometheus: remaining available time

Until First Blood (July 2026), Prometheus is the priority during free time. LinkedIn goes quiet. Teaching continues for income. UoPeople continues on schedule.

After First Blood, if the model works, you can decide whether to reduce teaching hours and increase Prometheus time.

## What "Going Quiet Online" Means

You stop posting LinkedIn content. You keep your profile active but stop the weekly content cadence. The 1M impressions already proved you can reach a US audience. When Prometheus has results, you return with something to sell — not content about AI trends, but "I built a tool that found X bugs and earned $Y in bounties." That converts differently.

## SMART Goals Summary

1. By July 31, 2026: Submit and receive payment for at least 1 valid bug report found and validated through Prometheus.

2. By October 31, 2026: Achieve 2+ valid submissions per month for 2 consecutive months, with evidence stored and reports generated entirely through Prometheus.

3. By January 31, 2027: Earn 40M VND in a single month from bug bounties, with Prometheus as the primary validation and reporting tool.

4. By January 31, 2027: Complete UoPeople BSBA degree.

These four goals are all you need. Everything else — LinkedIn content, consulting website, SaaS features — is noise until Goal 1 is met.
