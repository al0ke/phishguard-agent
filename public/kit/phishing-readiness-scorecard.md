# Phishing Readiness Scorecard

**Email & Identity Hygiene Pilot** · 10-minute self-score for Texas SMBs (<250 employees)  
Author: Ali (al0ke)

**How to use:** For each row, mark **0** (not in place), **1** (partial), or **2** (in place and used). Add the three section totals. This is a **self-assessment worksheet** — not a certification, not a lab grade, and not a compliance attestation.

---

## A. Controls (max 16)

| # | Control | Score (0–2) | Notes |
|---|---------|-------------|-------|
| 1 | MFA on email / SSO for all users | | |
| 2 | MFA on admin / privileged accounts (prefer phishing-resistant) | | |
| 3 | Legacy auth that bypasses MFA is blocked or tightly limited | | |
| 4 | External forwarding & inbox rules are audited | | |
| 5 | Suspicious email reporting path exists and is known | | |
| 6 | Ability to paste URLs/email into a triage tool (e.g. PhishGuard) before clicking | | |
| 7 | Vendor payment / bank-change verification is out-of-band | | |
| 8 | Stale app passwords / OAuth grants are reviewed | | |

**Controls subtotal:** ______ / 16

---

## B. People (max 10)

| # | People practice | Score (0–2) | Notes |
|---|-----------------|-------------|-------|
| 1 | New hires get a short “how to report phish” brief | | |
| 2 | Staff know not to approve unexpected MFA prompts | | |
| 3 | Finance / AP know the voice-verify rule for payment changes | | |
| 4 | Admins use separate accounts for admin work | | |
| 5 | Someone owns mailbox compromise response (reset MFA, kill sessions, check rules) | | |

**People subtotal:** ______ / 10

---

## C. Process (max 10)

| # | Process | Score (0–2) | Notes |
|---|---------|-------------|-------|
| 1 | Written steps for “employee reported a phish” | | |
| 2 | Quarterly mini-tabletop or walkthrough (even 30 minutes) | | |
| 3 | After an incident: capture 1–3 improvements and assign an owner | | |
| 4 | Access review for leavers / role changes includes mail + MFA | | |
| 5 | Leadership knows who to call for identity / email emergencies | | |

**Process subtotal:** ______ / 10

---

## Totals (self-score only)

| Section | Score | Max |
|---------|-------|-----|
| Controls | | 16 |
| People | | 10 |
| Process | | 10 |
| **Overall** | | **36** |

### Rough reading (guidance only — not a rating badge)

| Overall | Rough signal |
|---------|----------------|
| 0–12 | High exposure — start with MFA, reporting path, and forwarding audits |
| 13–24 | Partial — close gaps on admin MFA, vendor verify, and triage habit |
| 25–36 | Stronger baseline — keep rehearsing and reviewing grants/rules |

No score here means you are “certified,” “compliant,” or “safe harbor ready.” It only shows where to focus next.

---

## Next step with PhishGuard

Try a live URL/email paste triage: https://phishguard-plum.vercel.app  
Repo: https://github.com/al0ke/phishguard-agent  

For a structured 5-business-day walkthrough, see the **Email & Identity Hygiene Pilot** on `/kit`.

---

*Self-score worksheet by Ali (al0ke). Not legal advice. Not a certification.*
