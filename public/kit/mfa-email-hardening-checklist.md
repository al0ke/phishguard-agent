# MFA & Email Hardening Checklist

**Email & Identity Hygiene Pilot** · Practical steps for Texas SMBs  
Author: Ali (al0ke) · Educational / readiness use — not a certification

Focus: anything that touches **mail**, **identity**, or **admin access**. Check items as you implement them. Adapt to Microsoft 365, Google Workspace, or your stack.

---

## 1. MFA everywhere mail and admin touch

- [ ] MFA enforced on every mailbox that can receive business email.
- [ ] MFA enforced on SSO / identity provider (Entra ID, Google, Okta, etc.).
- [ ] MFA enforced on VPN, remote desktop, and admin consoles.
- [ ] Prefer phishing-resistant options (passkeys / FIDO2 / hardware keys) for admins first.
- [ ] Block legacy auth that bypasses MFA (IMAP/POP/basic auth) where the platform allows.
- [ ] Separate day-to-day accounts from privileged admin accounts.

## 2. App passwords, OAuth grants, and session hygiene

- [ ] Inventory app passwords and revoke unused ones.
- [ ] Review OAuth / “connected apps” grants quarterly; remove stale or unknown apps.
- [ ] Require re-auth for sensitive actions (password change, MFA reset, forwarding changes).
- [ ] After a suspected phish: revoke sessions / refresh tokens for that user promptly.
- [ ] Document who can reset MFA and how identity is verified before a reset.

## 3. Forwarding rules & inbox-rules abuse

- [ ] Audit mailbox forwarding (external forward, transport rules, journaling) monthly.
- [ ] Alert or require approval for new external forwarding.
- [ ] Audit inbox rules that auto-delete, move, or forward (common BEC persistence trick).
- [ ] Restrict who can create org-wide mail flow rules.
- [ ] After a compromised account: wipe attacker-created rules and re-check forwarding.

## 4. Vendor email & payment verification

- [ ] Confirm bank / payment detail changes by a known phone number or other out-of-band channel — never from the same email thread alone.
- [ ] Keep a short list of real vendor domains used for invoices and support.
- [ ] Flag urgent “wire today,” W-9 changes, or “CEO needs gift cards” for voice verification.
- [ ] For shared boxes (ap@, billing@, info@): define who monitors and how spoof is handled.

## 5. Reporting & light process

- [ ] One clear employee path to report suspicious email.
- [ ] Managers know to paste URLs/headers into a triage tool (e.g. PhishGuard) instead of clicking live links.
- [ ] Tabletop once a quarter: suspicious email → report → MFA/session check → close the loop.

---

## Triage with PhishGuard

Paste suspicious URLs or email text into PhishGuard — do not open live phishing links in a normal browser.

- Live demo: https://phishguard-plum.vercel.app  
- Source: https://github.com/al0ke/phishguard-agent  

---

*Generic best-practice guidance. Not legal advice. Not a formal audit or certification.*
