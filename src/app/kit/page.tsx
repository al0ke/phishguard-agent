import type { Metadata } from 'next'
import Link from 'next/link'

export const metadata: Metadata = {
  title: 'Email & Identity Hygiene Pilot · PhishGuard',
  description:
    '5-business-day Email & Identity Hygiene Pilot for Texas SMBs — readiness kit, MFA checklist, scorecard, and SB 2610 plain-English brief by Ali (al0ke).',
}

const artifacts = [
  {
    title: 'MFA / email hardening checklist',
    desc: 'Practical SMB steps: MFA on mail and admin, app passwords, forwarding & inbox-rules abuse, vendor email verification.',
    href: '/kit/mfa-email-hardening-checklist.md',
    file: 'mfa-email-hardening-checklist.md',
  },
  {
    title: 'Phishing readiness scorecard',
    desc: 'Simple self-score across controls, people, and process — fill in about 10 minutes. Not a certification.',
    href: '/kit/phishing-readiness-scorecard.md',
    file: 'phishing-readiness-scorecard.md',
  },
  {
    title: 'SB 2610 plain-English brief',
    desc: 'High-level orientation for Texas small employers, with official Legislature links. Not legal advice.',
    href: '/kit/sb-2610-plain-english-brief.md',
    file: 'sb-2610-plain-english-brief.md',
  },
]

const forWhom = [
  {
    title: 'Texas SMBs (<250 employees)',
    desc: 'Owners and ops leads who want a short, fixed-scope email & identity hygiene walkthrough — not a year-long transform.',
  },
  {
    title: 'Lean IT / office managers',
    desc: 'Teams that own Microsoft 365 or Google Workspace and need MFA, forwarding audits, and a clear report-phish path.',
  },
  {
    title: 'MSPs supporting Texas clients',
    desc: 'Partners who want a reusable readiness kit plus live URL/email triage via PhishGuard.',
  },
]

export default function KitPage() {
  return (
    <div
      className="min-h-screen flex flex-col"
      style={{ background: 'var(--cyber-bg)', color: 'var(--text-primary)' }}
    >
      <header className="border-b flex-shrink-0" style={{ borderColor: 'var(--cyber-border)' }}>
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
          <Link href="/" className="flex items-center gap-3 min-w-0">
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{
                background: 'linear-gradient(135deg, rgba(0,40,104,0.3), rgba(0,204,255,0.1))',
                border: '1px solid var(--cyber-border)',
              }}
            >
              <span className="text-[#00ff88] font-bold text-lg">P</span>
            </div>
            <div className="min-w-0">
              <p className="text-sm font-bold tracking-tight leading-none">
                <span className="text-[#00ff88]">PhishGuard</span>
                <span style={{ color: 'var(--text-muted)' }} className="font-normal ml-2">
                  by Ali / al0ke
                </span>
              </p>
              <p className="text-xs mt-1 truncate" style={{ color: 'var(--text-muted)' }}>
                Email & Identity Hygiene Pilot
              </p>
            </div>
          </Link>
          <nav className="flex items-center gap-3 text-sm flex-shrink-0">
            <Link href="/" className="hover:text-[#00ff88] transition-colors" style={{ color: 'var(--text-secondary)' }}>
              Analyzer
            </Link>
            <a
              href="https://phishguard-plum.vercel.app"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#00ff88] transition-colors"
              style={{ color: 'var(--text-secondary)' }}
            >
              Live demo
            </a>
            <a
              href="mailto:ali@al0ke.dev?subject=Email%20%26%20Identity%20Hygiene%20Pilot%20walkthrough"
              className="px-3 py-1.5 rounded-lg bg-[#00ff88] text-black font-bold text-xs hover:opacity-90 transition-opacity"
            >
              Book a walkthrough
            </a>
          </nav>
        </div>
      </header>

      <main className="flex-1">
        {/* Hero */}
        <section className="border-b" style={{ borderColor: 'var(--cyber-border)' }}>
          <div className="max-w-5xl mx-auto px-4 py-14 md:py-20">
            <p className="text-xs uppercase tracking-widest text-[#00ccff] mb-4">
              Phishing readiness for Texas small teams
            </p>
            <h1 className="text-3xl md:text-5xl font-bold tracking-tight leading-tight mb-4">
              <span className="text-[#00ff88]">Email & Identity</span>
              <br />
              Hygiene Pilot
            </h1>
            <p className="text-base md:text-lg max-w-2xl mb-8" style={{ color: 'var(--text-secondary)' }}>
              A fixed-scope, 5-business-day readiness pilot for Texas SMBs under 250 employees —
              MFA and mailbox hygiene, a self-score scorecard, and a plain-English SB 2610 brief —
              tied to live PhishGuard URL/email triage. Built by Ali (al0ke), drawing on work with a
              Texas agency CISO office.
            </p>

            <div className="flex flex-wrap gap-3 mb-10">
              <div
                className="px-4 py-3 rounded-xl border"
                style={{ background: 'var(--cyber-card)', borderColor: 'var(--cyber-border)' }}
              >
                <p className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                  Price
                </p>
                <p className="text-xl font-bold text-[#00ff88]">~$597</p>
              </div>
              <div
                className="px-4 py-3 rounded-xl border"
                style={{ background: 'var(--cyber-card)', borderColor: 'var(--cyber-border)' }}
              >
                <p className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                  Duration
                </p>
                <p className="text-xl font-bold">5 business days</p>
              </div>
              <div
                className="px-4 py-3 rounded-xl border"
                style={{ background: 'var(--cyber-card)', borderColor: 'var(--cyber-border)' }}
              >
                <p className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                  Audience
                </p>
                <p className="text-xl font-bold">Texas SMBs &lt;250</p>
              </div>
            </div>

            <div className="flex flex-wrap gap-3">
              <a
                href="mailto:ali@al0ke.dev?subject=Email%20%26%20Identity%20Hygiene%20Pilot%20walkthrough&body=Hi%20Ali%2C%0A%0AI%27d%20like%20a%20walkthrough%20of%20the%20Email%20%26%20Identity%20Hygiene%20Pilot%20(~%24597%2C%205%20business%20days).%0A%0ACompany%3A%0AApprox.%20employees%3A%0AMail%20platform%20(M365%2FGoogle%2Fother)%3A%0A"
                className="inline-flex items-center px-5 py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm hover:opacity-90 transition-opacity"
              >
                Book a walkthrough
              </a>
              <a
                href="https://phishguard-plum.vercel.app"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center px-5 py-3 rounded-lg border text-sm font-bold hover:border-[#00ff88] hover:text-[#00ff88] transition-colors"
                style={{ borderColor: 'var(--cyber-border)' }}
              >
                Try PhishGuard demo
              </a>
              <a
                href="https://github.com/al0ke/phishguard-agent"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center px-5 py-3 rounded-lg border text-sm font-bold hover:border-[#00ccff] hover:text-[#00ccff] transition-colors"
                style={{ borderColor: 'var(--cyber-border)', color: 'var(--text-secondary)' }}
              >
                GitHub
              </a>
            </div>
          </div>
        </section>

        {/* What's included */}
        <section className="border-b" style={{ borderColor: 'var(--cyber-border)' }}>
          <div className="max-w-5xl mx-auto px-4 py-14">
            <h2 className="text-xl font-bold mb-2">
              <span className="text-[#00ff88]">What&apos;s included</span>
            </h2>
            <p className="text-sm mb-8 max-w-2xl" style={{ color: 'var(--text-secondary)' }}>
              Download the readiness artifacts free. The paid pilot is a short working engagement —
              walkthrough, scorecard review, and live triage practice with PhishGuard. No fake checkout
              here; book a conversation first.
            </p>

            <ul className="space-y-4">
              {artifacts.map((item) => (
                <li
                  key={item.file}
                  className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-4 rounded-xl border"
                  style={{ background: 'var(--cyber-card)', borderColor: 'var(--cyber-border)' }}
                >
                  <div className="min-w-0">
                    <h3 className="font-bold text-sm mb-1">{item.title}</h3>
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                      {item.desc}
                    </p>
                  </div>
                  <a
                    href={item.href}
                    download
                    className="flex-shrink-0 inline-flex items-center justify-center px-4 py-2 rounded-lg border text-xs font-bold uppercase tracking-wider text-[#00ff88] hover:bg-[#00ff88]/10 transition-colors"
                    style={{ borderColor: 'rgba(0,255,136,0.35)' }}
                  >
                    Download .md
                  </a>
                </li>
              ))}
            </ul>

            <div
              className="mt-6 p-4 rounded-xl border"
              style={{ background: 'rgba(0,204,255,0.05)', borderColor: 'rgba(0,204,255,0.25)' }}
            >
              <p className="text-sm font-bold text-[#00ccff] mb-1">PhishGuard triage demo</p>
              <p className="text-sm mb-3" style={{ color: 'var(--text-secondary)' }}>
                Paste a suspicious URL or email snippet for multi-signal analysis — practice the same
                habit the pilot reinforces. Do not open live phishing links in a normal browser.
              </p>
              <div className="flex flex-wrap gap-3 text-sm">
                <a
                  href="https://phishguard-plum.vercel.app"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[#00ccff] hover:underline"
                >
                  phishguard-plum.vercel.app
                </a>
                <span style={{ color: 'var(--text-muted)' }}>·</span>
                <a
                  href="https://github.com/al0ke/phishguard-agent"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:underline"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  github.com/al0ke/phishguard-agent
                </a>
              </div>
            </div>
          </div>
        </section>

        {/* Who it's for */}
        <section className="border-b" style={{ borderColor: 'var(--cyber-border)' }}>
          <div className="max-w-5xl mx-auto px-4 py-14">
            <h2 className="text-xl font-bold mb-2">
              <span className="text-[#00ff88]">Who it&apos;s for</span>
            </h2>
            <p className="text-sm mb-8 max-w-2xl" style={{ color: 'var(--text-secondary)' }}>
              Educational readiness — not “we hacked your competitors,” not fake case studies.
            </p>
            <div className="grid md:grid-cols-3 gap-4">
              {forWhom.map((item) => (
                <div
                  key={item.title}
                  className="p-4 rounded-xl border"
                  style={{ background: 'var(--cyber-card)', borderColor: 'var(--cyber-border)' }}
                >
                  <h3 className="font-bold text-sm mb-2">{item.title}</h3>
                  <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                    {item.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Soft CTA + placeholder form */}
        <section>
          <div className="max-w-5xl mx-auto px-4 py-14">
            <h2 className="text-xl font-bold mb-2">
              <span className="text-[#00ff88]">Book a walkthrough</span>
            </h2>
            <p className="text-sm mb-8 max-w-2xl" style={{ color: 'var(--text-secondary)' }}>
              Soft ask only — tell Ali a bit about your team. No payment form on this page. Fixed
              pilot price is about <span className="text-[#00ff88] font-bold">$597</span> for roughly{' '}
              <span className="font-bold">5 business days</span>.
            </p>

            <form
              action="mailto:ali@al0ke.dev?subject=Email%20%26%20Identity%20Hygiene%20Pilot%20walkthrough"
              method="post"
              encType="text/plain"
              className="max-w-xl space-y-4 p-5 rounded-xl border"
              style={{ background: 'var(--cyber-card)', borderColor: 'var(--cyber-border)' }}
            >
              <div>
                <label htmlFor="name" className="block text-xs uppercase tracking-widest mb-1.5" style={{ color: 'var(--text-muted)' }}>
                  Name
                </label>
                <input
                  id="name"
                  name="name"
                  type="text"
                  required
                  className="w-full px-3 py-2 rounded-lg border bg-transparent text-sm outline-none focus:border-[#00ff88]"
                  style={{ borderColor: 'var(--cyber-border)', color: 'var(--text-primary)' }}
                />
              </div>
              <div>
                <label htmlFor="company" className="block text-xs uppercase tracking-widest mb-1.5" style={{ color: 'var(--text-muted)' }}>
                  Company
                </label>
                <input
                  id="company"
                  name="company"
                  type="text"
                  className="w-full px-3 py-2 rounded-lg border bg-transparent text-sm outline-none focus:border-[#00ff88]"
                  style={{ borderColor: 'var(--cyber-border)', color: 'var(--text-primary)' }}
                />
              </div>
              <div>
                <label htmlFor="employees" className="block text-xs uppercase tracking-widest mb-1.5" style={{ color: 'var(--text-muted)' }}>
                  Approx. employees
                </label>
                <input
                  id="employees"
                  name="employees"
                  type="text"
                  placeholder="e.g. under 250"
                  className="w-full px-3 py-2 rounded-lg border bg-transparent text-sm outline-none focus:border-[#00ff88]"
                  style={{ borderColor: 'var(--cyber-border)', color: 'var(--text-primary)' }}
                />
              </div>
              <div>
                <label htmlFor="message" className="block text-xs uppercase tracking-widest mb-1.5" style={{ color: 'var(--text-muted)' }}>
                  What you want from the pilot
                </label>
                <textarea
                  id="message"
                  name="message"
                  rows={4}
                  className="w-full px-3 py-2 rounded-lg border bg-transparent text-sm outline-none focus:border-[#00ff88] resize-y"
                  style={{ borderColor: 'var(--cyber-border)', color: 'var(--text-primary)' }}
                />
              </div>
              <button
                type="submit"
                className="w-full py-3 rounded-lg bg-[#00ff88] text-black font-bold text-sm hover:opacity-90 transition-opacity"
              >
                Open email to book
              </button>
              <p className="text-xs text-center" style={{ color: 'var(--text-muted)' }}>
                Opens your mail client to reach Ali (al0ke). Prefer direct?{' '}
                <a
                  href="mailto:ali@al0ke.dev?subject=Email%20%26%20Identity%20Hygiene%20Pilot%20walkthrough"
                  className="text-[#00ff88] hover:underline"
                >
                  ali@al0ke.dev
                </a>
              </p>
            </form>

            <p className="mt-8 text-xs max-w-2xl" style={{ color: 'var(--text-muted)' }}>
              SB 2610 materials are educational only. Requirements and interpretations can change —
              check the Texas Legislature and qualified counsel. This page does not sell legal
              services or claim compliance certification.
            </p>
          </div>
        </section>
      </main>

      <footer className="border-t py-4 flex-shrink-0" style={{ borderColor: 'var(--cyber-border)' }}>
        <div
          className="max-w-5xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs"
          style={{ color: 'var(--text-muted)' }}
        >
          <p>
            PhishGuard · Email & Identity Hygiene Pilot · Ali / al0ke
          </p>
          <div className="flex items-center gap-3">
            <Link href="/" className="hover:text-[#00ff88] transition-colors">
              Analyzer
            </Link>
            <a
              href="https://github.com/al0ke/phishguard-agent"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#00ff88] transition-colors"
            >
              GitHub
            </a>
          </div>
        </div>
      </footer>
    </div>
  )
}
