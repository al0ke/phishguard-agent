# 🛡️ PhishGuard Agent

AI-powered phishing threat analysis tool for detecting malicious URLs, email threats, and brand impersonation attacks.

![PhishGuard](https://img.shields.io/badge/PhishGuard-Agent-00ff88?style=for-the-badge)
![Next.js](https://img.shields.io/badge/Next.js-15-black?style=flat-square&logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?style=flat-square&logo=typescript)
![Tailwind](https://img.shields.io/badge/Tailwind-3.4-38bdf8?style=flat-square&logo=tailwindcss)

## Features

- **URL/Email Analysis** - Paste suspicious URLs or email content for instant analysis
- **VirusTotal Integration** - Check URLs against 70+ security vendors
- **URLhaus Database** - Query abuse.ch's malware URL database
- **Brand Impersonation Detection** - Identify lookalike domains (microsoft vs micr0soft)
- **IOC Extraction** - Automatically extract IPs, domains, URLs, and hashes
- **AI Verdict Engine** - Get intelligent threat assessments with confidence scores
- **Animated Scan Visualization** - Terminal-style progress tracking
- **Risk Score Gauge** - Visual representation of threat level (0-100)

## Tech Stack

- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Deployment**: Vercel

## Getting Started

### Prerequisites

- Node.js 18+ 
- npm or yarn

### Installation

```bash
# Clone the repository
git clone https://github.com/alibolt/phishguard-agent.git
cd phishguard-agent

# Install dependencies
npm install

# Run the development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to start analyzing threats.

## Environment Variables

```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

> Note: The app includes a default VirusTotal API key for demonstration. For production use, replace it with your own key.

## API Endpoints

### POST /api/analyze

Analyze a URL or email content for threats.

```json
{
  "input": "https://suspicious-domain.com/payload"
}
```

**Response:**

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "input": "https://suspicious-domain.com/payload",
  "inputType": "url",
  "overallVerdict": "malicious",
  "riskScore": 85,
  "threatLevel": "high",
  "urlsAnalyzed": ["https://suspicious-domain.com/payload"],
  "virusTotal": {
    "status": "malicious",
    "malicious": 12,
    "suspicious": 3,
    "ratio": "15/70"
  },
  "urlhaus": {
    "status": "malicious",
    "threatType": "malware",
    "firstSeen": "2024-01-10 00:00:00"
  },
  "brandImpersonation": [
    {
      "brand": "Microsoft",
      "originalDomain": "microsoft.com",
      "suspectedDomain": "micr0soft.com",
      "riskLevel": "high",
      "techniques": ["Character substitution"]
    }
  ],
  "iocs": {
    "ips": ["192.168.1.1"],
    "domains": ["suspicious-domain.com"],
    "urls": [],
    "hashes": []
  },
  "aiVerdict": {
    "summary": "THREAT DETECTED: This URL is confirmed malicious...",
    "recommendations": ["DO NOT click this URL", "Block at network level"],
    "confidence": 0.92
  }
}
```

## Threat Intelligence Sources

| Source | Description | API Required |
|--------|-------------|--------------|
| [VirusTotal](https://www.virustotal.com) | Security vendor consensus | Yes (included) |
| [URLhaus](https://urlhaus-api.abuse.ch) | Malware URL database | No |
| Brand Detection | Lookalike domain detection | No |

## Deployment

### Vercel (Recommended)

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/alibolt/phishguard-agent)

```bash
# Or via CLI
npm i -g vercel
vercel
```

## Visual Design

- **Dark Theme**: `#0a0a0f` background with `#111119` cards
- **Neon Accents**: Green (#00ff88), Red (#ff3366), Yellow (#ffcc00), Blue (#00ccff)
- **Risk Indicators**: 
  - 🟢 Safe (0-20)
  - 🔵 Low (20-40)
  - 🟡 Medium (40-60)
  - 🟠 High (60-80)
  - 🔴 Critical (80-100)

## Project Structure

```
phishguard/
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   └── analyze/
│   │   │       └── route.ts    # Analysis API endpoint
│   │   ├── layout.tsx          # Root layout
│   │   ├── page.tsx             # Main page
│   │   └── globals.css          # Global styles
│   ├── components/
│   │   ├── AnalysisInput.tsx    # URL/email input form
│   │   ├── ScanAnimation.tsx    # Terminal scan animation
│   │   ├── RiskGauge.tsx        # Risk score visualization
│   │   ├── ThreatReport.tsx     # Full threat report
│   │   └── IOCList.tsx          # IOC extraction display
│   └── lib/
│       ├── virusTotal.ts        # VirusTotal API integration
│       ├── urlhaus.ts           # URLhaus API integration
│       └── brandDetection.ts    # Brand impersonation detection
├── public/
├── package.json
├── tailwind.config.ts
├── tsconfig.json
└── README.md
```

## Phishing Hygiene Kit

Public product page: **[/kit](./src/app/kit/page.tsx)** — **Email & Identity Hygiene Pilot** for Texas SMBs (&lt;250 employees).

| | |
|--|--|
| **Offer** | Fixed-scope readiness pilot (~**$597**, **5 business days**) |
| **Who** | Texas SMBs / lean IT / MSPs supporting those clients |
| **Author** | Ali (al0ke) — experience with a Texas agency CISO office |
| **Soft CTA** | Mailto / book a walkthrough (no Stripe checkout on the page) |

Downloadable artifacts in `public/kit/`:

- `mfa-email-hardening-checklist.md` — MFA, app passwords, forwarding/inbox-rules abuse, vendor verification
- `phishing-readiness-scorecard.md` — 10-minute self-score (controls / people / process); not a certification
- `sb-2610-plain-english-brief.md` — high-level Texas SB 2610 orientation + official Legislature links; **not legal advice**

Income intent: productize PhishGuard into a short paid hygiene pilot while keeping free triage demo + kit downloads. Live demo: https://phishguard-plum.vercel.app · Repo: https://github.com/al0ke/phishguard-agent

```bash
npm run dev
# open http://localhost:3000/kit
```

`/kit` is excluded from the app’s Basic Auth so the landing and markdown downloads stay public.

## Security Notes

- Never enter real credentials on suspected phishing sites
- Always verify through official channels
- Report threats to your security team

## License

MIT License - See LICENSE file for details.

---

Built with 🔒 by Ali (al0ke) / PhishGuard