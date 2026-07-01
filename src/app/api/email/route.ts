import { NextRequest, NextResponse } from 'next/server'

// DNS-over-HTTPS via Google
async function dnsLookup(name: string, type: string): Promise<string[]> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { 'Accept': 'application/dns-json' } }
    )
    if (!res.ok) return []
    const data = await res.json()
    return (data.Answer || [])
      .filter((a: { data?: string }) => a.data)
      .map((a: { data: string }) => a.data)
  } catch {
    return []
  }
}

async function checkDMARC(domain: string): Promise<{ found: boolean; record: string | null; policy: string | null }> {
  const records = await dnsLookup(`_dmarc.${domain}`, 'TXT')
  const dmarcRecord = records.find(r => r.startsWith('"v=DMARC1') || r.includes('v=DMARC1'))
  if (!dmarcRecord) return { found: false, record: null, policy: null }
  const policyMatch = dmarcRecord.match(/p=(\w+)/)
  return { found: true, record: dmarcRecord.replace(/"/g, ''), policy: policyMatch ? policyMatch[1] : null }
}

async function checkSPF(domain: string): Promise<{ found: boolean; record: string | null }> {
  const records = await dnsLookup(domain, 'TXT')
  const spfRecord = records.find(r => r.includes('v=spf1'))
  return { found: !!spfRecord, record: spfRecord ? spfRecord.replace(/"/g, '') : null }
}

async function checkDKIM(domain: string): Promise<{ found: boolean; record: string | null }> {
  // Try common selectors
  const selectors = ['default', 'google', 'selector1', 'selector2', 's1', 'mail', 'smtp']
  for (const selector of selectors) {
    const records = await dnsLookup(`${selector}._domainkey.${domain}`, 'TXT')
    const dkimRecord = records.find(r => r.includes('v=DKIM1') || r.includes('k=rsa'))
    if (dkimRecord) return { found: true, record: dkimRecord.replace(/"/g, '').slice(0, 200) }
  }
  return { found: false, record: null }
}

async function getDomainAge(domain: string): Promise<{ created: string | null; ageDays: number | null; registrar: string | null }> {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { 'User-Agent': 'CSOC-ThreatAnalyzer/1.0' },
    })
    if (!res.ok) return { created: null, ageDays: null, registrar: null }
    const data = await res.json()
    const events = data.events || []
    const regEvent = events.find((e: { eventAction?: string; eventDate?: string }) => e.eventAction === 'registration')
    const created = regEvent?.eventDate || null
    let ageDays = null
    if (created) {
      const diff = Date.now() - new Date(created).getTime()
      ageDays = Math.floor(diff / (1000 * 60 * 60 * 24))
    }
    return { created, ageDays, registrar: data.registrar || null }
  } catch {
    return { created: null, ageDays: null, registrar: null }
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { rawEmail, senderEmail, fromDomain } = body

    // Parse sender from raw email if provided
    let sender = senderEmail || ''
    let domain = fromDomain || ''

    if (rawEmail) {
      // Extract From header
      const fromMatch = rawEmail.match(/From:\s*.*?<([^>]+)>/i) || rawEmail.match(/From:\s*(\S+@\S+)/i)
      if (fromMatch) sender = fromMatch[1].trim()
      if (sender) domain = sender.split('@')[1] || ''
    }

    if (!domain) {
      return NextResponse.json({ error: 'Could not determine sender domain' }, { status: 400 })
    }

    // Run all checks in parallel
    const [spf, dkim, dmarc, domainInfo] = await Promise.all([
      checkSPF(domain),
      checkDKIM(domain),
      checkDMARC(domain),
      getDomainAge(domain),
    ])

    // Extract URLs from email body if rawEmail provided
    let urls: string[] = []
    let suspiciousKeywords: string[] = []
    let attachments: string[] = []

    if (rawEmail) {
      const urlRegex = /https?:\/\/[^\s<>"]+/gi
      const foundUrls: string[] = rawEmail.match(urlRegex) || []
      urls = [...new Set(foundUrls)].slice(0, 20)

      const keywordList = [
        'urgent', 'verify', 'suspend', 'account', 'password', 'click here',
        'confirm', 'update', 'security', 'alert', 'limited', 'unlock',
        'verify your', 'activate', 'immediately', 'require',
      ]
      const lowerEmail = rawEmail.toLowerCase()
      suspiciousKeywords = keywordList.filter(k => lowerEmail.includes(k))

      const attachmentRegex = /Content-Disposition:\s*attachment;\s*filename="?([^";\s]+)"?/gi
      const matches = [...rawEmail.matchAll(attachmentRegex)]
      attachments = matches.map(m => m[1]).slice(0, 10)

      // Check for executive impersonation keywords
      const execKeywords = ['ceo', 'cfo', 'cto', 'president', 'director', 'executive', 'board', 'chief']
      const execFound = execKeywords.filter(k => lowerEmail.includes(k))
      if (execFound.length > 0) suspiciousKeywords.push(...execFound.map(k => `exec:${k}`))
    }

    // Calculate risk score (0-100)
    let riskScore = 0
    const factors: string[] = []

    if (!spf.found) { riskScore += 20; factors.push('SPF record missing') }
    else factors.push('SPF record present')

    if (!dkim.found) { riskScore += 15; factors.push('DKIM record not found') }
    else factors.push('DKIM record found')

    if (!dmarc.found) { riskScore += 20; factors.push('DMARC policy missing') }
    else if (dmarc.policy === 'none') { riskScore += 5; factors.push('DMARC policy is none (monitoring only)') }
    else factors.push(`DMARC policy: ${dmarc.policy}`)

    if (domainInfo.ageDays !== null) {
      if (domainInfo.ageDays < 30) { riskScore += 25; factors.push(`Domain is ${domainInfo.ageDays} days old (very new)`) }
      else if (domainInfo.ageDays < 90) { riskScore += 15; factors.push(`Domain is ${domainInfo.ageDays} days old (recent)`) }
      else factors.push(`Domain age: ${domainInfo.ageDays} days`)
    }

    if (suspiciousKeywords.length > 3) { riskScore += 15; factors.push(`${suspiciousKeywords.length} suspicious keywords detected`) }
    else if (suspiciousKeywords.length > 0) { riskScore += 5; factors.push(`${suspiciousKeywords.length} suspicious keywords`) }

    if (attachments.length > 0) { riskScore += 10; factors.push(`${attachments.length} attachment(s) found`) }

    if (urls.length > 3) { riskScore += 10; factors.push(`${urls.length} URLs in email body`) }

    riskScore = Math.min(riskScore, 100)

    const threatLevel = riskScore >= 70 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 30 ? 'medium' : 'low'

    return NextResponse.json({
      sender,
      domain,
      spf,
      dkim,
      dmarc,
      domainInfo,
      urls,
      suspiciousKeywords,
      attachments,
      riskScore,
      threatLevel,
      factors,
    })
  } catch (err) {
    console.error('Email analysis error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}