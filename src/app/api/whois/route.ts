import { NextRequest, NextResponse } from 'next/server'

interface Registrant {
  name?: string
  org?: string
  country?: string | null
  nameservers?: string[]
}

interface CertEntry {
  name_value?: string
  ip_address?: string
  not_before?: string
  not_after?: string
  issuer_name?: string
}

async function fetchWithTimeout(url: string, timeoutMs = 5000): Promise<Response | null> {
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    const res = await fetch(url, {
      headers: { 'User-Agent': 'CSOC-ThreatAnalyzer/1.0' },
      signal: controller.signal,
    })
    clearTimeout(timer)
    return res
  } catch {
    return null
  }
}

export async function POST(request: NextRequest) {
  try {
    const { domain } = await request.json()

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json({ error: 'Domain required' }, { status: 400 })
    }

    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]

    // RDAP first (fast, reliable) — 5s timeout
    let registrar = null, created = null, updated = null, expires = null
    const registrant: Registrant = {}
    let rdapOk = false

    const rdapRes = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`, 5000)
    if (rdapRes && rdapRes.ok) {
      try {
        const rdap = await rdapRes.json()
        rdapOk = true
        registrar = rdap.registrar || null
        const events = rdap.events || []
        for (const ev of events) {
          if (ev.eventAction === 'registration') created = ev.eventDate
          if (ev.eventAction === 'expiration') expires = ev.eventDate
          if (ev.eventAction === 'last update') updated = ev.eventDate
        }
        // Extract registrant from entities
        const entities = rdap.entities || []
        for (const ent of entities) {
          const roles = ent.roles || []
          if (roles.includes('registrant') || roles.includes('entity')) {
            const vcard = ent.vcardArray?.[1] || []
            for (const field of vcard) {
              if (field[0] === 'fn') registrant.name = field[3]
              if (field[0] === 'org') registrant.org = field[3]
              if (field[0] === 'adr') registrant.country = Array.isArray(field[3]) ? field[3][3] || field[3][0] : null
            }
          }
        }
        // Also check rdap.nameservers
        const nsArray = rdap.nameservers || []
        registrant.nameservers = nsArray.map((ns: { ldhName?: string }) => ns.ldhName).filter(Boolean).slice(0, 10)
      } catch { /* parse error, continue */ }
    }

    // crt.sh (slow, best-effort) — 4s timeout
    let certs: CertEntry[] = []
    let certCount = 0
    const crtRes = await fetchWithTimeout(
      `https://crt.sh/?q=%25.${encodeURIComponent(cleanDomain)}&output=json`,
      4000
    )
    if (crtRes && crtRes.ok) {
      try {
        const raw = await crtRes.text()
        certs = JSON.parse(raw).slice(0, 50)
        certCount = certs.length
      } catch { /* parse error */ }
    }

    // Extract subdomain hints from cert names
    const certNames = [...new Set(
      certs.flatMap((c) => (c.name_value || '').split('\n')).filter(Boolean)
    )].slice(0, 10)

    return NextResponse.json({
      domain: cleanDomain,
      registrar,
      created,
      updated,
      expires,
      registrant,
      nameservers: registrant.nameservers || certNames,
      cert_count: certCount,
      recent_certs: certs.slice(0, 5).map((c) => ({
        issued: c.not_before,
        expiry: c.not_after,
        issuer: c.issuer_name?.split(',')[0] || null,
      })),
      rdap_url: rdapOk ? `https://rdap.org/domain/${cleanDomain}` : null,
      rdap_found: rdapOk,
    })
  } catch (err) {
    console.error('WHOIS route error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}