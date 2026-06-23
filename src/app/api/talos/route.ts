import { NextRequest, NextResponse } from 'next/server'

// Cisco Talos Reputation Center — no public API, uses the same endpoint
// as the Talos web reputation lookup (talosintelligence.com/sb_api/query_lookup)
// Reference: Cortex-Analyzers TalosReputation.py

const TALOS_BASE = 'https://talosintelligence.com/sb_api/query_lookup'

const HEADERS: Record<string, string> = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.3809.100 Safari/537.36',
  'Accept': 'application/json, text/plain, */*',
  'Referer': 'https://talosintelligence.com/reputation_center/lookup',
}

interface TalosDetails {
  domain_name?: string
  email_score_name?: string
  email_score?: string
  web_score_name?: string
  web_score?: string
  category?: string
  web_reputation?: string
  email_rep_name?: string
  web_rep_name?: string
}

interface TalosLocation {
  country?: string
  city?: string
  longitude?: string
  latitude?: string
  organization?: string
  asn?: string
  isp?: string
}

function isIP(input: string): boolean {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
  const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
  return ipv4.test(input) || ipv6.test(input)
}

async function fetchTalos(query: string, signal: AbortSignal) {
  const url = new URL(TALOS_BASE)
  url.searchParams.set('query', query)
  const res = await fetch(url.toString(), { headers: HEADERS, signal })
  if (!res.ok) throw new Error(`Talos API ${res.status}`)
  return res.json()
}

export async function POST(request: NextRequest) {
  try {
    const { target } = await request.json()

    if (!target || typeof target !== 'string') {
      return NextResponse.json({ error: 'IP or domain required' }, { status: 400 })
    }

    const input = target.trim()
    const ipQuery = isIP(input) ? input : input

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 10000)

    try {
      // Query both details and location endpoints
      const [details, location] = await Promise.all([
        fetchTalos(`/api/v2/details/ip/${ipQuery}`, controller.signal),
        fetchTalos(`/api/v2/location/ip/${ipQuery}`, controller.signal).catch(() => null),
      ])

      clearTimeout(timer)

      const d: TalosDetails = details || {}
      const l: TalosLocation = location || {}

      // Talos reputation dispositions
      const emailRep = d.email_score_name || d.email_rep_name || 'Unknown'
      const webRep = d.web_score_name || d.web_rep_name || 'Unknown'
      const emailScore = d.email_score || null
      const webScore = d.web_score || null

      // Map reputation to severity
      const getSeverity = (rep: string): 'clean' | 'suspicious' | 'malicious' | 'unknown' => {
        const r = rep.toLowerCase()
        if (r.includes('clean') || r.includes('good') || r.includes('neutral')) return 'clean'
        if (r.includes('suspicious') || r.includes('questionable')) return 'suspicious'
        if (r.includes('malicious') || r.includes('spam') || r.includes('poor')) return 'malicious'
        return 'unknown'
      }

      return NextResponse.json({
        target: input,
        isIP: isIP(input),
        emailReputation: emailRep,
        emailScore: emailScore,
        emailSeverity: getSeverity(emailRep),
        webReputation: webRep,
        webScore: webScore,
        webSeverity: getSeverity(webRep),
        category: d.category || null,
        domainName: d.domain_name || null,
        // Location data
        country: l.country || null,
        city: l.city || null,
        organization: l.organization || null,
        isp: l.isp || null,
        asn: l.asn || null,
        latitude: l.latitude || null,
        longitude: l.longitude || null,
        raw: { details: d, location: l },
      })
    } finally {
      clearTimeout(timer)
    }
  } catch (err) {
    console.error('Talos API error:', err)
    return NextResponse.json({ error: 'Failed to query Talos. The service may be rate-limiting or unavailable.' }, { status: 502 })
  }
}