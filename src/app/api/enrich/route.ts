import { NextRequest, NextResponse } from 'next/server'

function isIP(target: string): boolean {
  const parts = target.trim().split('.')
  if (parts.length !== 4) return false
  return parts.every(p => /^\d+$/.test(p) && parseInt(p) <= 255)
}

async function fetchWithTimeout(url: string, timeoutMs = 5000): Promise<Response | null> {
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    const res = await fetch(url, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'CSOC-ThreatAnalyzer/1.0' },
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
    const { query, type } = await request.json()

    if (!query || typeof query !== 'string') {
      return NextResponse.json({ error: 'query required' }, { status: 400 })
    }

    const clean = query.trim()
    const resolvedType = type || (isIP(clean) ? 'ip' : 'domain')

    if (resolvedType === 'ip') {
      // Shodan InternetDB — correct URL is internetdb.shodan.io
      const res = await fetchWithTimeout(`https://internetdb.shodan.io/${clean}`, 5000)

      if (!res) {
        return NextResponse.json({
          type: 'ip',
          query: clean,
          ip: clean,
          ports: [],
          hostnames: [],
          tags: [],
          cves: [],
          country: null,
          asn: null,
          message: 'Lookup timed out — no data available',
        })
      }

      if (!res.ok) {
        return NextResponse.json({
          type: 'ip',
          query: clean,
          ip: clean,
          ports: [],
          hostnames: [],
          tags: [],
          cves: [],
          country: null,
          asn: null,
          message: `No data for this IP (status ${res.status})`,
        })
      }

      const data = await res.json()
      return NextResponse.json({
        type: 'ip',
        query: clean,
        ip: clean,
        ports: data.ports || [],
        hostnames: data.hostnames || [],
        tags: data.tags || [],
        cves: data.cves || [],
        country: data.country || data.country_code || null,
        asn: data.asn || data.asn_org || null,
        summary: data.summary || null,
      })
    } else {
      // Domain — crt.sh for subdomains (with timeout)
      const res = await fetchWithTimeout(
        `https://crt.sh/?q=%25.${encodeURIComponent(clean)}&output=json`,
        5000
      )

      if (!res || !res.ok) {
        return NextResponse.json({
          type: 'domain',
          query: clean,
          subdomains: [],
          relatedIPs: [],
          cert_count: 0,
          message: 'crt.sh lookup timed out',
        })
      }

      const raw = await res.text()
      let certs: Array<{ name_value?: string; ip_address?: string }> = []
      try { certs = JSON.parse(raw) } catch { /* empty */ }

      const subdomains = [...new Set(
        certs
          .map((c) => c.name_value || '')
          .flatMap((v: string) => v.split('\n'))
          .filter((v: string) => v.includes(clean))
          .map((v: string) => v.toLowerCase().replace(`.${clean}`, ''))
      )].filter(Boolean).slice(0, 30)

      const ips = [...new Set(certs.map((c) => c.ip_address).filter(Boolean))]

      return NextResponse.json({
        type: 'domain',
        query: clean,
        subdomains,
        relatedIPs: ips.slice(0, 20),
        cert_count: certs.length,
      })
    }
  } catch (err) {
    console.error('Enrich route error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}