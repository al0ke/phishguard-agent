import { NextRequest, NextResponse } from 'next/server'

interface CisaVulnerability {
  cveID?: string
  vendorProject?: string
  product?: string
  vulnerabilityName?: string
  dateAdded?: string
}

export async function GET(request: NextRequest) {
  const feed = request.nextUrl.searchParams.get('feed') || 'all'

  const results: Record<string, unknown> = {}

  try {
    if (feed === 'all' || feed === 'cisa') {
      // CISA KEV (Known Exploited Vulnerabilities)
      try {
        const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
          headers: { 'User-Agent': 'CSOC-ThreatAnalyzer/1.0' },
        })
        if (res.ok) {
          const data = await res.json()
          results.cisa = {
            count: data.count || data.vulnerabilities?.length || 0,
            title: data.title || 'CISA KEV Catalog',
            recent: (data.vulnerabilities || []).slice(0, 10).map((v: CisaVulnerability) => ({
              cve: v.cveID,
              vendor: v.vendorProject,
              product: v.product,
              name: v.vulnerabilityName,
              date: v.dateAdded,
              severity: v.vulnerabilityName?.toLowerCase().includes('critical') ? 'critical' : 'high',
            })),
          }
        }
      } catch { results.cisa = { error: 'Failed to fetch CISA KEV' } }
    }

    if (feed === 'all' || feed === 'openphish') {
      // OpenPhish — phishing URL feed
      try {
        const res = await fetch('https://openphish.com/feed.txt', {
          headers: { 'User-Agent': 'CSOC-ThreatAnalyzer/1.0' },
        })
        if (res.ok) {
          const text = await res.text()
          const urls = text.trim().split('\n').filter(Boolean)
          results.openphish = {
            count: urls.length,
            recent: urls.slice(0, 15).map((u: string) => {
              try {
                const parsed = new URL(u.trim())
                return {
                  url: u.trim(),
                  domain: parsed.hostname,
                  path: parsed.pathname,
                }
              } catch {
                return { url: u.trim(), domain: null, path: null }
              }
            }),
          }
        }
      } catch { results.openphish = { error: 'Failed to fetch OpenPhish' } }
    }

    if (feed === 'all' || feed === 'urlhaus') {
      // URLhaus — malware URL feed (CSV format)
      try {
        const res = await fetch('https://urlhaus.abuse.ch/downloads/csv_recent/', {
          headers: { 'User-Agent': 'CSOC-ThreatAnalyzer/1.0' },
        })
        if (res.ok) {
          const text = await res.text()
          const lines = text.trim().split('\n').filter(l => !l.startsWith('#') && l.trim())
          const recent = lines.slice(0, 15).map(line => {
            const parts = line.split('","').map(p => p.replace(/"/g, ''))
            return {
              date: parts[0] || null,
              url: parts[2] || parts[1] || null,
              status: parts[4] || null,
              threat: parts[5] || null,
            }
          }).filter(r => r.url)
          results.urlhaus = {
            count: lines.length,
            recent,
          }
        }
      } catch { results.urlhaus = { error: 'Failed to fetch URLhaus' } }
    }

    return NextResponse.json(results)
  } catch (err) {
    console.error('Threat feeds error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}