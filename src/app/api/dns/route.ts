import { NextRequest, NextResponse } from 'next/server'

interface DnsRecord {
  name: string
  type: number
  ttl: number
  data: string
}

async function dnsLookup(name: string, type: string): Promise<DnsRecord[]> {
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 5000)
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { 'Accept': 'application/dns-json' }, signal: controller.signal }
    )
    clearTimeout(timer)
    if (!res.ok) return []
    const data = await res.json()
    return (data.Answer || []).map((a: { name: string; type: number; TTL: number; data: string }) => ({
      name: a.name,
      type: a.type,
      ttl: a.TTL,
      data: a.data,
    }))
  } catch {
    return []
  }
}

export async function POST(request: NextRequest) {
  try {
    const { domain, types } = await request.json()

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json({ error: 'Domain required' }, { status: 400 })
    }

    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]
    const queryTypes: string[] = types || ['A', 'MX', 'TXT', 'NS', 'AAAA']

    const results: Record<string, DnsRecord[]> = {}
    await Promise.all(queryTypes.map(async (type: string) => {
      results[type] = await dnsLookup(cleanDomain, type)
    }))

    // Extract SPF/DMARC from TXT
    const txtRecords = results.TXT || []
    const spf = txtRecords.find(r => r.data?.includes('v=spf1'))
    const dmarcResults = await dnsLookup(`_dmarc.${cleanDomain}`, 'TXT')
    const dmarc = dmarcResults.find(r => r.data?.includes('v=DMARC1'))

    return NextResponse.json({
      domain: cleanDomain,
      records: results,
      spf: spf?.data?.replace(/"/g, '') || null,
      dmarc: dmarc?.data?.replace(/"/g, '') || null,
      dkim_selectors: ['default', 'google', 'selector1', 's1'],
      summary: {
        hasA: (results.A?.length || 0) > 0,
        hasAAAA: (results.AAAA?.length || 0) > 0,
        hasMX: (results.MX?.length || 0) > 0,
        hasSPF: !!spf,
        hasDMARC: !!dmarc,
        recordCount: Object.values(results).reduce((sum: number, arr: DnsRecord[]) => sum + arr.length, 0),
      },
    })
  } catch (err) {
    console.error('DNS route error:', err)
    return NextResponse.json({ error: 'Internal error' }, { status: 500 })
  }
}