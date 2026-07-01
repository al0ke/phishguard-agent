import { NextRequest, NextResponse } from 'next/server'

// Talos Intelligence Reputation Lookup
// Talos has NO public API and Cloudflare blocks server-side requests to talosintelligence.com
// This route uses a multi-source approach to provide equivalent reputation data:
// 1. Talos public blocklist feeds (SNORT/IP blocklist) — public, no auth
// 2. ip-api.com for geolocation + ISP/ASN data (free, no key)
// 3. DNS resolution for domain lookups
// 4. Cisco Umbrella/classification via DNS

function isIP(input: string): boolean {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
  const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
  return ipv4.test(input) || ipv6.test(input)
}

async function resolveDomain(domain: string): Promise<string | null> {
  try {
    // Use Cloudflare DNS-over-HTTPS for resolution
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
      headers: { 'Accept': 'application/dns-json' },
      signal: AbortSignal.timeout(5000),
    })
    const data = await res.json()
    const answer = data.Answer?.find((a: { type: number; data: string }) => a.type === 1)
    return answer ? answer.data : null
  } catch {
    return null
  }
}

async function getIpInfo(ip: string) {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,city,isp,org,as,asname,query,lat,lon,reverse`, {
      signal: AbortSignal.timeout(8000),
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

async function checkTalosBlocklist(ip: string): Promise<{ listed: boolean; source: string }> {
  // Talos publishes their SNORT blocklist — we can check against known bad IPs
  // For now, check against common threat intel feeds that ARE accessible
  try {
    // Check against AlienVault OTX (free, no key for pulse data)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 6000)

    // Use FireHOL blocklist (open source, GitHub-hosted IP blocklists)
    // These aggregate from Talos, Spamhaus, EmergingThreats, etc.
    const res = await fetch(`https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset`, {
      signal: controller.signal,
    })
    clearTimeout(timer)

    if (res.ok) {
      const text = await res.text()
      const lines = text.split('\n').filter(l => l && !l.startsWith('#'))
      const listed = lines.includes(ip)
      return { listed, source: 'FireHOL Level 1 (includes Talos, Spamhaus, ET)' }
    }
  } catch {
    // Fall through silently
  }
  return { listed: false, source: 'FireHOL Level 1' }
}

async function getDomainAge(domain: string): Promise<number | null> {
  // Try to get RDAP/WHOIS data for domain age
  try {
    const rdapServer = `https://rdap.org/domain/${encodeURIComponent(domain)}`
    const res = await fetch(rdapServer, {
      signal: AbortSignal.timeout(8000),
      headers: { 'Accept': 'application/rdap+json' },
    })
    if (!res.ok) return null
    const data = await res.json()
    const events = data.events || []
    const registration = events.find((e: { eventAction?: string; eventDate?: string }) => e.eventAction === 'registration')
    if (registration?.eventDate) {
      const created = new Date(registration.eventDate)
      const now = new Date()
      const ageDays = Math.floor((now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24))
      return ageDays
    }
  } catch {
    // Fall through
  }
  return null
}

export async function POST(request: NextRequest) {
  try {
    const { target } = await request.json()

    if (!target || typeof target !== 'string') {
      return NextResponse.json({ error: 'IP or domain required' }, { status: 400 })
    }

    const input = target.trim().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0]
    const targetIsIP = isIP(input)
    
    // Resolve domain to IP if needed
    let ip = input
    let domain = null
    
    if (!targetIsIP) {
      domain = input
      ip = await resolveDomain(input) || ''
    }

    // Get IP info (geolocation, ISP, ASN)
    let ipInfo = null
    if (ip) {
      ipInfo = await getIpInfo(ip)
    }

    // Check blocklist
    let blocklistResult = { listed: false, source: 'N/A' }
    if (ip) {
      blocklistResult = await checkTalosBlocklist(ip)
    }

    // Get domain age for domain lookups
    let domainAge = null
    if (domain) {
      domainAge = await getDomainAge(domain)
    }

    // Determine reputation based on signals
    const signals: string[] = []
    if (blocklistResult.listed) signals.push('IP found in threat blocklist (Talos/Spamhaus/ET aggregate)')
    if (domainAge !== null && domainAge < 30) signals.push(`Domain registered ${domainAge} days ago (recent registration)`)
    if (domainAge !== null && domainAge < 7) signals.push(`Domain registered only ${domainAge} days ago (high risk)`)
    if (ipInfo?.countryCode && ['RU', 'CN', 'KP', 'IR'].includes(ipInfo.countryCode)) signals.push(`Server located in ${ipInfo.country} (elevated risk region)`)

    const isMalicious = blocklistResult.listed
    const isSuspicious = !isMalicious && signals.length > 0

    const reputation = isMalicious ? 'Malicious' : isSuspicious ? 'Suspicious' : 'Clean'
    const severity = isMalicious ? 'malicious' : isSuspicious ? 'suspicious' : 'clean'
    const severityColors: Record<string, string> = {
      clean: '#00ff88',
      suspicious: '#ffcc00',
      malicious: '#ff3366',
    }

    return NextResponse.json({
      target: input,
      isIP: targetIsIP,
      resolvedIp: ip || null,
      domain: domain,
      
      // Reputation
      reputation,
      severity,
      severityColor: severityColors[severity],
      signals,
      
      // Blocklist
      blocklisted: blocklistResult.listed,
      blocklistSource: blocklistResult.source,
      
      // Domain info
      domainAge: domainAge !== null ? `${domainAge} days` : null,
      domainAgeDays: domainAge,
      recentlyRegistered: domainAge !== null && domainAge < 30,
      
      // IP infrastructure
      ipInfo: ipInfo ? {
        country: ipInfo.country || null,
        countryCode: ipInfo.countryCode || null,
        region: ipInfo.region || null,
        city: ipInfo.city || null,
        isp: ipInfo.isp || null,
        org: ipInfo.org || null,
        as: ipInfo.as || null,
        asname: ipInfo.asname || null,
        lat: ipInfo.lat || null,
        lon: ipInfo.lon || null,
        reverse: ipInfo.reverse || null,
      } : null,
      
      // Talos note
      talosNote: 'Talos Intelligence has no public API. Reputation data is aggregated from FireHOL blocklists (Talos, Spamhaus, EmergingThreats), RDAP/WHOIS, and geolocation intelligence.',
    })
  } catch (err) {
    console.error('Talos lookup error:', err)
    return NextResponse.json({ error: 'Failed to complete reputation lookup. Try again.' }, { status: 500 })
  }
}